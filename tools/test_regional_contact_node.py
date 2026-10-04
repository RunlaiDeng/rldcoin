"""Native-ledger integration checks using the real binary and contact runtime."""
import fcntl
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import threading
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Native, Service, startup_config
from regional_contact_campaign import Campaign, public

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeContactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-native-contact-tests-')
        self.root = Path(self.temp.name).resolve()/'fixture'
        self.c = Campaign(BINARY,self.root)
        self.services = []

    def tearDown(self):
        for service in self.services:
            service.close()
        self.c.cleanup()
        self.temp.cleanup()

    def config(self, name, label_region=None, suffix=''):
        root = self.root/(name+'-mesh'+suffix)
        identity = mesh.initialize(root,self.c.currency,label_region or self.c.regions[name],name)
        config = {'format':mesh.VERSION,'state':str(root),'network':self.c.currency,'contacts':[]}
        return config,identity['node_id']

    def test_failed_bounded_selection_retains_intent_until_next_authenticated_selection(self):
        config,_=self.config('earth',suffix='-selection-preference')
        service=self.service('earth',config);held=threading.Event();release=threading.Event()
        def holder():
            with mesh.Node(config):held.set();release.wait(5)
        thread=threading.Thread(target=holder);thread.start()
        try:
            self.assertTrue(held.wait(5));before=(service.native.ledger/'journal.json').read_bytes()
            with self.assertRaises(BlockingIOError):
                with service.selection_node():self.fail('held mesh acquired')
            self.assertIs(service.tcp.selection_owner,threading.current_thread())
            release.set();thread.join(5);self.assertFalse(thread.is_alive())
            with service.selection_node() as node:
                self.assertEqual(node.network,self.c.currency)
                self.assertIs(service.tcp.selection_owner,threading.current_thread())
            self.assertIsNone(service.tcp.selection_owner)
            self.assertEqual((service.native.ledger/'journal.json').read_bytes(),before)
        finally:release.set();thread.join(5)

    def native(self,name):
        return Native(BINARY,self.root/name,self.c.authority,self.c.currency)

    def service(self,name,config,native=None):
        service = Service(native or self.native(name),config,public(10))
        self.services.append(service)
        return service

    def start_default(self, name):
        log = (self.root / (name + '-default.log')).open('ab')
        self.addCleanup(log.close)
        command = [str(BINARY), '--dir', str(self.root/name), '--authority', self.c.authority,
            '--currency', self.c.currency, '--transport-python', sys.executable, '--interval', '0.1']
        process = subprocess.Popen(command, stdout=log, stderr=log)
        def stop():
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        self.addCleanup(stop)
        deadline = time.monotonic() + 10
        path = self.root/name/'transport/regional-contact-status.json'
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), (self.root/(name+'-default.log')).read_text())
            if path.exists():
                status = mesh.load(path, mesh.MAX_STATE)
                if status['process_id'] == process.pid:
                    return process, status
            time.sleep(0.025)
        self.fail('normal node startup never enabled its relay')

    def test_normal_startup_enables_isolated_relay_without_mining_and_restores_identity(self):
        before = (self.root/'proxima/journal.json').read_bytes()
        process, status = self.start_default('proxima')
        self.assertTrue(status['relay_enabled'])
        self.assertFalse(status['local_import_mining_enabled'])
        self.assertEqual(status['transport']['nodes'], 1)
        self.assertEqual(status['transport']['tcp']['listener']['host'],'127.0.0.1')
        self.assertGreater(status['transport']['tcp']['listener']['port'],0)
        self.assertFalse(status['transport']['tcp']['ledger_acceptance_from_transport'])
        self.assertTrue(status['transport']['tcp']['encrypted'])
        self.assertEqual(status['transport']['tcp']['tls_version'],'TLSv1.3')
        self.assertFalse(status['transport']['tcp']['fallback_to_plaintext'])
        certificate=(self.root/'proxima/transport/tcp-tls.private.pem').read_bytes()
        fingerprint=status['transport']['tcp']['tls_cert_sha256']
        identity = (self.root/'proxima/transport/identity.private.json').read_bytes()
        self.assertEqual(before, (self.root/'proxima/journal.json').read_bytes())
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)
        process, status = self.start_default('proxima')
        self.assertTrue(status['native_observation_available'])
        self.assertEqual(identity, (self.root/'proxima/transport/identity.private.json').read_bytes())
        self.assertEqual(certificate,(self.root/'proxima/transport/tcp-tls.private.pem').read_bytes())
        self.assertEqual(fingerprint,status['transport']['tcp']['tls_cert_sha256'])
        self.assertEqual(before, (self.root/'proxima/journal.json').read_bytes())
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)

    def test_invalid_native_authority_does_not_create_a_relay_identity(self):
        result = subprocess.run([str(BINARY), '--dir', str(self.root/'proxima'),
            '--authority', public(99), '--currency', self.c.currency,
            '--transport-python', sys.executable], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'proxima/transport').exists())

    def test_default_initialization_recovers_identity_config_commit_crash_window(self):
        root = self.root/'proxima/transport'
        identity = mesh.initialize(root, self.c.currency, self.c.regions['proxima'], 'regional-node')
        config = startup_config(self.native('proxima'))
        self.assertEqual(config['contacts'], [])
        with mesh.Node(config) as node:
            self.assertEqual(node.id, identity['node_id'])
        self.assertEqual(config, startup_config(self.native('proxima')))

    def test_relay_only_keeps_verified_value_pending_until_explicit_local_block_production(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        chosen = sorted(self.c.cli('earth','status')['ledger']['coins'])[0]
        intent = self.c.intent('earth', [10], [(10,19)], ('proxima',11,80,2), 1, [chosen])
        self.c.mine('earth', [intent['command']])
        self.c.certify('earth')
        source, source_id = self.config('earth')
        target, target_id = self.config('proxima')
        source['contacts'] = [{'peer':target_id,'inbox':str(self.root/'pending-px-earth'),
            'outbox':str(self.root/'pending-earth-px')}]
        target['contacts'] = [{'peer':source_id,'inbox':str(self.root/'pending-earth-px'),
            'outbox':str(self.root/'pending-px-earth')}]
        producer = self.service('earth', source)
        receiver = Service(self.native('proxima'), target, None)
        self.services.append(receiver)
        for _ in range(8):
            producer.tick()
            receiver.tick()
        observed = self.c.cli('proxima', 'contact-status')['contacts']
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0]['evidence_verified'])
        self.assertFalse(observed[0]['import_accepted'])
        self.assertEqual(self.c.cli('proxima','status')['height'], 0)
        self.assertFalse(self.c.cli('proxima','status')['ledger']['coins'])
        receiver.close()
        receiver = self.service('proxima', target)
        for _ in range(4):
            producer.tick()
            receiver.tick()
        self.assertEqual(self.c.cli('proxima','status')['height'], 1)
        self.assertEqual(len(self.c.cli('proxima','status')['ledger']['imports']), 1)

    def test_duplicate_contact_service_cannot_take_over_the_existing_process_lock(self):
        config,_ = self.config('proxima')
        service = self.service('proxima',config)
        with self.assertRaises(BlockingIOError):
            Service(self.native('proxima'),config,public(10))
        self.assertTrue(service.tick()['native_observation_available'])
        self.assertEqual(self.c.cli('proxima','status')['height'],0)

    def test_four_reachable_destination_nodes_all_receive_export_offers(self):
        for _ in range(4):self.c.mine('earth')
        self.c.certify('earth')
        chosen=sorted(self.c.cli('earth','status')['ledger']['coins'])[0]
        operation=self.c.intent('earth',[10],[(10,19)],('proxima',11,80,2),1,[chosen])
        self.c.mine('earth',[operation['command']]);self.c.certify('earth')
        source,source_id=self.config('earth')
        targets=[self.config('proxima',suffix=f'-candidate-{n}') for n in range(4)]
        source['contacts']=[{'peer':ident,'inbox':str(self.root/f'inbound-{n}'),
                             'outbox':str(self.root/f'outbound-{n}')} for n,(_,ident) in enumerate(targets)]
        for n,(config,ident) in enumerate(targets):
            config['contacts']=[{'peer':source_id,'inbox':str(self.root/f'outbound-{n}'),
                                 'outbox':str(self.root/f'inbound-{n}')}]
            with mesh.Node(config) as target:exchange=target.exchange(source_id)
            with mesh.Node(source) as node:node.receive(exchange,ident)
        producer=self.service('earth',source)
        for _ in range(4):producer.tick()
        destinations=set()
        with mesh.Node(source) as node:
            for transit in node.state['messages'].values():
                packet,raw,_=mesh.transit_check(transit,node.network)
                frame,_=wire.inspect_frame(raw)
                if frame['export_id']==operation['export_or_transaction_id']:
                    destinations.add(packet['destination'])
        self.assertEqual(destinations,{ident for _,ident in targets})
        self.assertFalse(self.c.cli('proxima','status')['ledger']['imports'])

    def test_local_transport_label_or_network_cannot_replace_native_currency_region(self):
        before = (self.root/'proxima/journal.json').read_bytes()
        config,_ = self.config('proxima',self.c.regions['andromeda'])
        with self.assertRaisesRegex(ValueError,'local mesh label'):
            Service(self.native('proxima'),config,public(10))
        config,_ = self.config('proxima',suffix='-wrong-network')
        config['network'] = 'f'*64
        with self.assertRaisesRegex(ValueError,'binding mismatch'):
            Service(self.native('proxima'),config,public(10))
        self.assertEqual(before,(self.root/'proxima/journal.json').read_bytes())

    def test_busy_native_store_keeps_relay_alive_and_does_not_report_stale_value_as_fresh(self):
        config,_ = self.config('proxima')
        service = self.service('proxima',config)
        self.assertTrue(service.tick()['native_observation_available'])
        descriptor = os.open(self.root/'proxima/LOCK',os.O_RDWR)
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            report = service.tick()
            self.assertFalse(report['native_observation_available'])
            self.assertIsNone(report['native_observation'])
            self.assertTrue(report['errors'])
            self.assertEqual(report['transport']['nodes'],1)
        finally:
            os.close(descriptor)
        self.assertTrue(service.tick()['native_observation_available'])
        self.assertEqual(self.c.cli('proxima','status')['height'],0)

    def test_mesh_selection_contention_is_unknown_without_native_or_custody_progress(self):
        config,_=self.config('proxima')
        service=self.service('proxima',config)
        before=(self.root/'proxima/journal.json').read_bytes()
        with mesh.Node(config):report=service.tick()
        self.assertFalse(report['transport']['progress_observation_available'])
        self.assertNotIn('height',report['transport'])
        self.assertTrue(report['native_observation_available'])
        self.assertEqual(report['applied'],[]);self.assertEqual(service.bft_seen,set())
        self.assertEqual(before,(self.root/'proxima/journal.json').read_bytes())
        self.assertEqual(service.tick()['transport']['nodes'],1)

    def test_corrupt_mesh_selection_is_refused_without_unknown_fallback(self):
        config,ident=self.config('proxima')
        service=self.service('proxima',config)
        path=Path(config['state'])/'mesh-state.json';state=mesh.load(path,mesh.MAX_STATE)
        state['adverts'][ident]['body']['region']='0'*64
        mesh.atomic(path,state);damaged=path.read_bytes()
        before=(self.root/'proxima/journal.json').read_bytes()
        with self.assertRaises(ValueError):service.tick()
        self.assertEqual(path.read_bytes(),damaged)
        self.assertEqual(before,(self.root/'proxima/journal.json').read_bytes())

    def test_bad_received_frames_cannot_block_the_later_valid_native_import_or_double_credit(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        coins = self.c.cli('earth','status')['ledger']['coins']
        chosen = sorted(coins)[0]
        operation = self.c.intent('earth',[10],[(10,19)],('proxima',11,80,2),1,[chosen])
        self.c.mine('earth',[operation['command']])
        self.c.certify('earth')
        raw = wire.canonical(self.c.cli('earth','contact-export','--export',operation['export_or_transaction_id']))
        frame,payload = wire.inspect_frame(raw)
        source,source_id = self.config('earth')
        target,target_id = self.config('proxima')
        source['contacts'] = [{'peer':target_id,'inbox':str(self.root/'px-earth'),'outbox':str(self.root/'earth-px')}]
        target['contacts'] = [{'peer':source_id,'inbox':str(self.root/'earth-px'),'outbox':str(self.root/'px-earth')}]
        with mesh.Node(source) as node:
            for index in range(5):
                changed = wire.decode_json(payload)
                changed['currency'] = mesh.digest({'foreign':index})
                bad = wire.make_frame(frame['kind'],frame['source_chain_id'],frame['destination_chain_id'],frame['export_id'],wire.canonical(changed))
                node.enqueue(bad,target_id)
            node.enqueue(raw,target_id)
        producer = self.service('earth',source)
        receiver = self.service('proxima',target)
        for _ in range(16):
            producer.tick()
            receiver.tick()
        status = self.c.cli('proxima','status')
        self.assertEqual(status['height'],1)
        self.assertEqual(status['ledger']['minted'],'0')
        self.assertEqual(len(status['ledger']['imports']),1)
        self.assertEqual(len(self.c.cli('proxima','contact-status')['contacts']),1)
        self.assertIn(operation['export_or_transaction_id'],status['ledger']['imports'])
        self.assertFalse(receiver.tick()['native_observation']['contacts'][0]['original_recipient_output_spendable_now'])
        # The five invalid frames remain stored and signed storage receipts
        # exist, while only the real native export has become an import.
        with mesh.Node(target) as node:
            self.assertEqual(len(node.state['receipts']),6)
            self.assertEqual(len(node.state['messages']),6)


if __name__=='__main__':
    unittest.main()
