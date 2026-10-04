"""Explicit one-way spool lifecycle; signed transport only, no ledger authority."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from interstellar_mesh_inspection import MeshInspection, config_commitment

NETWORK='a'*64


class OneWayFixture:
    def __init__(self,root):
        self.root=Path(root).resolve();self.names=('source','forward','destination','return')
        self.identities={name:mesh.initialize(self.root/name,NETWORK,str(n+1)*64,name)
                         for n,name in enumerate(self.names)}
        self.ids={name:value['node_id'] for name,value in self.identities.items()}
        self.configs={name:dict(format=mesh.VERSION,state=str(self.root/name),network=NETWORK,contacts=[])
                      for name in self.names}
        self.edges=list(zip(self.names,self.names[1:]+self.names[:1]))
        for source,target in self.edges:
            send=self.root/source/'outgoing';receive=self.root/target/'incoming'
            self.configs[source]['contacts'].append(dict(peer=self.ids[target],adapter=mesh.SPOOL_ONEWAY,outbox=str(send)))
            self.configs[target]['contacts'].append(dict(peer=self.ids[source],adapter=mesh.SPOOL_ONEWAY,inbox=str(receive)))
        self.anchors={name:dict(public_key=self.identities[name]['public_key'],node_id=self.ids[name],network=NETWORK,
                                config_sha256=config_commitment(config)) for name,config in self.configs.items()}
        for config in self.configs.values():
            with mesh.Node(config):pass
    def carry(self,source,target,ancient=False):
        # A test carrier moves exact bytes between separate local directories.
        # Local publication/handoff is not a destination custody acknowledgment.
        send=self.root/source/'outgoing';receive=self.root/target/'incoming'
        files,total=mesh.spool_files(receive)
        for path in mesh.spool_files(send)[0]:
            raw=wire.read_file(path,mesh.MAX_BATCH);dest=receive/path.name
            if not dest.exists():
                mesh.require(len(files)<mesh.MAX_SPOOL_FILES and total+len(raw)<=mesh.MAX_SPOOL_BYTES,'carrier receiver capacity')
                wire.write_new(dest,raw);files.append(dest);total+=len(raw)
            else:mesh.require(wire.read_file(dest,mesh.MAX_BATCH)==raw,'carrier collision')
            if ancient:os.utime(dest,(1,1))
            path.unlink();fd=os.open(send,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
    def rounds(self,count=1,blocked=(),ancient=False):
        for _ in range(count):
            for name in self.names:
                with mesh.Node(self.configs[name]) as node:
                    result=node.tick();mesh.require(not result['errors'],str(result['errors']))
            for edge in self.edges:
                if edge not in blocked:self.carry(*edge,ancient=ancient)
    def frame(self):
        return wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"fixture":"native verification still required"}')


class OneWayContactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-oneway-');self.addCleanup(self.temp.cleanup)
        self.f=OneWayFixture(self.temp.name)
    def test_signed_discovery_needs_actual_reverse_path_and_advertises_only_outgoing_edges(self):
        f=self.f;f.rounds(5,blocked=(('return','source'),))
        with mesh.Node(f.configs['source']) as node:
            self.assertEqual(node.state['adverts'][node.id]['body']['neighbors'],[f.ids['forward']])
            self.assertIsNone(node.route(f.ids['destination']))
        f.rounds(7)
        with mesh.Node(f.configs['source']) as node:
            self.assertEqual(node.route(f.ids['destination']),[f.ids[n] for n in ('source','forward','destination')])
            # The incoming return carrier is reachable only around the directed
            # cycle; receiving its bytes creates no direct outgoing edge.
            self.assertEqual(node.route(f.ids['return']),[f.ids[n] for n in ('source','forward','destination','return')])
    def test_exact_frame_and_destination_receipt_take_separate_directed_paths_after_restart(self):
        f=self.f;f.rounds(7)
        with mesh.Node(f.configs['source']) as node:ident=node.enqueue(f.frame(),f.ids['destination'])
        # Four receive slots also rotate old discovery evidence; delivery has
        # no fixed three-tick promise. Keep a finite observation bound.
        for _ in range(16):
            f.rounds(1,blocked=(('destination','return'),),ancient=True)
            with mesh.Node(f.configs['destination']) as node:
                if ident in node.receipts():break
        with mesh.Node(f.configs['destination']) as node:
            self.assertIn(ident,node.receipts());self.assertEqual(mesh.transit_check(node.transit(ident),NETWORK)[1],f.frame())
            self.assertFalse(node.status()['payment_authorized'])
        with mesh.Node(f.configs['source']) as node:
            self.assertNotIn(ident,node.receipts());self.assertIn(ident,node.state['messages'])
        # Every round reopens real durable state, not an in-memory fixture node.
        for _ in range(16):
            f.rounds(1,ancient=True)
            with mesh.Node(f.configs['source']) as node:
                if ident in node.receipts():break
        with mesh.Node(f.configs['return']) as node:
            self.assertNotIn(ident,node.summaries());self.assertIn(ident,node.receipts())
        with mesh.Node(f.configs['source']) as node:
            self.assertIn(ident,node.receipts());self.assertFalse(node.status()['payment_authorized'])
    def test_wrong_direction_unknown_adapter_extra_fields_and_directory_alias_refuse(self):
        f=self.f
        with mesh.Node(f.configs['source']) as node:
            before=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'outgoing'):node.exchange(f.ids['return'])
            with mesh.Node(f.configs['forward']) as other:
                bundle=other.exchange(f.ids['destination'])
                bundle=mesh.sign(other.key,'exchange',dict(bundle['body'],to=f.ids['source']))
            with self.assertRaisesRegex(ValueError,'incoming'):node.receive(bundle,f.ids['forward'])
            self.assertEqual(node.path.read_bytes(),before)
        for mutate in (lambda c:c.update(adapter='unknown'),lambda c:c.update(host='127.0.0.1'),lambda c:c.pop('adapter')):
            config=copy.deepcopy(f.configs['source']);mutate(config['contacts'][0])
            with self.assertRaises(ValueError):mesh.Node(config)
        config=copy.deepcopy(f.configs['source']);config['contacts'][1]['inbox']=config['contacts'][0]['outbox']
        with self.assertRaisesRegex(ValueError,'distinct'):mesh.Node(config)
    def test_invalid_signature_and_durable_failure_keep_incoming_bytes_and_prior_state(self):
        f=self.f;f.rounds(7)
        with mesh.Node(f.configs['source']) as node:node.tick()
        f.carry('source','forward')
        path=mesh.spool_files(f.root/'forward'/'incoming')[0][0]
        bundle=wire.decode_json(path.read_bytes());bundle['signature']='0'*128
        raw=wire.canonical(bundle);path.unlink();path=path.parent/(mesh.digest(bundle)+'.json');wire.write_new(path,raw)
        with mesh.Node(f.configs['forward']) as node:
            before=copy.deepcopy({key:node.state[key] for key in ('adverts','messages','receipts')});result=node.tick()
            self.assertTrue(any('signature' in error for error in result['errors']))
            self.assertEqual(path.read_bytes(),raw)
            # Tick advances its ordinary cursor, but hostile evidence is absent.
            self.assertEqual({key:node.state[key] for key in before},before)
        path.unlink()
        with mesh.Node(f.configs['source']) as node:
            node.enqueue(f.frame(),f.ids['destination']);node.tick()
        f.carry('source','forward')
        path=mesh.spool_files(f.root/'forward'/'incoming')[0][0];raw=path.read_bytes()
        with mesh.Node(f.configs['forward']) as node:
            receive=node.receive
            def fail(bundle,peer):
                with patch.object(mesh,'atomic',side_effect=OSError('durable state refused')):return receive(bundle,peer)
            with patch.object(node,'receive',side_effect=fail):result=node.tick()
            self.assertTrue(any('durable' in error for error in result['errors']))
            self.assertEqual(path.read_bytes(),raw)
    def test_full_spool_refuses_new_publication_without_losing_pending_evidence(self):
        f=self.f;f.rounds(7)
        with mesh.Node(f.configs['source']) as node:
            ident=node.enqueue(f.frame(),f.ids['destination'])
            with patch.object(mesh,'MAX_SPOOL_FILES',0):result=node.tick()
            self.assertTrue(any('capacity' in error for error in result['errors']))
            self.assertIn(ident,node.state['messages']);self.assertNotIn(ident,node.receipts())
    def test_cold_inspection_uses_public_setup_anchor_and_checks_direction_without_private_identity(self):
        f=self.f;f.rounds(7)
        def inventory():return {str(p.relative_to(f.root)):p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
        before=inventory();opening=os.open
        def forbid_identity(path,*args,**kwargs):
            if str(path).endswith('identity.private.json'):raise AssertionError('private identity inspection')
            return opening(path,*args,**kwargs)
        with patch.object(os,'open',side_effect=forbid_identity):
            with MeshInspection(f.configs['source'],**f.anchors['source']) as node:
                self.assertEqual(mesh.Node.route(node,f.ids['destination']),[f.ids[n] for n in ('source','forward','destination')])
        self.assertEqual(inventory(),before)
        config=copy.deepcopy(f.configs['source']);out=config['contacts'][0];out['inbox']=out.pop('outbox')
        with self.assertRaisesRegex(ValueError,'config'):
            MeshInspection(config,**f.anchors['source'])
        with self.assertRaisesRegex(ValueError,'pinned config'):
            MeshInspection(config,**dict(f.anchors['source'],config_sha256=config_commitment(config)))
        self.assertEqual(inventory(),before)



class OneWayNativeLifecycleTests(unittest.TestCase):
    def test_default_four_node_directed_carriage_offline_source_native_import_payment_and_cold(self):
        import hashlib
        import subprocess
        import sys
        import time
        from regional_contact_campaign import Campaign, public
        binary=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()
        from contextlib import nullcontext
        started=time.monotonic()
        retained=os.environ.get('RLD_ONEWAY_FIXTURE_ROOT')
        if retained:Path(retained).resolve().mkdir(mode=0o700)
        context=nullcontext(retained) if retained else tempfile.TemporaryDirectory(prefix='rld-oneway-native-')
        with context as temporary:
            c=Campaign(binary,Path(temporary).resolve()/'fixture')
            try:
                c.cli('return','init','--bootstrap',c.root/'bootstrap.json','--region','proxima')
                for _ in range(4):c.mine('earth')
                c.certify('earth');status=c.cli('earth','status')
                chosen=next(i for i,coin in sorted(status['ledger']['coins'].items())
                    if coin['mature']<=status['height'] and coin['payment']['owner']==public(10)
                    and coin['payment']['amount']=='100')
                intent=c.intent('earth',[10],[(10,19)],('andromeda',11,80,2),1,[chosen])
                c.mine('earth',[intent['command']]);c.certify('earth')
                original=c.cli('earth','status')['ledger']
                names=('earth','proxima','andromeda','return');edges=list(zip(names,names[1:]+names[:1]))
                identities={name:mesh.initialize(c.root/name/'transport',c.currency,
                    c.regions.get(name,c.regions['proxima']),name) for name in names}
                configs={name:dict(format=mesh.VERSION,state=str(c.root/name/'transport'),network=c.currency,contacts=[])
                         for name in names}
                directories={}
                for source,target in edges:
                    send=c.root/source/'transport'/'outgoing';receive=c.root/target/'transport'/'incoming'
                    directories[source,target]=(send,receive)
                    configs[source]['contacts'].append(dict(peer=identities[target]['node_id'],adapter=mesh.SPOOL_ONEWAY,outbox=str(send)))
                    configs[target]['contacts'].append(dict(peer=identities[source]['node_id'],adapter=mesh.SPOOL_ONEWAY,inbox=str(receive)))
                anchors={name:dict(public_key=identities[name]['public_key'],node_id=identities[name]['node_id'],
                    network=c.currency,config_sha256=config_commitment(config)) for name,config in configs.items()}
                for name,config in configs.items():
                    mesh.atomic(c.root/name/'transport/config.json',config)
                    with mesh.Node(config):pass
                carrier_moves=0
                def carry():
                    nonlocal carrier_moves
                    for send,receive in directories.values():
                        files,total=mesh.spool_files(receive)
                        for path in mesh.spool_files(send)[0]:
                            raw=wire.read_file(path,mesh.MAX_BATCH);dest=receive/path.name
                            if not dest.exists():
                                mesh.require(len(files)<mesh.MAX_SPOOL_FILES and total+len(raw)<=mesh.MAX_SPOOL_BYTES,'mechanical carrier capacity')
                                wire.write_new(dest,raw);files.append(dest);total+=len(raw)
                            else:mesh.require(wire.read_file(dest,mesh.MAX_BATCH)==raw,'mechanical carrier collision')
                            path.unlink();fd=os.open(send,os.O_RDONLY)
                            try:os.fsync(fd)
                            finally:os.close(fd)
                            carrier_moves+=1
                def observation(name):
                    p=c.processes.get(name)
                    if p is not None:self.assertIsNone(p.poll())
                    value=mesh.load(c.root/name/'transport/regional-contact-status.json',mesh.MAX_STATE)
                    if p is not None:
                        mesh.require(value['process_id']==p.pid,'stale process observation; await current startup')
                    return value
                def wait(check,label):
                    deadline=time.monotonic()+30
                    while time.monotonic()<deadline:
                        carry()
                        try:
                            if result:=check():return result
                        except (OSError,ValueError,KeyError):pass
                        time.sleep(0.05)
                    self.fail('bounded one-way native observation: '+label)
                def start(name,miner=False):
                    log=(c.root/(name+'-oneway.log')).open('ab');c.logs.append(log)
                    command=[str(binary),'--dir',str(c.root/name),'--authority',c.authority,
                        '--currency',c.currency,'--transport-python',sys.executable,'--interval','0.1']
                    if miner:command+=['--miner',public(10)]
                    c.processes[name]=subprocess.Popen(command,stdout=log,stderr=log)
                    wait(lambda:observation(name)['native_observation_available'],name+' ordinary default startup')
                    self.assertEqual(observation(name)['transport']['tcp']['contacts']['observations'],{})
                for name in names:start(name)
                wait(lambda:any(x['evidence_verified'] and not x['import_accepted']
                    for x in observation('andromeda')['native_observation']['contacts']),'verified destination pending, no miner')
                self.assertEqual(c.cli('andromeda','status')['height'],0)
                self.assertFalse(c.cli('andromeda','status')['ledger']['coins'])
                c.stop('earth');c.offline_earth=original;c.remote_interval=True
                source_journal=(c.root/'earth/journal.json').read_bytes()
                c.stop('andromeda');start('andromeda',miner=True)
                wait(lambda:any(x['import_accepted'] for x in observation('andromeda')['native_observation']['contacts']),
                     'native import without source process or source CLI')
                c.mine('andromeda');c.mine('andromeda');c.certify('andromeda')
                local=c.intent('andromeda',[11],[(14,50),(11,27)],None,1)
                c.mine('andromeda',[local['command']]);c.certify('andromeda')
                ledger=c.cli('andromeda','status')['ledger']
                self.assertEqual(sum(int(x['payment']['amount']) for x in ledger['coins'].values()
                    if x['payment']['owner']==public(14)),50)
                self.assertEqual((c.root/'earth/journal.json').read_bytes(),source_journal)
                self.assertEqual(c.earth_calls_while_offline,0)
                c.remote_interval=False;start('earth')
                wait(lambda:any(v=='ARCHIVED_EVIDENCE_STORED_NOT_LEDGER_ACCEPTED' or v=='EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'
                    for v in observation('earth')['transport']['messages'].values()),'signed receipt through distinct return carrier')
                self.assertEqual(c.cli('earth','status')['ledger'],original)
                self.assertGreater(carrier_moves,0)
                for name in list(c.processes):c.stop(name)
                def inventory():return {str(p.relative_to(c.root)):(hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mode)
                    for p in c.root.rglob('*') if p.is_file()}
                before=inventory()
                for name in names:
                    self.assertEqual(c.cli(name,'status')['currency'],c.currency)
                    with MeshInspection(configs[name],**anchors[name]) as node:
                        for ident in node.state['archives']:node.archived(ident)
                self.assertEqual(inventory(),before)
                c.audit('one-way native default lifecycle, full source stop, recipient local payment and cold')
                self.assertEqual(c.checks[-1]['issued'],'300');self.assertEqual(c.checks[-1]['pending_exports'],'0')
                if report:=os.environ.get('RLD_ONEWAY_REPORT'):
                    import json
                    out=Path(report);self.assertFalse(out.exists())
                    out.write_text(json.dumps(dict(format='RLD-ONEWAY-DEFAULT-NATIVE-LIFECYCLE-V1',completed=True,
                        fixture_only=True,live_rld=False,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                        currency=c.currency,ordinary_default_startup=True,explicit_directed_contacts=4,
                        exact_signed_carrier_moves=carrier_moves,source_process_stopped_during_import_and_local_payment=True,
                        source_native_calls_while_offline=c.earth_calls_while_offline,source_journal_unchanged_while_offline=True,
                        recipient_local_payment='50',source_original_debit_unchanged=True,full_native_cold_replay_nodes=4,
                        strict_setup_public_config_anchor_transport_inspection=True,private_files_and_permissions_unchanged=True,
                        issuance='300',unresolved_exports='0',controller_unanimous_certification=True,
                        mechanical_same_host_carrier=True,autonomous_bft_qualified=False,physical_adapter_qualified=False,
                        independent_custody_qualified=False,duration_seconds=round(time.monotonic()-started,3)),indent=2)+'\n')
            finally:c.cleanup()


if __name__=='__main__':unittest.main()
