#!/usr/bin/env python3
"""Three native ledger/contact processes, adjacent discovery, offline value return.

All monetary keys are public fixture seeds. Mesh identities and contact state
stay in the caller's private fixture directory, never in the sanitized report.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire

NAMES = ['earth', 'proxima', 'andromeda']


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def seeds(name):
    first = {'earth': 2, 'proxima': 22, 'andromeda': 42}[name]
    return sorted(range(first, first+4), key=public)


def save(path, value):
    path.write_bytes(wire.canonical(value))


class Campaign:
    def __init__(self, binary, root, adapter='directory'):
        mesh.require(adapter in ('directory','tcp'), 'unsupported fixture contact adapter')
        self.adapter=adapter
        self.listen={}
        self.binary = Path(binary).resolve()
        self.helper = self.binary.with_name('contact-fixture')
        self.root = Path(root).absolute()
        self.root.mkdir(mode=0o700)
        self.calls = self.helper_calls = self.starts = 0
        self.processes, self.logs, self.configs, self.heads, self.active = {}, [], {}, {}, {}
        self.checks = []
        self.offline_earth = None
        self.remote_interval = False
        self.earth_calls_while_offline = 0
        self.bootstrap = self.help('bootstrap')
        self.currency = self.bootstrap['admissions'][0]['currency']
        self.authority = public(1)
        self.regions = {}
        save(self.root / 'bootstrap.json', self.bootstrap)
        for name in NAMES:
            self.regions[name] = self.cli(name, 'init', '--bootstrap', self.root/'bootstrap.json', '--region', name)['region']
            self.active[name] = seeds(name)
            for seed in self.active[name]:
                self.init_signer(name, seed)

    def invoke(self, command, helper=False, success=True):
        deadline = time.monotonic()+30
        while True:
            if helper:
                self.helper_calls += 1
            else:
                self.calls += 1
            output = subprocess.run(list(map(str, command)), capture_output=True, timeout=30, check=False)
            reason = output.stderr.decode(errors='replace')
            busy = 'would block' in reason or 'temporarily unavailable' in reason
            if success and output.returncode and busy and time.monotonic() < deadline:
                time.sleep(0.025)
                continue
            mesh.require((output.returncode == 0) == success, 'fixture CLI failure: '+reason[:2048])
            return wire.decode_json(output.stdout) if success else {'rejected': True, 'reason': reason}

    def cli(self, name, *args, success=True):
        if name == 'earth' and self.remote_interval:
            self.earth_calls_while_offline += 1
            raise ValueError('Earth was invoked during the required remote-only interval')
        return self.invoke([self.binary, '--dir', self.root/name, '--authority', self.authority if hasattr(self, 'authority') else public(1),
            '--currency', self.currency, *args], success=success)

    def help(self, *args):
        return self.invoke([self.helper, *args], helper=True)

    def init_signer(self, name, seed):
        key = self.root/f'{name}-key-{seed}.json'
        save(key, {'secret_key': (bytes([seed])*32).hex()})
        key.chmod(0o600)
        result = self.cli(name, 'signer-init', '--signer-dir', self.root/f'{name}-signer-{seed}', '--key', public(seed))
        self.heads[name, seed] = result['lock_head']

    def vote(self, name, seed, action='sign-checkpoint', proposal=None):
        args = [action, '--signer-dir', self.root/f'{name}-signer-{seed}', '--key-file', self.root/f'{name}-key-{seed}.json',
            '--expected-lock', self.heads[name, seed]]
        if proposal:
            args.extend(['--file', proposal])
        result = self.cli(name, *args)
        self.heads[name, seed] = result['lock_head']
        # Surviving head pins are outside the respective signer directories.
        save(self.root/'caller-retained-heads.json', {f'{n}-{s}': h for (n,s),h in self.heads.items()})
        return result['approval']

    def certify(self, name):
        snapshot = self.cli(name, 'statement')
        snapshot['approvals'] = [self.vote(name, seed) for seed in self.active[name]]
        path = self.root/f'{name}-checkpoint.json'
        save(path, snapshot)
        self.cli(name, 'finalize', '--file', path)
        self.audit(name+':unanimous checkpoint')
        return snapshot

    def intent(self, name, owners, outputs=(), remote=None, fee=0, inputs=None):
        request = {'owners': owners, 'inputs': inputs, 'outputs': [{'seed': s, 'amount': str(a)} for s,a in outputs],
            'remote': None if remote is None else {'region': remote[0], 'seed': remote[1], 'amount': str(remote[2]), 'fee': str(remote[3])}, 'fee': str(fee)}
        path = self.root/'intent-request.json'
        save(path, request)
        return self.help('intent', '--dir', self.root/name, '--currency', self.currency, '--request', path)

    def mine(self, name, commands=(), success=True):
        path = self.root/'commands.json'
        save(path, list(commands))
        result = self.cli(name, 'mine', '--miner', public(10), '--commands', path, success=success)
        if success:
            self.audit(name+':native block')
        return result

    def live(self):
        for name, process in self.processes.items():
            mesh.require(process.poll() is None, 'native contact process exited: '+name)

    def wait(self, check, label, timeout=30):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            self.live()
            try:
                result = check()
                if result:
                    return result
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(0.05)
        raise ValueError('bounded ground observation deadline: '+label)

    def status(self, name):
        report=mesh.load(self.root/(name+'-mesh')/'regional-contact-status.json',mesh.MAX_STATE)
        if name in self.processes:
            mesh.require(report.get('process_id')==self.processes[name].pid,'observation belongs to an earlier process')
        return report

    def start(self, name, miner=True):
        mesh.require(name not in self.processes, 'process is already running')
        log = (self.root/(name+'.log')).open('ab')
        self.logs.append(log)
        command=[str(self.binary), '--dir', str(self.root/name), '--authority', self.authority,
            '--currency', self.currency, '--mesh-config', str(self.root/(name+'.mesh-config.json')),
            '--transport-python', sys.executable, '--interval', '0.25']
        if miner:
            command.extend(['--miner',public(10)])
        if self.adapter=='tcp':
            command.extend(['--mesh-listen','127.0.0.1:'+str(self.listen[name])])
        self.processes[name] = subprocess.Popen(command, stdout=log, stderr=log)
        self.starts += 1
        self.wait(lambda:self.status(name)['native_observation_available'],name+' native process startup handshake')

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process:
            process.terminate()
            process.wait(timeout=30)
            mesh.require(process.returncode == 0, 'native contact process did not stop cleanly: '+name)

    def transport_setup(self):
        self.ids = {name: mesh.initialize(self.root/(name+'-mesh'), self.currency, self.regions[name], name)['node_id'] for name in NAMES}
        pins={}
        if self.adapter=='tcp':
            pins={name:tcp.public_tls_identity({'format':mesh.VERSION,'state':str(self.root/(name+'-mesh')),
                'network':self.currency,'contacts':[]})['tls_cert_sha256'] for name in NAMES}
            held=[]
            try:
                for name in NAMES:
                    s=socket.socket()
                    s.bind(('127.0.0.1',0))
                    held.append(s)
                    self.listen[name]=s.getsockname()[1]
            finally:
                for s in held:
                    s.close()
        for index, name in enumerate(NAMES):
            contacts = [({'peer': self.ids[other], 'host':'127.0.0.1','port':self.listen[other],
                'tls_cert_sha256':pins[other]}
                if self.adapter=='tcp' else {'peer': self.ids[other], 'inbox': str(self.root/'contact'/(other+'-'+name)),
                'outbox': str(self.root/'contact'/(name+'-'+other))}) for j,other in enumerate(NAMES) if abs(j-index)==1]
            config = {'format': mesh.VERSION, 'state': str(self.root/(name+'-mesh')), 'network': self.currency, 'contacts': contacts}
            self.configs[name] = config
            save(self.root/(name+'.mesh-config.json'), config)
            self.start(name)
        self.wait(lambda: all(self.status(n)['transport']['nodes']==3 and self.status(n)['native_observation_available'] for n in NAMES), 'three native nodes discovered')
        mesh.require(self.status('earth')['transport']['routes'][self.ids['andromeda']] == [self.ids[n] for n in NAMES], 'learned route is not two adjacent hops')

    def imported(self, name, eid):
        observation = self.status(name)['native_observation']
        return observation and any(c['export']==eid and c['import_accepted'] for c in observation['contacts'])

    def audit(self, phase):
        ledgers = []
        for name in NAMES:
            if self.remote_interval and name=='earth':
                ledger = self.offline_earth
            else:
                ledger = self.cli(name, 'status')['ledger']
            ledgers.append(ledger)
        issued = sum(int(l['minted']) for l in ledgers)
        liquid = sum(int(c['payment']['amount']) for l in ledgers for c in l['coins'].values())
        pending = sum(int(e['recipient']['amount']) for l in ledgers for e in l['exports'].values()) - sum(int(l['received']) for l in ledgers)
        mesh.require(issued == liquid+pending and pending >= 0, 'actual native value conservation failed: '+phase)
        self.checks.append({'phase': phase, 'issued': str(issued), 'liquid': str(liquid), 'pending_exports': str(pending), 'conserved': True})

    def rotate_earth(self):
        new = sorted(range(62,66), key=public)
        for seed in new:
            self.init_signer('earth', seed)
        path = self.root/'validators.json'
        save(path, [public(s) for s in new])
        proposal = self.cli('earth', 'propose-epoch', '--validators', path)
        path = self.root/'handoff-request.json'
        save(path, proposal)
        old_votes = [self.vote('earth', s, 'sign-handoff', path) for s in self.active['earth']]
        new_votes = [self.vote('earth', s, 'sign-handoff', path) for s in new]
        proposal['old_approvals'], proposal['new_approvals'] = old_votes, new_votes
        save(path, proposal)
        self.cli('earth', 'install-epoch', '--file', path)
        self.active['earth'] = new
        self.mine('earth')
        self.certify('earth')

    def cleanup(self):
        for name in list(self.processes):
            self.stop(name)
        for log in self.logs:
            log.close()

    def prepare_remote_interval(self, first, second):
        if self.adapter=='tcp':
            # Actual sockets cannot move bytes after the source disappears.
            # Give neighboring carriers custody before disconnecting Earth;
            # explicit relay-only startup verifies but does not mine imports.
            self.stop('andromeda')
            self.start('andromeda',miner=False)
            self.start('proxima',miner=False)
            def pending(name,eid):
                observation=self.status(name)['native_observation']
                return observation and any(c['export']==eid and c['evidence_verified']
                    and not c['import_accepted'] for c in observation['contacts'])
            self.wait(lambda:pending('proxima',first['export_or_transaction_id'])
                and pending('andromeda',second['export_or_transaction_id']), 'native pending evidence has crossed real sockets')
            self.wait(lambda:sum(v=='EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'
                for v in self.status('earth')['transport']['messages'].values())>=2, 'signed destination custody before Earth disconnects')
            self.stop('proxima')
            self.stop('andromeda')
        self.stop('earth')
        self.rotate_earth()
        self.offline_earth = self.cli('earth', 'status')['ledger']
        self.start('proxima')
        if self.adapter=='tcp':
            self.start('andromeda')

    def run(self):
        for _ in range(4):
            self.mine('earth')
        self.certify('earth')
        self.transport_setup()
        self.stop('proxima')
        original = self.cli('earth', 'status')['ledger']
        mature = sorted(i for i,c in original['coins'].items() if int(c['mature']) <= 5)
        first = self.intent('earth', [10], [(10,19)], ('proxima',11,80,2), 1, [mature[0]])
        second = self.intent('earth', [10], [(10,49)], ('andromeda',12,50,2), 1, [mature[1]])
        self.mine('earth', [first['command'], second['command']])
        self.certify('earth')
        self.wait(lambda: len(self.status('earth')['transport']['messages'])>=2, 'durable queued exports while relay is stopped')
        self.stop('earth')
        with mesh.Node(self.configs['earth']) as node:
            queued = [t for t in node.state['messages'].values() if t['packet']['body']['node_id']==node.id]
            mesh.require(len(queued)>=2 and not node.state['receipts'], 'sender restart lost or prematurely acknowledged exports')
        self.start('earth')
        self.wait(lambda: self.status('earth')['native_observation_available'], 'sender restarted with queue')
        self.prepare_remote_interval(first,second)
        self.remote_interval = True
        self.wait(lambda: self.imported('proxima',first['export_or_transaction_id']) and self.imported('andromeda',second['export_or_transaction_id']), 'old-era in-flight native imports')
        self.audit('old-era finalized exports imported through neighbors after origin handoff')
        with mesh.Node(self.configs['andromeda']) as node:
            forwarded = [t for t in node.state['messages'].values() if wire.inspect_frame(base64.b64decode(t['packet']['body']['frame']))[0]['export_id']==second['export_or_transaction_id']]
            mesh.require(forwarded and all(len(t['hops'])==2 for t in forwarded), 'direct Earth value did not use two actual relay hops')
        for _ in range(2):
            self.mine('proxima')
        self.certify('proxima')
        split = self.intent('proxima', [11], [(12,30),(11,47)], fee=1)
        self.mine('proxima', [split['command']])
        self.certify('proxima')
        onward = self.intent('proxima', [12], remote=('andromeda',12,29,1), fee=1)
        self.mine('proxima', [onward['command']])
        self.certify('proxima')
        self.wait(lambda: self.imported('andromeda',onward['export_or_transaction_id']), 'automatic onward native import with Earth stopped')
        self.audit('onward value accepted; no Earth service or directory calls')
        for _ in range(2):
            self.mine('andromeda')
        self.certify('andromeda')
        merged = self.intent('andromeda', [12], [(12,30),(13,45)], fee=1)
        self.mine('andromeda', [merged['command']])
        self.certify('andromeda')
        returning = self.intent('andromeda', [12,13], remote=('earth',14,74,1), fee=1)
        forged = json.loads(json.dumps(returning['command']))
        forged['Spend']['approvals'].pop()
        self.mine('andromeda', [forged], success=False)
        self.mine('andromeda', [returning['command']])
        self.certify('andromeda')
        self.wait(lambda: any(v=='QUEUED_WAITING_CONTACT_OR_ROUTE' for v in self.status('andromeda')['transport']['messages'].values()), 'return queued while Earth is absent')
        self.audit('new return export waits for restored adjacent contact')
        mesh.require(self.earth_calls_while_offline==0, 'Earth was used in distant execution')
        self.remote_interval = False
        self.start('earth')
        self.wait(lambda: self.imported('earth',returning['export_or_transaction_id']), 'Earth receives new return once')
        self.audit('new return imported exactly once; original debit remains')
        for _ in range(2):
            self.mine('earth')
        self.certify('earth')
        earth = self.cli('earth', 'status')['ledger']
        mesh.require(first['export_or_transaction_id'] in earth['exports'] and first['export_or_transaction_id']!=returning['export_or_transaction_id'], 'return released/reused original debit')
        original_output = [c for c in self.cli('earth','contact-status')['contacts'] if c['export']==returning['export_or_transaction_id']]
        mesh.require(original_output and original_output[0]['original_recipient_output_spendable_now'], 'returned recipient output is not locally spendable')
        before = self.cli('andromeda', 'status')
        self.stop('andromeda')
        self.start('andromeda')
        self.wait(lambda: self.status('andromeda')['native_observation_available'], 'destination restart')
        after = self.cli('andromeda', 'status')
        mesh.require(before['state']==after['state'] and before['height']==after['height'], 'destination restart double imported or mined')
        # Transport-valid hostile carriage: the claimed currency is foreign.
        raw = wire.canonical(self.cli('earth','contact-export','--export',second['export_or_transaction_id']))
        frame,payload = wire.inspect_frame(raw)
        hostile = wire.decode_json(payload)
        hostile['currency'] = 'f'*64
        bad = wire.make_frame(frame['kind'],frame['source_chain_id'],frame['destination_chain_id'],frame['export_id'],wire.canonical(hostile))
        with mesh.Node(self.configs['earth']) as node:
            bad_packet = node.enqueue(bad,self.ids['andromeda'])
        self.wait(lambda: any(r['packet_id']==bad_packet and 'wrong currency' in r['reason'] for r in self.status('andromeda')['rejected']), 'transport-valid foreign currency rejected by native ledger')
        self.wait(lambda: self.status('earth')['transport']['messages'].get(bad_packet)=='EVIDENCE_STORED_NOT_LEDGER_ACCEPTED', 'hostile byte-storage receipt is not credit')
        final = self.cli('andromeda','status')
        mesh.require(final['state']==after['state'] and final['height']==after['height'], 'transport receipt changed destination value')
        self.audit('hostile transport received and acknowledged but native credit rejected')
        self.live()
        if self.adapter=='tcp':
            mesh.require(not (self.root/'contact').exists(), 'TCP campaign unexpectedly used shared spools')
            mesh.require(all(any(v.get('inbound_last_success_at_unix') or v.get('outbound_last_success_at_unix')
                for v in self.status(n)['transport']['tcp']['contacts']['observations'].values()) for n in NAMES),
                'TCP campaign lacks observed signed socket contact')
        return {'format':'RLD-NATIVE-CONTACT-CAMPAIGN-V1','date':'2026-09-30','result':'PASS_BOUNDED_NATIVE_CONTACT_VALUE_RETURN',
            'implementation':self.bootstrap['currency']['implementation'],'currency':self.currency,'regions':NAMES,
            'topology':'Earth <-> Proxima Centauri <-> Andromeda; only adjacent '+self.adapter+' contacts',
            'transport_runtime':'Python signed '+self.adapter+' contact companion launched by native CLI; Rust verifies and mines value',
            'contact_adapter':self.adapter,'actual_ipv4_loopback_sockets':self.adapter=='tcp',
            'shared_spools_used':self.adapter=='directory','cross_host_contact_qualified':False,'encrypted_transport':self.adapter=='tcp',
            'tls_version':'TLSv1.3' if self.adapter=='tcp' else None,'tls_pinned_certificate_and_signed_connection_challenge':self.adapter=='tcp',
            'plaintext_fallback':False,
            'tcp_custody_before_source_disconnect':self.adapter=='tcp',
            'native_contact_process_starts':self.starts,'direct_native_cli_invocations_including_busy_retries':self.calls,
            'public_fixture_helper_invocations':self.helper_calls,'learned_remote_route_hops':2,
            'automatic_native_evidence_and_import':True,'old_era_exports_accepted_after_in_flight_origin_handoff':True,
            'normal_node_startup_enables_relay_without_subcommand':True,
            'relay_stop_sender_restart_and_resume':True,'destination_restart_without_duplicate_credit':True,
            'earth_services_removed_for_remote_local_payment_and_onward':True,'earth_calls_during_remote_interval':0,
            'multiple_sources_split_merge_fees_and_multiple_owners':True,'new_cyclic_return_and_permanent_initial_debit':True,
            'transport_valid_foreign_currency_rejected_without_credit':True,'storage_receipt_does_not_grant_payment':True,
            'return_gross_amount':'74','return_original_recipient_amount':'73','checks':self.checks,
            'original_export':first['export_or_transaction_id'],'direct_two_hop_export':second['export_or_transaction_id'],
            'onward_export':onward['export_or_transaction_id'],'new_return_export':returning['export_or_transaction_id'],
            'physical_route_verified':False,'independent_operators':False,'mainnet_authorized':False,'live_rld':False,
            'elapsed_years_or_storage_aging_verified':False,'source_http_used':False,
            'limits':{'native_contact_records':256,'applications_and_offers_per_poll':4,'frame_bytes':wire.MAX_FRAME,'payload_bytes':wire.MAX_PAYLOAD},
            'remaining':['BFT fork choice/view changes and independent reconfiguration','payment channels and their liquidity reservations','complete wallet product, independent encrypted-custody qualification and cross-device/reorganization recovery',
                'cross-host/physical contact and independent TLS security qualification; adversarial availability/resource admission','cryptographic horizons and delayed revocation',
                'external monotonic rollback roots and independent long-term archives','independent operators/custody/review and actual release']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--adapter',choices=['directory','tcp'],default='directory')
    args = parser.parse_args()
    c = Campaign(args.binary,args.root,args.adapter)
    try:
        report = c.run()
        wire.write_new(args.report,wire.canonical(report))
        print(json.dumps(report,indent=2))
    finally:
        c.cleanup()


if __name__=='__main__':
    main()
