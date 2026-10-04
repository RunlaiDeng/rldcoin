#!/usr/bin/env python3
"""Continue a sealed no-value twelve-node cycle under bounded ground faults.

The original stores remain untouched. A sole-controller, private copy retains
native journals, exact caller heads, identities and TLS pins; it is not an
independent restore or copied-key custody qualification. Ordinary nodes perform
all votes, catch-up, exports and imports. The controller only signs actual owner
requests, operates its processes/ciphertext fault relays and reads observations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import threading
import time

from regional_ground_value import audit_certified_prefixes
from regional_ground_relay import MeteredRelay


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeReceiptProbe:
    """Limit controller read interference; never retain an authorization result."""
    interval_seconds = 2

    def __init__(self):
        self.next_read = 0.0
        self.attempts = 0

    def attempt(self, read, accepts):
        now = time.monotonic()
        if now < self.next_read:
            return False
        self.next_read = now + self.interval_seconds
        self.attempts += 1
        value = read()
        return value if accepts(value) else False


def retain_fault_inspection_anchors(root, source_anchors, network, node_ids):
    """Pin public source identities and operator-rebound configs before startup.

    The caller must already have authenticated the completed source's exact
    setup anchors. Never read a copied private identity to derive a cold anchor.
    """
    import interstellar_mesh as mesh
    from interstellar_mesh_inspection import config_commitment
    names = {f'{region}-{replica}' for region in ('earth', 'proxima', 'andromeda')
             for replica in range(4)}
    mesh.require(set(source_anchors) == {'format', 'network', 'nodes'}
                 and source_anchors['format'] == 'RLD-MULTIREGION-MESH-INSPECTION-ANCHORS-V1'
                 and source_anchors['network'] == network
                 and set(source_anchors['nodes']) == names
                 and {f'{name}-{n}' for name, n in node_ids} == names,
                 'complete authenticated source inspection anchors required')
    path = root/'fault-mesh-inspection-anchors.json'
    mesh.require(not path.exists() and not path.is_symlink(),
                 'retain existing fault setup inspection anchors')
    result = dict(format=source_anchors['format'], network=network, nodes={})
    for name, n in sorted(node_ids):
        label = f'{name}-{n}'
        row = source_anchors['nodes'][label]
        mesh.require(set(row) == {'public_key', 'node_id', 'network', 'config_sha256'}
                     and row['network'] == network
                     and mesh.node_id(mesh.hex32(row['public_key'])) == row['node_id'] == node_ids[name,n],
                     'source public carrier differs from configured fixture pin')
        mesh.hex32(row['config_sha256'])
        config = mesh.load(root/f'mesh-config-{label}.json', 65536)
        mesh.require(config['network'] == network,
                     'rebound fault transport network differs')
        result['nodes'][label] = dict(row, config_sha256=config_commitment(config))
    mesh.require(len({row['node_id'] for row in result['nodes'].values()}) == 12,
                 'fault carrier identities must remain distinct')
    mesh.atomic(path, result)
    return digest(path)


def retained_resume_heights(record, manifest, implementation):
    """Bind a recovery stage to a stopped failed drill, never a fresh pass."""
    commitment=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    checks=record.get('conservation_checks') or []
    cold=checks[-1] if checks else {}
    drill=[e for e in manifest['files'] if e['path']=='tools/regional_bft_sustained_campaign.py']
    if not (record.get('fixture_only') is True and record.get('live_rld') is False
            and record.get('completed') is False and record.get('owned_process_cleanup_verified') is True
            and record.get('sealed_source_state_unchanged') is True
            and record.get('native_implementation')==manifest.get('native_implementation')==implementation
            and record.get('runtime_source_set_sha256')==manifest.get('source_set_sha256')==commitment
            and len(drill)==1 and record.get('drill_source_sha256')==drill[0]['sha256']
            and all(type(record.get(k)) is int and record[k]==0 for k in ('controller_generated_consensus_messages',
                'controller_carried_payment_proofs','controller_installed_checkpoints'))
            and cold.get('phase','').startswith('stopped native stores:')
            and cold.get('compatible_prefixes_verified') is True and cold.get('conserved') is True):
        raise ValueError('stopped failed fixture and exact prior source required for retained-payment recovery')
    heights=cold.get('replica_heights',{})
    if set(heights)!={'earth','proxima','andromeda'} or any(
            not isinstance(values,list) or len(values)!=4 or any(type(h) is not int or not 0<=h<=24 for h in values)
            for values in heights.values()):
        raise ValueError('twelve bounded cold native heights required for retained-payment recovery')
    return {name:list(values) for name,values in heights.items()}


def consensus_sample(observed):
    """Unavailable process telemetry is neither height zero nor ledger proof."""
    consensus=observed.get('consensus') or {}
    available=(consensus.get('progress_observation_available',True)
               and all(type(consensus.get(k)) is int for k in ('height','round','retained_messages')))
    return {'consensus_observation_complete':bool(available),
            'height':consensus.get('height') if available else None,
            'round':consensus.get('round') if available else None,
            'retained_bft_messages':consensus.get('retained_messages') if available else None,
            'consensus_diagnostic':consensus.get('diagnostic')}


def transport_sample(observed):
    """Optional mesh observations never grant custody or invent zero counters."""
    transport=observed.get('transport')
    if not isinstance(transport,dict):transport={}
    available=(transport.get('progress_observation_available',True) is True
               and all(type(transport.get(k)) is int and transport[k]>=0
                       for k in ('active_messages','archived_records')))
    tcp=transport.get('tcp')
    contacts=tcp.get('contacts') if isinstance(tcp,dict) else None
    if not isinstance(contacts,dict):contacts={}
    def counter(name):
        value=contacts.get(name)
        return value if type(value) is int and value>=0 else None
    diagnostic=transport.get('diagnostic')
    return {'transport_observation_complete':bool(available),
            'active_transport_packets':transport['active_messages'] if available else None,
            'archived_transport_records':transport['archived_records'] if available else None,
            'transport_diagnostic':diagnostic[:256] if isinstance(diagnostic,str) else
                                   (None if available else 'transport telemetry unavailable'),
            'tcp_local_lock_retries':counter('local_lock_retries'),
            'tcp_local_lock_exhaustions':counter('local_lock_exhaustions')}


def has_complete_commit_group(native_messages, context):
    """Read-only drain observation; callers supply native-verified messages.

    This does not construct a quorum or authorize installation. Only the
    ordinary companion/native verifier may install the retained certificate.
    """
    groups={}
    for message in native_messages:
        vote=message.get('Vote')
        if vote and vote['phase']=='Commit' and vote['context']==context:
            groups.setdefault((vote['round'],vote['value']),set()).add(vote['approval']['key'])
    return any(len(voters)>=3 for voters in groups.values())


class FaultRelay:
    """Bounded byte relay. It never terminates TLS or reads application JSON."""
    def __init__(self, target):
        self.target = target
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.enabled = False
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.capacity = threading.BoundedSemaphore(2)
        self.workers = []
        self.attempts = self.refused = self.forwarded = self.bytes = 0
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.attempts += 1
                enabled = self.enabled
            if not enabled or not self.capacity.acquire(blocking=False):
                with self.lock:
                    self.refused += 1
                client.close()
                continue
            worker = threading.Thread(target=self.forward, args=(client,), daemon=True)
            self.workers = [w for w in self.workers if w.is_alive()]
            self.workers.append(worker)
            worker.start()

    def forward(self, client):
        total = 0
        try:
            with client, socket.create_connection(self.target, timeout=1) as remote:
                client.settimeout(0.3)
                remote.settimeout(0.3)
                deadline = time.monotonic() + 4
                while not self.closed.is_set() and time.monotonic() < deadline:
                    readable, _, _ = select.select([client, remote], [], [], 0.1)
                    for source in readable:
                        raw = source.recv(65536)
                        if not raw:
                            return
                        total += len(raw)
                        if total > 64 * 1024 * 1024:
                            return
                        (remote if source is client else client).sendall(raw)
                        with self.lock:
                            self.bytes += len(raw)
        except OSError:
            pass
        finally:
            with self.lock:
                self.forwarded += 1
            self.capacity.release()

    def enable(self):
        with self.lock:
            self.enabled = True

    def report(self):
        with self.lock:
            return {'attempts': self.attempts, 'refused_connections': self.refused,
                    'forwarded_connections': self.forwarded, 'ciphertext_bytes_forwarded': self.bytes,
                    'max_workers': 2, 'max_connection_seconds': 4,
                    'max_connection_bytes': 64 * 1024 * 1024, 'TLS_terminated': False}

    def close(self):
        self.closed.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=5)
        if self.thread.is_alive() or any(w.is_alive() for w in self.workers):
            raise ValueError('owned ciphertext fault relay did not stop')


def execute(args, joint=False):
    drill_source_sha256=digest(Path(__file__))
    tools = args.runtime_tools.resolve()
    sys.path.insert(0, str(tools))
    import interstellar_mesh as mesh
    import interstellar_tcp as tcp
    from regional_bft_multiregion_campaign import Campaign as Cycle
    from regional_contact_campaign import public, seeds
    from regional_bft_node import FORMAT
    from regional_contact_node import Native

    manifest = json.loads(args.source_manifest.read_text())
    for entry in manifest['files']:
        if entry['path'].startswith('tools/') and Path(entry['path']).suffix == '.py':
            if digest(tools / Path(entry['path']).name) != entry['sha256']:
                raise ValueError('runtime differs from named frozen source')
    previous = json.loads(args.cycle_report.read_text())
    profile = None
    if joint:
        from regional_bft_joint_fault_profile import Profile, FORBIDDEN, READ_ONLY, bounded_read
        mesh.require(args.resume_report is None, 'joint retained-payment recovery is separately unimplemented')
        mesh.require(args.cycle_cold_report is not None and args.cycle_source_manifest is not None,
                     'joint fault scope requires exact cycle cold report/source manifest')
        profile = Profile(previous, json.loads(args.cycle_cold_report.read_text()),
                          json.loads(args.cycle_source_manifest.read_text()), manifest, digest(args.cycle_report))
    mesh.require(previous['mesh_format'] == mesh.VERSION == 'RLD-CONTACT-MESH-V3'
                 and previous['socket_adapter'] == tcp.ADAPTER == 'RLD-CONTACT-TCP-V4'
                 and (profile is not None or (previous['format'] == 'RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1'
                      and previous['replica_heights'] == {'earth': [7]*4, 'proxima': [4]*4, 'andromeda': [4]*4}))
                 and previous['initial_debit_never_released'], 'completed archive cycle required')
    recovery=args.resume_report is not None
    resume_record=None
    if recovery:
        resume_record=json.loads(args.resume_report.read_text())
        heights=retained_resume_heights(resume_record,json.loads(args.resume_source_manifest.read_text()),previous['implementation'])
        previous=dict(previous,replica_heights=heights)
    source, root = args.source_root.resolve(), args.root.resolve()
    mesh.require(source.is_dir() and not root.exists() and not root.is_relative_to(source),
                 'new private copy root required')
    from verify_regional_bft_cycle import inspection_anchors
    source_inspection_anchors = inspection_anchors(source, previous)
    process_snapshot = subprocess.check_output(['ps', '-A', '-o', 'args='], text=True)
    # Check the actual executable argv, not a stale lock or prior status PID.
    for line in process_snapshot.splitlines():
        executable = Path(line.split()[0]).name if line.split() else ''
        if str(source) in line and (executable == 'rld-regional-ledger-candidate'
                                    or (executable.lower().startswith('python')
                                        and 'regional_contact_node.py' in line)):
            raise ValueError('source fixture still running; copied-key concurrent run refused')
    source_observations = {str(p.relative_to(source)): digest(p)
                           for p in source.rglob('*') if p.is_file() and not p.is_symlink()}
    mesh.require(not any(p.is_symlink() for p in source.rglob('*')), 'source fixture symlink refused')
    shutil.copytree(source, root)
    root.chmod(0o700)

    class Campaign(Cycle):
        def cli(self, name, n, *values, success=True):
            if profile is not None:
                mesh.require(values and values[0] not in FORBIDDEN, 'joint fault controller attempted epoch authority')
            call = super().cli
            if profile is not None and success and values[0] in READ_ONLY:
                return bounded_read(lambda *args: call(name,n,*args,success=True),
                                    *values,on_retry=self.read_retry)
            return call(name, n, *values, success=success)

        def read_retry(self):
            self.native_read_lock_retries += 1

        def voter(self, name, n):
            config = self.configs[name,n]
            return profile.voter(config, name, n) if profile is not None else config

        def check_joint_custody(self, n):
            config = self.configs['earth',n]
            campaign = self
            class ReadNative(Native):
                def call(self, *args):
                    return bounded_read(super().call,*args,on_retry=campaign.read_retry)
            native = ReadNative(self.binary, self.node('earth',n), public(1), self.currency)
            return profile.custody(native, config, native.call('status'),
                native.call('bft-status','--signer-dir',config['signer_dir']),
                mesh.load(Path(config['head_file']),8*1024*1024), root, n)

        def __init__(self):
            self.binary, self.helper, self.root = args.binary.resolve(), args.binary.resolve().with_name('contact-fixture'), root
            self.calls = self.helper_calls = self.rejections = self.starts = 0
            self.native_read_lock_retries = 0
            self.heads, self.regions, self.certificates, self.checks = {}, {}, {}, []
            self.earth_forbidden = False
            self.offline_earth = None
            self.processes, self.logs, self.configs, self.observations = {}, [], {}, []
            self.ports, self.node_ids, self.fingerprints, self.relays = {}, {}, {}, []
            self.contact_meters = {}
            self.fault_relays = []
            self.currency, self.implementation = previous['currency'], previous['implementation']
            self.offered, self.events, self.samples, self.signed = [], [], [], {}
            self.original_ledgers, self.paused_keys = {}, []
            self.started = time.monotonic()
            self.receipt_probe = NativeReceiptProbe()
            # Rewrite only operator-configured private paths into the fresh copy.
            for p in root.glob('mesh-config-*.json'):
                config = mesh.load(p, 65536)
                config['state'] = str(root / Path(config['state']).name)
                self.file(p.stem, config)
            held = []
            try:
                for name in ('earth', 'proxima', 'andromeda'):
                    for n in range(4):
                        key = name, n
                        config = mesh.load(root/f'mesh-config-{name}-{n}.json', 65536)
                        mesh.require((Path(config['state'])/'tcp-tls.private.pem').is_file(), 'retained TLS material required')
                        pin = tcp.public_tls_identity(config)
                        self.node_ids[key], self.fingerprints[key] = pin['node_id'], pin['tls_cert_sha256']
                        endpoint = socket.socket(); endpoint.bind(('127.0.0.1', 0)); held.append(endpoint)
                        self.ports[key] = endpoint.getsockname()[1]
                        state = self.cli(name, n, 'status')
                        mesh.require(state['height'] == previous['replica_heights'][name][n], 'sealed native prefix differs')
                        self.regions[name] = state['region']
                        if n == 1: self.original_ledgers[name] = state['ledger']
                id_keys = {value: key for key, value in self.node_ids.items()}
                if getattr(args, 'meter_contacts', False):
                    for key in self.ports:
                        config = mesh.load(root/f'mesh-config-{key[0]}-{key[1]}.json', 65536)
                        for contact in config['contacts']:
                            other = id_keys[contact['peer']]
                            mesh.require(contact['tls_cert_sha256'] == self.fingerprints[other],
                                         'explicit meter target TLS pin differs')
                            mesh.require((key,other) not in self.contact_meters and len(self.contact_meters) < 32,
                                         'bounded unique explicit meter edge required')
                            cut = {key,other} == {('earth',1),('proxima',1)}
                            meter = MeteredRelay(('127.0.0.1',self.ports[other]),
                                f'{key[0]}_{key[1]}_to_{other[0]}_{other[1]}',enabled=not cut)
                            self.contact_meters[key,other] = meter
                            self.relays.append(meter)
                    forward = self.contact_meters[('earth',1),('proxima',1)]
                    reverse = self.contact_meters[('proxima',1),('earth',1)]
                else:
                    forward = FaultRelay(('127.0.0.1', self.ports['proxima', 1]))
                    self.relays.append(forward)
                    reverse = FaultRelay(('127.0.0.1', self.ports['earth', 1]))
                    self.relays.append(reverse)
                self.fault_relays = [forward, reverse]
                for name in ('earth', 'proxima', 'andromeda'):
                    for n, seed in enumerate(seeds(name)):
                        key = name, n
                        path = root/f'mesh-config-{name}-{n}.json'
                        config = mesh.load(path, 65536)
                        for contact in config['contacts']:
                            other = id_keys[contact['peer']]
                            mesh.require(contact['tls_cert_sha256'] == self.fingerprints[other], 'retained neighbor TLS pin differs')
                            contact['host'], contact['port'] = '127.0.0.1', self.ports[other]
                            if self.contact_meters:
                                contact['port'] = self.contact_meters[key,other].port
                            else:
                                if key == ('earth', 1) and other == ('proxima', 1): contact['port'] = forward.port
                                if key == ('proxima', 1) and other == ('earth', 1): contact['port'] = reverse.port
                        self.file(path.stem, config)
                        bft = mesh.load(root/f'bft-config-{name}-{n}.json', 65536)
                        for field in ('state', 'signer_dir', 'head_file', 'key_file'):
                            old = Path(bft[field]); bft[field] = str(root / old.relative_to(source))
                        if profile is not None:bft = profile.rebind(bft, source, root, name)
                        bft['stop_height'] = args.stop_height
                        mesh.require((profile is not None or bft['format'] == FORMAT)
                                     and bft['key'] == public(seed), 'BFT fixture binding differs')
                        head = mesh.load(Path(bft['head_file']), 8*1024*1024)
                        native = self.cli(name, n, 'bft-status', '--signer-dir', self.signer(name, n))
                        mesh.require(head['head'] == native['head'] and head['pending'] is None and head['outbox'] is None,
                                     'retained caller head differs; no first-sign recovery')
                        self.heads[key], self.configs[key] = head['head'], bft
                        self.file(f'bft-config-{name}-{n}', bft).chmod(0o600)
                        if profile is not None and name == 'earth':self.check_joint_custody(n)
                self.offline_gate = 9 if profile is None else profile.gate(
                    Native(self.binary,self.node('earth',0),public(1),self.currency),self.configs['earth',0])
                mesh.require(self.offline_gate <= args.stop_height, 'fault cap precedes actual missing-leader gate')
                self.inspection_anchors_sha256 = retain_fault_inspection_anchors(
                    root, source_inspection_anchors, self.currency, self.node_ids)
            finally:
                for endpoint in held: endpoint.close()

        def wallet_offer(self, name, owner, recipient, amount, destination=None):
            offered={'region':name,'kind':'export' if destination else 'local_payment','amount':str(amount),
                     'owner_approval_released':False,'native_queue_accepted':None,'queue_outcome':'not_called'}
            self.offered.append(offered)
            wallet = root/f'sustained-wallet-{name}-{owner}'
            mesh.require(not wallet.exists(), 'fresh actual-owner journal required')
            initialized = self.cli(name, 1, 'wallet-init', '--wallet-dir', wallet, '--owner', public(owner))
            request = {'owner': public(owner), 'inputs': None,
                       'outputs': [] if destination else [{'owner': public(recipient), 'amount': str(amount)}],
                       'fee': '1', 'valid_for_blocks': 8, 'remote': None}
            if destination:
                request['remote'] = {'destination': self.regions[destination],
                                     'recipient': {'owner': public(recipient), 'amount': str(amount)}, 'destination_fee': '1'}
            prepared = self.cli(name, 1, 'wallet-prepare', '--wallet-dir', wallet,
                                '--expected-wallet-head', initialized['wallet_head'], '--file', self.file(f'sustained-request-{name}', request))
            key = self.file(f'sustained-owner-key-{name}', {'secret_key': (bytes([owner])*32).hex()}); key.chmod(0o600)
            signed = self.cli(name, 1, 'wallet-sign', '--wallet-dir', wallet,
                             '--expected-wallet-head', prepared['wallet_head'], '--file', self.file(f'sustained-review-{name}', prepared),
                             '--review', prepared['review_commitment'], '--key-file', key)
            # Retain the exact released head separately before a submission can
            # lose its response. Never derive fresh consent from a rolled-back journal.
            self.file(f'sustained-wallet-caller-head-{name}', {'head': signed['wallet_head']}).chmod(0o600)
            offered['owner_approval_released']=True
            before = self.cli(name, 1, 'status')['ledger']
            offered['queue_outcome']='unknown_until_response'
            result = self.cli(name, 1, 'bft-submit', '--file', self.file(f'sustained-submission-{name}', signed['commands']))
            mesh.require(result['queued'] and not result['block_included'] and self.cli(name, 1, 'status')['ledger'] == before,
                         'queued owner request debited native ledger')
            offered.update(native_queue_accepted=True,queue_outcome='accepted',queue_did_not_debit=True)
            self.signed[name] = signed
            if destination:
                return {'currency': self.currency, 'source': self.regions[name], 'destination': self.regions[destination],
                        'export': prepared['draft']['intent_id'], 'recipient': public(recipient), 'net_amount': str(amount-1)}

        def heights(self, name, indices=range(4)):
            return [self.observation((name, n))['consensus']['height'] for n in indices]

        def audit(self, phase):
            # A lagging fixed replica can omit a debit already in another
            # certified prefix. Verify compatible prefixes, then count each
            # region's highest observed certified ledger exactly once.
            self.checks.append(dict(audit_certified_prefixes(self.cli, self.regions, self.currency), phase=phase))

        def sample(self, phase):
            values=[]
            for key in self.processes:
                observed = self.observation(key)
                values.append({'region': key[0], 'replica': key[1], **consensus_sample(observed),
                               **transport_sample(observed),
                               'sampled_errors': observed['errors']})
            self.samples.append({'phase': phase, 'elapsed_seconds': round(time.monotonic()-self.started, 3), 'nodes': values})
            self.audit(phase)
            if self.contact_meters:
                counters = [meter.report() for meter in self.contact_meters.values()]
                mesh.require(all(row['metric_counters_available'] for row in counters),
                             'explicit contact metric counters unavailable')
                self.samples[-1]['explicit_contact_stream_counters'] = counters

        def run(self):
            if recovery:
                receipt_path=root/'sustained-receipt-expectation.json'
                expected=mesh.load(receipt_path,65536)
                mesh.require(set(expected)=={'currency','source','destination','export','recipient','net_amount'}
                             and expected['currency']==self.currency and expected['source']==self.regions['earth']
                             and expected['destination']==self.regions['proxima'] and expected['net_amount']=='9',
                             'exact retained fixture payment expectation required')
                receipt=self.cli('proxima',1,'wallet-receipt','--file',receipt_path)
                mesh.require(receipt['expected']==expected and not receipt['live_rld']
                             and expected['export'] in self.cli('earth',1,'status')['ledger']['exports'],
                             'retained source debit/recipient binding differs')
                self.events.append({'kind':'retained_payment_recovery_stage','fresh_fault_profile_passed':False,
                                    'new_owner_requests':0,'receipt_expectation_unchanged':True})
                for relay in self.relays:relay.enable()
                for name in ('earth','proxima','andromeda'):
                    for key in self.region_keys(name):self.start(key)
                def mature_retained():
                    return self.receipt_probe.attempt(
                        lambda:self.cli('proxima',1,'wallet-receipt','--file',receipt_path),
                        lambda result:result['expected']==expected and result['original_output_spendable_now']
                            and result['local_finality_covers_import'] and not result['quarantined'])
                receipt=self.wait(mature_retained,'retained signed payment reaches native maturity without replacement',args.phase_timeout)
                self.sample('retained-payment recovery maturity; not a fresh fault profile')
                mesh.require(not self.offered,'recovery stage must not sign or queue new owner requests')
                return self.finish(expected,receipt)
            expected = self.wallet_offer('earth', 13, 21, 10, 'proxima')
            self.wallet_offer('proxima', 20, 15, 1)
            self.wallet_offer('andromeda', 20, 16, 1)
            self.events.append({'kind':'faults_applied','offline_validator':{'region':'earth','replica':0},
                                'interregion_contacts':'earth/proxima both directions cut','local_stop_height':args.stop_height})
            retained_paths = ([self.node('earth',0)/'journal.json', self.signer('earth',0)/'bft.json', root/'caller-head-earth-0/head.json']
                              if profile is None else profile.offline_paths(self.configs['earth',0],root))
            retained = {p:digest(p) for p in retained_paths}
            for name in ('earth', 'proxima', 'andromeda'):
                for key in self.region_keys(name):
                    if key != ('earth', 0): self.start(key)
            self.wait(lambda:min(self.heights('earth', (1, 2, 3))) >= self.offline_gate,
                      f'three voters progress past offline parent-{self.offline_gate-1} leader', args.phase_timeout)
            mesh.require(all(digest(p) == before for p, before in retained.items()), 'offline replica/signer/caller head changed')
            proof = self.cli('earth', 1, 'proof')
            mesh.require(any(s['statement']['region'] == self.regions['earth'] and s['statement']['height'] == self.offline_gate
                             and s['bft']['prepared']['round'] > 0 for s in proof['snapshots']), 'offline leader lacked certified view change')
            exported = self.cli('earth', 1, 'status')['ledger']['exports'].get(expected['export'])
            mesh.require(exported is not None, 'actual queued export was not certified')
            self.wait(lambda:min(self.heights('proxima')) >= 6 and min(self.heights('andromeda')) >= 6,
                      'both isolated remote regions continue local certified progress', args.phase_timeout)
            for name, recipient in [('proxima', 15), ('andromeda', 16)]:
                ledger = self.cli(name, 1, 'status')['ledger']
                mesh.require(sum(int(c['payment']['amount']) for c in ledger['coins'].values() if c['payment']['owner'] == public(recipient)) == 1,
                             'isolated remote local payment missing')
            mesh.require(expected['export'] not in self.cli('proxima', 1, 'status')['ledger']['imports'], 'disconnected contact fabricated import')
            mesh.require(all(relay.report()['refused_connections'] > 0 for relay in self.fault_relays), 'contact outage did not refuse actual attempts')
            self.sample('certified export stays deducted while interregion contact is cut; remote local payments continue')
            self.events.append({'kind': 'validator_offline', 'region': 'earth', 'replica': 0,
                                'starting_height': previous['replica_heights']['earth'][0], 'missing_leader_successor': self.offline_gate,
                                'minimum_online_height': min(self.checks[-1]['replica_heights']['earth'][1:]),
                                'native_signer_and_external_head_unchanged': True, 'certified_view_change_seen': True})
            self.start(('earth', 0))
            self.wait(lambda:self.observation(('earth', 0))['consensus']['height'] >= self.offline_gate,
                      'offline validator catches up through pinned TLS', args.phase_timeout)
            for relay in self.relays: relay.enable()
            self.events.append({'kind': 'interregion_contacts_restored', 'elapsed_seconds': round(time.monotonic()-self.started, 3)})
            receipt_path = self.file('sustained-receipt-expectation', expected)
            def mature():
                return self.receipt_probe.attempt(
                    lambda:self.cli('proxima', 1, 'wallet-receipt', '--file', receipt_path),
                    lambda receipt:receipt['expected']==expected and receipt['original_output_spendable_now']
                        and receipt['local_finality_covers_import'] and not receipt['quarantined'])
            receipt = self.wait(mature, 'retained new export imports uniquely and matures after contact restoration', args.phase_timeout)
            self.sample('after restored contact and independent native recipient maturity')
            return self.finish(expected,receipt)

        def finish(self, expected, receipt):
            # Preserve keys while entering the existing keyless read-only mode.
            # Drain all already signed complete certificates before the final
            # snapshot. This is local fixture quiescence, not key revocation.
            for name,n in self.configs:
                config = self.voter(name,n)
                if config is None:
                    self.check_joint_custody(n)
                    continue
                key = Path(config['key_file']); retained_key = key.with_name(key.name+'.retained-pause')
                mesh.require(key.is_file() and not retained_key.exists(), 'fixture signing key pause collision')
                before = digest(key); os.rename(key, retained_key); mesh.sync_retained(retained_key)
                self.paused_keys.append((key, retained_key, before))
            def settled():
                for name in ('earth', 'proxima', 'andromeda'):
                    heights = self.heights(name)
                    if len(set(heights)) != 1: return False
                    current = heights[0]
                    context=self.cli(name,0,'bft-context')['context']
                    if context['parent_height']!=current:return False
                    messages=[]
                    for n in range(4):
                        if profile is not None and name == 'earth':self.check_joint_custody(n)
                        config = self.voter(name,n)
                        if config is None:continue
                        head = mesh.load(Path(config['head_file']), 8*1024*1024)
                        if head['pending'] is not None or head['outbox'] is not None: return False
                        signer = self.cli(name,n,'bft-status','--signer-dir',config['signer_dir'])
                        if signer['head']!=head['head']:return False
                        messages.extend(self.cli(name,n,'bft-retained-messages','--signer-dir',config['signer_dir']))
                    if has_complete_commit_group(messages,context):return False
                return True
            self.wait(settled, 'keyless fixture pause drains complete native certificates', args.phase_timeout)
            for key in list(self.processes): self.stop(key)
            for name in ('earth', 'proxima', 'andromeda'):
                self.same_replicas(name, range(4))
            final = {name: self.cli(name, 1, 'status') for name in ('earth', 'proxima', 'andromeda')}
            mesh.require(expected['export'] in final['earth']['ledger']['exports']
                         and expected['export'] in final['proxima']['ledger']['imports'], 'export debit/import tombstone disappeared')
            for name, old in self.original_ledgers.items():
                for field in ('exports', 'imports'):
                    mesh.require(all(final[name]['ledger'][field].get(k) == v for k,v in old[field].items()),
                                 'historical export debit/import tombstone changed')
            self.audit('stopped native stores replay; new import exists once and debit remains')
            archives = []
            for name in ('earth', 'proxima', 'andromeda'):
                for n in range(4):
                    with mesh.Node(mesh.load(root/f'mesh-config-{name}-{n}.json', 65536)) as node:
                        for ident in node.state['archives']: node.archived(ident)
                        files, total = node.archive_inventory()
                        archives.append({'region': name, 'replica': n, 'archived_records': len(node.state['archives']),
                                         'retained_files': len(files), 'retained_bytes': total, 'full_cold_read_passed': True})
            return {'completed': True, 'recipient': receipt, 'final_heights': {n: s['height'] for n, s in final.items()},
                    'cold_archive_reads': archives}

    campaign = None
    failure = None
    result = {}
    cleanup_ok = False
    try:
        campaign = Campaign.__new__(Campaign)
        campaign.__init__()
        result = campaign.run()
    except Exception as error:
        failure = str(error).replace(str(root), '<private-fixture>').replace(str(source), '<sealed-fixture>')[:4096]
        if campaign is not None:
            try: campaign.sample('failed bounded observation; all evidence retained')
            except Exception: pass
    finally:
        if campaign is not None:
            try:
                campaign.cleanup()
                cleanup_ok = True
            except Exception as error: failure = failure or ('owned node cleanup failed: '+str(error))
            for key, retained, before in campaign.paused_keys:
                try:
                    mesh.require(retained.is_file() and digest(retained) == before and not key.exists(), 'retained fixture key changed')
                    os.rename(retained, key); mesh.sync_retained(key)
                except Exception as error:
                    failure = failure or str(error); cleanup_ok = False
            for relay in campaign.relays:
                try: relay.close()
                except Exception as error:
                    failure = failure or str(error); cleanup_ok = False
            if cleanup_ok and len(campaign.configs)==12:
                try:campaign.audit('stopped native stores: complete replay of all twelve compatible prefixes')
                except Exception as error:failure=failure or ('cold native audit failed: '+str(error))
    unchanged = all(p.is_file() and digest(p) == source_observations[str(p.relative_to(source))]
                    for p in source.rglob('*') if p.is_file()) and len(source_observations) == len([p for p in source.rglob('*') if p.is_file()])
    if not unchanged:failure=failure or 'sealed fixture source changed during its isolated-copy experiment'
    if digest(Path(__file__))!=drill_source_sha256:failure=failure or 'executed drill source changed during the run'
    report = {'format': 'RLD-JOINT-BFT-SUSTAINED-GROUND-CAMPAIGN-V1' if joint else 'RLD-REGIONAL-BFT-SUSTAINED-GROUND-CAMPAIGN-V3', 'fixture_only': True, 'live_rld': False,
              'completed': failure is None and result.get('completed', False), 'failure': failure,
              'mode':'retained_payment_recovery' if recovery else 'fresh_fault_profile',
              'fresh_fault_profile_completed':not recovery and failure is None and result.get('completed',False),
              'retained_payment_recovery_completed':recovery and failure is None and result.get('completed',False),
              'retained_failed_report_sha256':digest(args.resume_report) if recovery else None,
              'same_host_same_controller': True, 'private_fixture_copy_not_independent_custody': True,
              'sealed_source_state_unchanged': unchanged, 'runtime_source_set_sha256': manifest['source_set_sha256'],
              'drill_source_sha256': drill_source_sha256, 'native_implementation': previous['implementation'],
              'currency': previous['currency'],
              'mesh_inspection_anchors_sha256': getattr(campaign, 'inspection_anchors_sha256', None),
              'source_mesh_inspection_anchors_sha256': previous['mesh_inspection_anchors_sha256'],
              'maximum_local_stop_height': args.stop_height, 'phase_observation_bound_seconds': args.phase_timeout,
              'controller_generated_consensus_messages': 0, 'controller_carried_payment_proofs': 0,
              'controller_installed_checkpoints': 0, 'power_loss_qualified': False, 'sustained_BFT_liveness_qualified': False,
              'cross_host_qualified': False, 'independent_operators_qualified': False, 'physical_route_qualified': False,
              'result': result}
    if profile is not None:
        report.update(activated_epoch=previous['activated_epoch'],cycle_report_sha256=digest(args.cycle_report),
            cycle_cold_report_sha256=digest(args.cycle_cold_report),
            cycle_source_set_sha256=json.loads(args.cycle_source_manifest.read_text())['source_set_sha256'],
            controller_generated_epoch_approvals=0,controller_installed_epoch_activation=0,
            uses_current_new_voter_journals=True,keyless_carrier_not_initialized=True,
            overlapping_membership_qualified=False)
        report['controller_read_only_lock_retries'] = campaign.native_read_lock_retries if campaign else 0
    if campaign is not None:
        report.update(duration_seconds=round(time.monotonic()-campaign.started, 3), offered_owner_requests=campaign.offered,
                      fault_events=campaign.events, conservation_checks=campaign.checks, observations=campaign.observations,
                      phase_samples=campaign.samples, ciphertext_fault_relays=[relay.report() for relay in campaign.fault_relays],
                      native_cli_calls=campaign.calls, node_process_starts=campaign.starts,
                      controller_native_receipt_probe_interval_seconds=NativeReceiptProbe.interval_seconds,
                      controller_native_receipt_probe_attempts=campaign.receipt_probe.attempts,
                      owned_process_cleanup_verified=cleanup_ok)
        report.update(all_explicit_contact_streams_metered=bool(campaign.contact_meters),
                      explicit_contact_stream_meters=[meter.report() for meter in campaign.contact_meters.values()],
                      value_auditor_sha256=digest(Path(audit_certified_prefixes.__code__.co_filename)),
                      contact_meter_sha256=digest(Path(MeteredRelay.__init__.__code__.co_filename)),
                      continuous_value_or_resource_peaks_measured=False,
                      physical_wire_bytes_measured=False)
        if campaign.contact_meters and not all(meter.report()['metric_counters_available'] for meter in campaign.contact_meters.values()):
            failure = failure or 'explicit contact metric counters unavailable'
            report.update(completed=False,fresh_fault_profile_completed=False,
                          retained_payment_recovery_completed=False,failure=failure)
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    mesh.require(unchanged, 'sealed fixture source changed during its isolated-copy experiment')
    print(json.dumps({'completed': report['completed'], 'failure': failure, 'sealed_source_unchanged': unchanged}), flush=True)
    if failure is not None: raise ValueError(failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-tools', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--cycle-report', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True, help='Stopped private sealed fixture; never publish')
    parser.add_argument('--root', type=Path, required=True, help='Fresh private copy; never publish')
    parser.add_argument('--report', type=Path, required=True, help='Sanitized success or failure report')
    parser.add_argument('--stop-height', type=int, default=24)
    parser.add_argument('--phase-timeout', type=int, default=600)
    parser.add_argument('--resume-report',type=Path,help='Stopped failed drill; recovery stage never replaces the fresh full profile')
    parser.add_argument('--resume-source-manifest',type=Path,help='Exact manifest named by the stopped failed drill')
    parser.add_argument('--joint-cycle',action='store_true',help='Explicit stopped preconfigured joint cycle; never inferred')
    parser.add_argument('--cycle-cold-report',type=Path)
    parser.add_argument('--cycle-source-manifest',type=Path)
    parser.add_argument('--meter-contacts',action='store_true',
                        help='Explicit loopback ciphertext meter per configured directed hop; fresh scope only')
    args = parser.parse_args()
    if (args.resume_report is None)!=(args.resume_source_manifest is None):
        parser.error('retained-payment recovery requires both prior failed report and its exact source manifest')
    if not (12 <= args.stop_height <= 24 and 60 <= args.phase_timeout <= 600):
        parser.error('bounded ground profile requires height 12..24 and observation 60..600 seconds')
    execute(args, joint=args.joint_cycle)


if __name__ == '__main__': main()
