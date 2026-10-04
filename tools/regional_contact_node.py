#!/usr/bin/env python3
"""Contact companion launched by the native fixture node; Rust owns value checks.

Directory contacts are a bounded ground adapter. Discovered self-signed regions
are routing candidates only, never ledger, signer or monetary authority.
"""
import argparse
from bisect import bisect_right
import base64
from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire

FORMAT = 'RLD-REGIONAL-CONTACT-NODE-V1'
MAX_PER_TICK = 4
MAX_NATIVE_OUTPUT = 8 * 1024 * 1024


class Native:
    def __init__(self, binary, ledger, authority, currency):
        self.binary = Path(binary)
        mesh.require(self.binary.is_absolute() and self.binary.is_file() and not self.binary.is_symlink(), 'native binary must be an absolute regular file')
        self.ledger = Path(ledger)
        self.authority = mesh.hex32(authority)
        self.currency = mesh.hex32(currency)
        mesh.require(self.ledger.is_absolute(), 'ledger directory must be absolute')

    def call(self, *args, private_input=None):
        mesh.require(private_input is None or isinstance(private_input,(bytes,bytearray)) and len(private_input)<=1024,
            'private native input outside bound')
        # Native outputs are bounded by the candidate's journal/frame limits.
        # File-backed capture also bounds memory if a broken executable floods.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run([str(self.binary), '--dir', str(self.ledger),
                '--authority', self.authority, '--currency', self.currency, *map(str, args)],
                input=private_input, stdout=output, stderr=errors, timeout=30, check=False)
            mesh.require(output.tell() <= MAX_NATIVE_OUTPUT and errors.tell() <= 64 * 1024, 'native response outside bound')
            errors.seek(0)
            mesh.require(result.returncode == 0, 'native rejected: ' + errors.read(2048).decode('utf-8', errors='replace').strip())
            output.seek(0)
            return wire.decode_json(output.read(MAX_NATIVE_OUTPUT + 1))

    def apply(self, raw, miner):
        # The mesh retains the complete frame throughout. A temporary native
        # input is disposable; native proof/pending records persist separately.
        with tempfile.NamedTemporaryFile(prefix='rld-regional-contact-', suffix='.json') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            args = ['contact-apply', '--file', handle.name]
            if miner is not None:
                args.extend(['--miner', miner])
            return self.call(*args)


def startup_config(native, path=None):
    """Restore one persistent relay identity, after native authority validation.

    An empty contact set means waiting for a real contact, never an invented
    reachable peer. Default initialization is serialized across startup races.
    """
    observation = native.call('contact-status')
    mesh.require(observation['currency'] == native.currency, 'startup currency mismatch')
    if path is not None:
        return mesh.load(path, 64 * 1024)
    root = mesh.safe_dir(native.ledger / 'transport')
    descriptor = os.open(root / '.startup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        path = root / 'config.json'
        if path.exists() or path.is_symlink():
            return mesh.load(path, 64 * 1024)
        identity = root / 'identity.private.json'
        if not identity.exists() and not identity.is_symlink():
            mesh.initialize(root, native.currency, observation['region'], 'regional-node')
        config = {'format': mesh.VERSION, 'state': str(root),
            'network': native.currency, 'contacts': []}
        # Validate recovered identity before exposing configuration, including
        # the crash window after identity creation but before config commit.
        with mesh.Node(config) as node:
            mesh.require(node.state['adverts'][node.id]['body']['region'] == observation['region'],
                'default relay identity differs from native ledger')
        mesh.atomic(path, config)
        return config
    finally:
        os.close(descriptor)


class Service:
    def __init__(self, native, config, miner, listen=('127.0.0.1',0), insecure_tcp=False, bft_config=None, parallel_carriage=True, contact_trace=None):
        self.native, self.config, self.miner = native, config, miner
        self.contact_trace=contact_trace
        self.lock = None
        self.tcp = None
        self.bft = None
        self.carriage = None
        mesh.require(type(parallel_carriage) is bool,'invalid parallel carriage selection')
        self.bft_seen = set()
        self.bft_individual_retry = False
        # Scheduling only, two primitive packet IDs; never custody or replay.
        self.receive_after = {'novel': None, 'background': None}
        self.root = mesh.safe_dir(config['state'])
        try:
            self.lock = os.open(self.root / '.regional-contact-service.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observation = native.call('contact-status')
            self.region = observation['region']
            mesh.require(observation['currency'] == native.currency and config['network'] == native.currency,
                'native/transport currency network binding mismatch')
            self.path = self.root / 'regional-contact-progress.json'
            if self.path.exists():
                self.progress = mesh.load(self.path, 8192)
                mesh.require(set(self.progress) == {'format', 'currency', 'region', 'cursor'}
                    and self.progress['format'] == FORMAT and self.progress['currency'] == native.currency
                    and self.progress['region'] == self.region, 'contact progress identity mismatch')
                mesh.integer(self.progress['cursor'], 0, 2**63-1)
            else:
                self.progress = {'format': FORMAT, 'currency': native.currency, 'region': self.region, 'cursor': 0}
            with mesh.Node(config) as node:
                mesh.require(node.state['adverts'][node.id]['body']['region'] == self.region,
                    'local mesh label differs from native ledger identity')
            mesh.atomic(self.path, self.progress)
            self.tcp = (tcp.Server(config,listen,insecure=insecure_tcp,contact_trace=contact_trace) if contact_trace is not None
                        else tcp.Server(config,listen,insecure=insecure_tcp))
            if bft_config is not None:
                mesh.require(miner is None, 'BFT validator cannot use uncertified import mining')
                from regional_bft_node import Runtime
                self.bft = Runtime(native,config,bft_config)
                if contact_trace is not None:self.bft.contact_trace=contact_trace
                self.bft.carriage_node = self.tcp.ordinary_mesh_node
                if parallel_carriage:
                    from regional_carriage_worker import Worker
                    self.carriage = Worker(self.tcp)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.carriage is not None:
            self.carriage.close()
            self.carriage = None
        if self.bft is not None:
            self.bft.close()
            self.bft = None
        if self.tcp is not None:
            self.tcp.close()
            self.tcp = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    @contextmanager
    def selection_node(self):
        self.tcp.request_selection()
        deadline=time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS
        node=None
        try:
            with self.tcp.selection_mesh_node(deadline) as selected:
                node=selected
                yield node
        except OSError as error:
            if node is None and error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):self.tcp.finish_selection()
            raise
        except BaseException:
            if node is None:self.tcp.finish_selection()
            raise
        finally:
            if node is not None:self.tcp.finish_selection()

    def receive_candidates(self, summaries, receipts, destination):
        eligible = sorted(i for i, t in summaries.items()
            if t['destination'] == destination and i in receipts
            and i not in self.bft_seen)
        if not eligible:
            return []
        if self.bft is not None:
            # Cold startup authenticated the retained complete envelopes. Their
            # exact byte identities classify scheduling only: every selected
            # packet/receipt and every received envelope is still verified.
            # A changed proof on the same signed body remains a new envelope.
            retained = {self.bft.state['messages'].content(i)
                        for i in self.bft.state['messages']}
            novel = [i for i in eligible if summaries[i]['kind'] == 'regional-bft'
                     and summaries[i]['export_id'] not in retained]
            novel_set = set(novel)
            background = [i for i in eligible if i not in novel_set]
            def take(items, count, kind):
                if not items or not count:return []
                # Removing a received item or inserting a new one must not
                # shift a numeric rank past the next waiting packet. Continue
                # after the exact last selected ID, wrapping the sorted ring.
                after=self.receive_after[kind]
                start=0 if after is None else bisect_right(items,after)%len(items)
                selected=(items[start:]+items[:start])[:count]
                self.receive_after[kind]=selected[-1]
                return selected
            # Each nonempty class retains half the original four slots. A
            # changed proof remains novel; every selected complete envelope
            # still takes normal authentication before native deduplication.
            count=min(len(novel),max(MAX_PER_TICK//2,MAX_PER_TICK-len(background)))
            return take(novel,count,'novel')+take(background,MAX_PER_TICK-count,'background')
        offset = self.progress['cursor'] % len(eligible)
        return (eligible[offset:] + eligible[:offset])[:MAX_PER_TICK]

    def tick(self):
        tick_started = time.monotonic()
        stage_started = tick_started
        stage_seconds = {}
        # Release the mesh lock before native replay/mining. Enqueue and receipt
        # tools can safely operate between bounded contact iterations.
        # BFT consumes already durably received evidence and publishes its
        # native response before the one ordinary outgoing contact batch.
        # Newly signed votes can then travel this tick. Inbound custody remains
        # asynchronous in the server; replies are consumed on the next tick.
        socket_observation = (self.carriage.snapshot() if self.carriage is not None else
                              self.tcp.tick() if self.bft is None else None)
        stage_seconds['tcp'] = round(time.monotonic()-stage_started, 6)
        stage_started = time.monotonic()
        received, routes, adverts = [], {}, {}
        errors = list(socket_observation['errors']) if socket_observation is not None else []
        rejected = []
        selected=[]
        transport={'progress_observation_available':False,'diagnostic':'mesh selection unavailable'}
        try:
          with self.selection_node() as node:
            transport = node.tick()
            errors.extend(transport['errors'])
            summaries=node.summaries();receipts=node.receipts()
            selected = self.receive_candidates(summaries, receipts, node.id)
            if selected:
                for ident in selected:
                    try:
                        transit=node.transit(ident)
                        packet, raw, _ = mesh.transit_check(transit, node.network)
                        mesh.receipt_matches(receipts[ident], transit)
                        received.append((ident, raw))
                    except (OSError, ValueError) as error:
                        errors.append(str(error))
                        rejected.append({'packet_id': ident, 'reason': str(error)})
            adverts = {i: a['body']['region'] for i, a in node.state['adverts'].items()}
            routes = {i: node.route(i) for i in adverts if i != node.id}
        except OSError as error:
            if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):raise
            errors.append(str(error))
            transport['diagnostic']='mesh selection lock contention; retained evidence remains pending'
        stage_seconds['mesh_selection'] = round(time.monotonic()-stage_started, 6)
        stage_started = time.monotonic()
        native_observation = None
        applied = []
        try:
            native_observation = self.native.call('contact-status')
            mesh.require(native_observation['currency'] == self.native.currency and native_observation['region'] == self.region,
                'fresh native identity differs from startup binding')
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            errors.append(str(error))
        if native_observation is not None:
            accepted = {c['message_id'] for c in native_observation['contacts']
                if c['import_accepted'] or (self.miner is None and c['evidence_verified'])}
            individual_retry=self.bft_individual_retry
            self.bft_individual_retry=False
            pending_bft=[]
            def flush_bft():
                if not pending_bft:return
                try:
                    self.bft.receive_many([raw for _,raw in pending_bft])
                    self.bft_seen.update(packet_id for packet_id,_ in pending_bft)
                    if self.contact_trace is not None:
                        for packet_id,raw in pending_bft:self.contact_trace.native_received(packet_id,raw)
                except (OSError,ValueError,subprocess.TimeoutExpired) as error:
                    if len(pending_bft)>1:self.bft_individual_retry=True
                    errors.append(str(error))
                    rejected.extend({'packet_id':packet_id,'reason':str(error)} for packet_id,_ in pending_bft)
                finally:pending_bft.clear()
            for packet_id, raw in received:
                try:
                    frame, _ = wire.inspect_frame(raw)
                    if frame['kind']=='regional-bft':
                        if self.bft is not None:
                            pending_bft.append((packet_id,raw))
                            if individual_retry or len(pending_bft)==4:flush_bft()
                        continue
                    flush_bft()
                    if frame['message_id'] not in accepted:
                        result = self.native.apply(raw, self.miner)
                        applied.append({'packet_id': packet_id, 'native': result})
                except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                    flush_bft()
                    errors.append(str(error))
                    rejected.append({'packet_id': packet_id, 'reason': str(error)})
            flush_bft()
            # Export authority is obtained from the actual native ledger. A
            # region advertised by a mesh key selects only a candidate carrier.
            try:
                outgoing = self.native.call('contact-outgoing')
                offers = outgoing['offers']
                if offers:
                    offset = self.progress['cursor'] % len(offers)
                    offers = (offers[offset:] + offers[:offset])[:MAX_PER_TICK]
                for offer in offers:
                    candidates = sorted(i for i, region in adverts.items() if region == offer['destination'] and routes.get(i))
                    if not candidates:
                        continue
                    value = self.native.call('contact-export', '--export', offer['export'])
                    raw = wire.canonical(value)
                    frame, _ = wire.inspect_frame(raw)
                    mesh.require(frame['source_chain_id'] == self.region and frame['destination_chain_id'] == offer['destination'], 'outgoing native route changed')
                    with self.tcp.ordinary_mesh_node() as node:
                        # Inspect retained packets to reconcile enqueue-after-
                        # crash, without a fragile external "already sent" flag.
                        retained = set()
                        for summary in node.summaries().values():
                            if summary['source'] == node.id:
                                retained.add((summary['frame_id'],summary['destination']))
                        # Rotate among reachable candidates; a dishonest label
                        # can delay delivery but cannot change the ledger target.
                        # The receive/offer cursor advances by MAX_PER_TICK.
                        # Using it directly can pin a four-node destination to
                        # one candidate forever. Rotate by complete tick count.
                        destination = candidates[(self.progress['cursor'] // MAX_PER_TICK) % len(candidates)]
                        if (frame['message_id'], destination) not in retained:
                            node.enqueue(raw, destination)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
            try:
                native_observation = self.native.call('contact-status')
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                native_observation = None
                errors.append(str(error))
        consensus = None
        stage_seconds['native_receive_and_outgoing'] = round(time.monotonic()-stage_started, 6)
        stage_started = time.monotonic()
        if self.bft is not None:
            try:
                consensus=self.bft.tick()
            except (OSError,ValueError,subprocess.TimeoutExpired) as error:
                errors.append(str(error))
                consensus={'autonomous_signing_enabled':not self.bft.failed,'progress_observation_available':False,
                           'diagnostic':str(error)[:256],'independent_bft_qualified':False}
        stage_seconds['consensus'] = round(time.monotonic()-stage_started, 6)
        if socket_observation is None:
            stage_started = time.monotonic()
            socket_observation = self.tcp.tick()
            stage_seconds['tcp'] = round(time.monotonic()-stage_started, 6)
            errors.extend(socket_observation['errors'])
        elif self.carriage is not None:
            socket_observation=self.carriage.snapshot()
            # Parallel CPU/socket duration is not a serial contact-tick stage.
            stage_seconds['tcp']=None
        transport['tcp'] = socket_observation
        stage_seconds['before_status_publication'] = round(time.monotonic()-tick_started, 6)
        self.progress['cursor'] = (self.progress['cursor'] + MAX_PER_TICK) % (2**63)
        mesh.atomic(self.path, self.progress)
        report = {'format': FORMAT, 'process_id': os.getpid(), 'currency': self.native.currency, 'region': self.region,
            'relay_enabled': True, 'local_import_mining_enabled': self.miner is not None,
            'observed_at_unix': int(time.time()), 'transport': transport,
            'native_observation': native_observation, 'native_observation_available': native_observation is not None,
            'applied': applied, 'rejected': rejected, 'errors': errors[:16], 'fixture_only': True,
            'consensus': consensus,
            'physical_route_verified': False, 'independent_operators': False,
            'transport_receipt_is_payment_authority': False, 'remote_current_state_known': False}
        observation = getattr(self.bft, 'observation', None)
        if observation is not None:
            observation.event('contact-tick', tick_started, selected=len(selected), received=len(received),
                              errors=len(errors), tcp_seconds=stage_seconds['tcp'],
                              mesh_seconds=stage_seconds['mesh_selection'],
                              native_seconds=stage_seconds['native_receive_and_outgoing'],
                              consensus_seconds=stage_seconds['consensus'])
            report['bft_observation'] = observation.snapshot()
        if self.contact_trace is not None:report['contact_trace']=self.contact_trace.snapshot()
        mesh.atomic(self.root / 'regional-contact-status.json', report)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--authority', required=True)
    parser.add_argument('--currency', required=True)
    parser.add_argument('--mesh-config', type=Path)
    parser.add_argument('--bft-config', type=Path)
    parser.add_argument('--listen',default='127.0.0.1:0')
    parser.add_argument('--insecure-tcp',action='store_true')
    parser.add_argument('--miner')
    parser.add_argument('--interval', type=float, default=1)
    args = parser.parse_args()
    mesh.require(0.1 <= args.interval <= 3600, 'contact interval outside bound')
    native = Native(args.binary, args.ledger, args.authority, args.currency)
    config = startup_config(native, args.mesh_config)
    parts=args.listen.split(':')
    mesh.require(len(parts)==2 and parts[1].isdigit(), 'TCP listener must be literal IPv4:port')
    listen=mesh.tcp_endpoint(parts[0],int(parts[1]),listening=True)
    trace_mode=os.environ.get('RLD_GROUND_CONTACT_TRACE','0')
    mesh.require(trace_mode in ('0','1'),'explicit ground contact trace mode required')
    trace=None
    if trace_mode=='1':
        from regional_contact_trace import ContactTrace
        trace=ContactTrace()
    service = Service(native, config, args.miner,listen,args.insecure_tcp,args.bft_config,contact_trace=trace)
    running = True
    def stop(*_):
        nonlocal running
        running = False
        service.tcp.running = False
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    previous = None
    try:
        while running:
            try:
                result = service.tick()
            except tcp.MeshRuntimeStopping:
                # Only a received stop signal permits graceful local refusal.
                # Other validation/custody errors keep their normal failure.
                if running:
                    raise
                break
            # Only material changes print; the on-disk observation is refreshed.
            comparable = {k: v for k, v in result.items() if k not in ('observed_at_unix', 'bft_observation','contact_trace')}
            comparable['transport'] = {k: v for k, v in result['transport'].items() if k != 'observed_at_unix'}
            if comparable != previous:
                print(json.dumps({k:v for k,v in result.items() if k not in ('bft_observation','contact_trace')}), flush=True)
                previous = comparable
            deadline = time.monotonic() + args.interval
            while running and time.monotonic() < deadline:
                time.sleep(min(0.1, args.interval))
    finally:
        service.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit('regional contact node rejected: ' + str(error))
