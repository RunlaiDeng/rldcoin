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
from regional_native_startup import Inspection

FORMAT = 'RLD-REGIONAL-CONTACT-NODE-V2'
MAX_PER_TICK = 4
MAX_NATIVE_OUTPUT = 8 * 1024 * 1024


class NativeRefusal(ValueError):
    """Complete bounded subprocess refusal; display text grants no authority."""
    def __init__(self, command, exit_code, diagnostic):
        self.command = command
        self.exit_code = exit_code
        self.diagnostic = diagnostic
        super().__init__('native rejected: ' + diagnostic[:2048].strip())


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
                input=private_input, stdout=output, stderr=errors, timeout=30, check=False,
                cwd=Path(__file__).resolve().parents[1])
            mesh.require(output.tell() <= MAX_NATIVE_OUTPUT and errors.tell() <= 64 * 1024, 'native response outside bound')
            errors.seek(0)
            if result.returncode != 0:
                raise NativeRefusal(str(args[0]) if args else '', result.returncode,
                                    errors.read(64 * 1024).decode('utf-8', errors='replace'))
            output.seek(0)
            return wire.decode_json(output.read(MAX_NATIVE_OUTPUT + 1))

    def apply(self, raw, miner):
        # The mesh retains the complete frame throughout. A temporary native
        # input is disposable; native proof/pending records persist separately.
        with tempfile.NamedTemporaryFile(prefix='rld-regional-contact-', suffix='.json') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            frame,_=wire.inspect_frame(raw)
            if frame['kind']=='source-finality':
                mesh.require(miner is None,'origin contact requires ordinary certified BFT Import')
                head=self.call('history-head')
                mesh.require(type(head) is dict and head.get('currency')==self.currency
                    and head.get('region')==frame['destination_chain_id'],
                    'origin contact current Native head domain differs')
                mesh.hex32(head['history_head'])
                result=self.call('contact-origin-apply','--file',handle.name,'--expected-head',head['history_head'])
                mesh.require(type(result) is dict and set(result)=={'format','currency','region','message_id',
                    'source_checkpoint','history_head','verified','ledger_changed','import_accepted','signing_authority','fixture_only'}
                    and result['format']=='RLD-NATIVE-ORIGIN-CONTACT-ACCEPT-V2'
                    and result['currency']==self.currency and result['region']==frame['destination_chain_id']
                    and result['message_id']==frame['message_id'] and result['verified'] is True
                    and result['ledger_changed'] is False and result['import_accepted'] is False
                    and result['signing_authority'] is False and result['fixture_only'] is True,
                    'origin contact Native acceptance binding differs')
                mesh.hex32(result['source_checkpoint']);mesh.hex32(result['history_head'])
                return result
            args = ['contact-apply', '--file', handle.name]
            if miner is not None:
                args.extend(['--miner', miner])
            return self.call(*args)


def startup_config(native, path=None):
    """Restore one persistent relay identity, after native authority validation.

    An empty contact set means waiting for a real contact, never an invented
    reachable peer. Default initialization is serialized across startup races.
    """
    observation = Inspection(native).call('contact-status')
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
        self.trace_publisher=None
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
            observation = Inspection(native).call('contact-status')
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
            if contact_trace is not None:
                from regional_contact_trace import TracePublisher
                self.trace_publisher=TracePublisher(contact_trace,self.root/'regional-contact-trace-status.json')
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
        try:
            if self.trace_publisher is not None:
                publisher=self.trace_publisher;self.trace_publisher=None
                publisher.close()
        finally:
            if self.lock is not None:
                os.close(self.lock)
                self.lock = None

    def receive_bft_batch(self, rows, errors, rejected, deferred):
        """A local lock cannot establish envelope invalidity or acceptance."""
        mesh.require(type(rows) is list and 0 < len(rows) <= MAX_PER_TICK,
                     'BFT receive batch count outside bound')
        try:
            if self.contact_trace is not None:
                for packet_id, raw in rows:
                    self.contact_trace.native_stage('native_receive_attempt', packet_id, raw)
            self.bft.receive_many([raw for _, raw in rows])
            self.bft_seen.update(packet_id for packet_id, _ in rows)
            if self.contact_trace is not None:
                for packet_id, raw in rows:
                    self.contact_trace.native_received(packet_id, raw)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            if self.contact_trace is not None:
                for packet_id, raw in rows:
                    self.contact_trace.native_stage('native_receive_refused', packet_id, raw,
                                                    error_class=type(error).__name__)
            if len(rows) > 1:
                self.bft_individual_retry = True
            errors.append(str(error))
            # Authenticate all complete bytes again on retry. No bft_seen hint
            # or negative proof decision may be released from this refusal.
            if (isinstance(error, NativeRefusal)
                    and error.command in ('bft-network-inspect-batch',
                                          'bft-origin-network-receive-batch',
                                          'bft-network-check', 'bft-sync', 'bft-context','bft-origin-network-sync',
                                          'bft-origin-network-observe-conflicts','history-head')
                    and type(error.exit_code) is int and error.exit_code == 1
                    and error.diagnostic.strip() in (
                        'regional candidate rejected: lock acquisition failed because the operation would block',
                        'regional candidate rejected: complete stream already locked',
                    )):
                deferred.extend(dict(packet_id=packet_id,
                                     stage='native-validation-pending',
                                     command=error.command, exit_code=error.exit_code,
                                     diagnostic=error.diagnostic.strip(),
                                     ledger_acceptance_known=False,
                                     signing_authority=False)
                                for packet_id, _ in rows)
            else:
                rejected.extend(dict(packet_id=packet_id, reason=str(error))
                                for packet_id, _ in rows)

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

    def receive_candidates(self, summaries, receipts, destination, quota=None):
        eligible = sorted(i for i, t in summaries.items()
            if t['destination'] == destination and i in receipts
            and i not in self.bft_seen
            and (quota is None or i not in quota['attempted'])
            and not (t['kind']=='source-finality' and t.get('frame_id') in
                     getattr(self,'_native_origin_messages',frozenset())))
        remaining=MAX_PER_TICK if quota is None else MAX_PER_TICK-len(quota['attempted'])
        if not eligible or remaining <= 0:
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
            if quota is None:
                count=min(len(novel),max(MAX_PER_TICK//2,MAX_PER_TICK-len(background)))
                return take(novel,count,'novel')+take(background,MAX_PER_TICK-count,'background')
            # One operation owns the original four attempts, including failures.
            # Preserve each class's half before borrowing unused places. Late
            # traffic cannot undo borrowing or create another four-frame unit.
            n=min(len(novel),remaining,max(0,MAX_PER_TICK//2-quota['novel']))
            b=min(len(background),remaining-n,max(0,MAX_PER_TICK//2-quota['background']))
            n+=min(len(novel)-n,remaining-n-b)
            b+=min(len(background)-b,remaining-n-b)
            selected=take(novel,n,'novel')+take(background,b,'background')
            quota['novel']+=n;quota['background']+=b
        else:
            offset = self.progress['cursor'] % len(eligible)
            selected=(eligible[offset:] + eligible[:offset])[:remaining]
        if quota is not None:quota['attempted'].update(selected)
        return selected

    def contact_observation(self):
        # Operation-local projections from the original full inspection replay.
        # No cached ledger, shared lock, recovery bypass or transport authority.
        value=self.native.call('contact-observation')
        mesh.require(type(value) is dict and set(value)=={
            'format','currency','region','status','outgoing','ledger_changed','signing_authority'}
            and value['format']=='RLD-NATIVE-CONTACT-OBSERVATION-V1'
            and value['currency']==self.native.currency and value['region']==self.region
            and value['ledger_changed'] is False and value['signing_authority'] is False,
            'fresh native contact observation binding differs')
        status,outgoing=value['status'],value['outgoing']
        mesh.require(type(status) is dict and type(outgoing) is dict
            and status.get('currency')==outgoing.get('currency')==self.native.currency
            and status.get('region')==outgoing.get('region')==self.region
            and type(status.get('contacts')) is list and type(outgoing.get('offers')) is list
            and status.get('source_http_required') is False
            and outgoing.get('all_offers_require_native_contact_export_validation') is True,
            'native contact projections differ')
        return status,outgoing

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
        rejected, deferred = [], []
        local_os_errors=list(socket_observation.get('local_os_errors',())) if socket_observation is not None else []
        def observe_os_error(error, stage):
            origin=tcp._local_os_error_origin(error,stage)
            if origin is not None and len(local_os_errors)<16:local_os_errors.append(origin)
        # Refresh completion from a full Native open before selection. This
        # operation-local exact-frame observation never authenticates a changed
        # proof, creates Import/receipts, restores a ledger or suppresses BFT.
        self._native_origin_messages=frozenset()
        native_observation=None;outgoing=None
        try:
            native_observation,outgoing=self.contact_observation()
            origin_messages=native_observation.get('origin_evidence_message_ids',[])
            mesh.require(type(origin_messages) is list and len(origin_messages)<=4096
                and all(type(ident) is str for ident in origin_messages)
                and origin_messages==sorted(set(origin_messages)), 'native origin completion shape differs')
            for ident in origin_messages:mesh.hex32(ident)
            self._native_origin_messages=frozenset(origin_messages)
        except (OSError,ValueError,subprocess.TimeoutExpired) as error:
            native_observation=None;outgoing=None
            errors.append(str(error));observe_os_error(error,'native-contact-status')
        stage_seconds['native_contact_observation']=round(time.monotonic()-stage_started,6)
        stage_started=time.monotonic()
        spool_outgoing=any('outbox' in contact and 'host' not in contact
                           for contact in self.config['contacts'])
        quota={'attempted':set(),'novel':0,'background':0}
        selected=[]
        transport={'progress_observation_available':False,'diagnostic':'mesh selection unavailable'}
        try:
          with self.selection_node() as node:
            node.contact_trace = getattr(self, 'contact_trace', None)
            transport = node.tick(defer_spool_outgoing=True) if self.bft is not None or spool_outgoing else node.tick()
            errors.extend(transport['errors'])
            summaries=node.summaries();receipts=node.receipts()
            selected = self.receive_candidates(summaries, receipts, node.id, quota)
            if selected:
                for ident in selected:
                    try:
                        transit=node.transit(ident)
                        packet, raw, _ = mesh.transit_check(transit, node.network)
                        mesh.receipt_matches(receipts[ident], transit)
                        received.append((ident, raw))
                        if self.contact_trace is not None and summaries[ident]['kind'] == 'regional-bft':
                            self.contact_trace.native_stage('native_receive_selected', ident, raw)
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
        applied = []
        # Current Origin BFT checks its own complete inputs and exact Native
        # head independently. An unavailable optional contact projection must
        # not discard its already selected inputs without even that attempt.
        from regional_bft_node import ORIGIN_RUNTIME_FORMAT
        independent_bft=(self.bft is not None and getattr(self.bft,'format',None)==ORIGIN_RUNTIME_FORMAT
                         and getattr(self.bft,'joint',None) is None)
        def apply_received(items):
            nonlocal native_observation,outgoing
            if native_observation is not None or independent_bft:
                accepted = {c['message_id'] for c in (native_observation['contacts'] if native_observation is not None else [])
                    if c['import_accepted'] or (self.miner is None and c['evidence_verified'])}
                individual_retry=self.bft_individual_retry
                self.bft_individual_retry=False
                pending_bft=[]
                native_write_attempted=False
                def flush_bft():
                    nonlocal native_write_attempted
                    if not pending_bft:return
                    # A sync may have changed custody even if its result is lost.
                    native_write_attempted=True
                    try:
                        self.receive_bft_batch(pending_bft, errors, rejected, deferred)
                    finally:pending_bft.clear()
                for packet_id, raw in items:
                    try:
                        frame, _ = wire.inspect_frame(raw)
                        if frame['kind']=='regional-bft':
                            if self.bft is not None:
                                pending_bft.append((packet_id,raw))
                                if self.contact_trace is not None:
                                    self.contact_trace.native_stage('native_receive_queued',packet_id,raw)
                                if individual_retry or len(pending_bft)==4:flush_bft()
                            continue
                        flush_bft()
                        # Other contact application and outgoing selection keep
                        # their original fresh-projection prerequisite unchanged.
                        if native_observation is None:continue
                        if frame['message_id'] not in accepted:
                            native_write_attempted=True
                            result = self.native.apply(raw, self.miner)
                            applied.append({'packet_id': packet_id, 'native': result})
                    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                        flush_bft()
                        errors.append(str(error))
                        observe_os_error(error,'native-contact-apply')
                        # Only the exact complete typed contact-apply lock refusal
                        # leaves Native validity unknown. Retain the original frame
                        # for full verification on a later tick; no import/seen or
                        # signing credit is released by this local refusal.
                        if (isinstance(error, NativeRefusal)
                                and error.command in ('contact-apply','contact-origin-apply','history-head')
                                and type(error.exit_code) is int and error.exit_code == 1
                                and error.diagnostic.strip() in (
                                    'regional candidate rejected: lock acquisition failed because the operation would block',
                                    'regional candidate rejected: complete stream already locked',
                                )):
                            deferred.append(dict(packet_id=packet_id,
                                stage='native-validation-pending',command=error.command,
                                exit_code=error.exit_code,diagnostic=error.diagnostic.strip(),
                                ledger_acceptance_known=False,signing_authority=False))
                        else:
                            rejected.append({'packet_id': packet_id, 'reason': str(error)})
                flush_bft()
                # Any write attempt (including an unknown result) invalidates both
                # initial projections. Never export or display the pre-write view.
                if native_write_attempted:
                    try:
                        native_observation,outgoing=self.contact_observation()
                    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                        native_observation=None;outgoing=None
                        errors.append(str(error))
                        observe_os_error(error,'native-contact-status-final')
        apply_received(received)
        if native_observation is not None or independent_bft:
            # Export authority is obtained from the actual native ledger. A
            # region advertised by a mesh key selects only a candidate carrier.
            try:
                offers = outgoing['offers'] if outgoing is not None else []
                if offers:
                    offset = self.progress['cursor'] % len(offers)
                    offers = (offers[offset:] + offers[:offset])[:MAX_PER_TICK]
                selections=[]
                for offer in offers:
                    candidates=sorted(i for i,region in adverts.items()
                        if region==offer['destination'] and routes.get(i))
                    if not candidates:continue
                    # One first recipient per selected offer retains the old
                    # offer service. Spare places use the original four-item
                    # total budget, round-robin across further recipients.
                    # Advertised regions select carriers, never Native rights.
                    start=(self.progress['cursor']//MAX_PER_TICK)%len(candidates)
                    selections.append((offer,candidates[start:]+candidates[:start],[]))
                places=MAX_PER_TICK
                for index in range(MAX_PER_TICK):
                    for _,candidates,chosen in selections:
                        if not places:break
                        if index<len(candidates):chosen.append(candidates[index]);places-=1
                    if not places:break
                for offer,_,destinations in selections:
                    if not destinations:continue
                    value = self.native.call('contact-export', '--export', offer['export'])
                    raw = wire.canonical(value)
                    frame, _ = wire.inspect_frame(raw)
                    mesh.require(frame['source_chain_id'] == self.region and frame['destination_chain_id'] == offer['destination'], 'outgoing native route changed')
                    with self.tcp.ordinary_mesh_node() as node:
                        # Inspect exact retained bytes before one atomic bounded
                        # admission. Failed writes grant no custody or ledger
                        # acknowledgment. Cold state reconciles retained copies.
                        retained={(summary['frame_id'],summary['destination'])
                            for summary in node.summaries().values() if summary['source']==node.id}
                        items=[(raw,destination) for destination in destinations
                               if (frame['message_id'],destination) not in retained]
                        if items:node.enqueue_batch(items)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
                observe_os_error(error,'native-outgoing')
        # Finish the current contact unit before obeying stop. Never start
        # another consensus/signing unit; already retained effects stay intact.
        if getattr(self.tcp, 'running', True) is False:
            raise tcp.MeshRuntimeStopping('TCP runtime is stopping; preserve evidence')
        consensus = None
        stage_seconds['native_receive_and_outgoing'] = round(time.monotonic()-stage_started, 6)
        stage_started = time.monotonic()
        def before_timeout():
            # Exactly one late intake opportunity, only within this unit's
            # remaining four selections. Do not tick the mesh or renew a timer.
            if len(quota['attempted'])>=MAX_PER_TICK:return False
            late=[]
            with self.selection_node() as node:
                node.contact_trace=getattr(self,'contact_trace',None)
                errors.extend(node.drain_spool_incoming())
                summaries,receipts=node.summaries(),node.receipts()
                chosen=self.receive_candidates(summaries,receipts,node.id,quota)
                selected.extend(chosen)
                for ident in chosen:
                    try:
                        transit=node.transit(ident)
                        _,raw,_=mesh.transit_check(transit,node.network)
                        mesh.receipt_matches(receipts[ident],transit)
                        late.append((ident,raw))
                        if self.contact_trace is not None and summaries[ident]['kind']=='regional-bft':
                            self.contact_trace.native_stage('native_receive_selected',ident,raw)
                    except (OSError,ValueError) as error:
                        errors.append(str(error))
                        rejected.append({'packet_id':ident,'reason':str(error)})
            # No mesh lock crosses Native authentication/persistence. Even an
            # empty or rejected attempt requires a new Native phase observation.
            apply_received(late)
            return True
        if self.bft is not None:
            previous_refresh=getattr(self.bft,'before_timeout',None)
            if independent_bft:self.bft.before_timeout=before_timeout
            try:
                consensus=self.bft.tick()
            except (OSError,ValueError,subprocess.TimeoutExpired) as error:
                errors.append(str(error))
                observe_os_error(error,'consensus')
                # A failed observation cannot establish the current signing role.
                consensus={'autonomous_signing_enabled':None,'progress_observation_available':False,
                           'diagnostic':str(error)[:256],'independent_bft_qualified':False}
            finally:
                if independent_bft:self.bft.before_timeout=previous_refresh
        stage_seconds['consensus'] = round(time.monotonic()-stage_started, 6)
        if spool_outgoing:
            # Intake preceded Native export verification and optional signing.
            # Send exactly the deferred directory batch now, including newly
            # durable responses.
            # TCP already follows this order. Timeout-boundary intake uses only
            # unused selections; the global cursor still advances once.
            stage_started=time.monotonic()
            try:
                with self.tcp.ordinary_mesh_node() as node:
                    node.contact_trace = getattr(self, 'contact_trace', None)
                    errors.extend(node.flush_spool_outgoing())
            except (OSError,ValueError) as error:
                errors.append(str(error));observe_os_error(error,'mesh-outgoing')
            stage_seconds['spool_outgoing']=round(time.monotonic()-stage_started,6)
        if socket_observation is None:
            stage_started = time.monotonic()
            socket_observation = self.tcp.tick()
            stage_seconds['tcp'] = round(time.monotonic()-stage_started, 6)
            errors.extend(socket_observation['errors'])
            local_os_errors.extend(socket_observation.get('local_os_errors',()))
        elif self.carriage is not None:
            socket_observation=self.carriage.snapshot()
            # Parallel CPU/socket duration is not a serial contact-tick stage.
            stage_seconds['tcp']=None
        transport['tcp'] = socket_observation
        stage_seconds['before_status_publication'] = round(time.monotonic()-tick_started, 6)
        self.progress['cursor'] = (self.progress['cursor'] + MAX_PER_TICK) % (2**63)
        mesh.atomic(self.path, self.progress)
        # Process-only bounded history keeps a captured exact origin through
        # later snapshots and graceful stop; it never changes current errors.
        self.local_os_error_history=tuple((list(getattr(self,'local_os_error_history',()))+local_os_errors)[-16:])
        report = {'format': FORMAT, 'process_id': os.getpid(), 'currency': self.native.currency, 'region': self.region,
            'relay_enabled': True, 'local_import_mining_enabled': self.miner is not None,
            'observed_at_unix': int(time.time()), 'transport': transport,
            'native_observation': native_observation, 'native_observation_available': native_observation is not None,
            'applied': applied, 'rejected': rejected, 'deferred': deferred,
            'errors': errors[:16], 'local_os_errors': list(self.local_os_error_history), 'local_os_errors_are_process_history': True, 'fixture_only': True,
            'consensus': consensus,
            'physical_route_verified': False, 'independent_operators': False,
            'transport_receipt_is_payment_authority': False, 'remote_current_state_known': False}
        observation = getattr(self.bft, 'observation', None)
        if observation is not None:
            observation.event('contact-tick', tick_started, selected=len(selected), received=len(received),
                              errors=len(errors), tcp_seconds=stage_seconds['tcp'],
                              mesh_seconds=stage_seconds['mesh_selection'],
                              native_contact_seconds=stage_seconds['native_contact_observation'],
                              spool_outgoing_seconds=stage_seconds.get('spool_outgoing'),
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
