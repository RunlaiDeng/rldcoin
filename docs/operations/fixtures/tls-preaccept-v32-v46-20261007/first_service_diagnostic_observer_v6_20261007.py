"""Fixture-only original-function observation; never consensus/custody authority.

Only primitive IDs/positions are retained. Original packet/key/header objects,
signatures and mutable plans do not enter this independent diagnostic ring.
An observer error invalidates collection; it never changes a protocol result.
"""
from collections import deque
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import time

FORMAT = 'RLD-FIRST-SERVICE-DIAGNOSTIC-V4'
MAX_EVENTS = 32
MAX_EVENT_BYTES = 192 * 1024
MAX_BYTES = 8 * 1024 * 1024
MAX_COUNTER = 2**63 - 1

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')

def require(value, reason):
    if not value:
        raise ValueError(reason)

def ids(values, limit):
    require(type(values) is list and len(values) <= limit, 'diagnostic ID bound')
    require(len(set(values)) == len(values) and all(type(v) is str and len(v) == 64
            and all(c in '0123456789abcdef' for c in v) for v in values),
            'diagnostic primitive IDs')
    return list(values)

def metadata(value):
    observed = value['observed']
    return dict(pending=ids(value['pending'], 32), prepared=ids(value['prepared'], 256),
                arrivals=ids(value['arrivals'], 256),
                observed_count=None if observed is None else len(ids(observed, 256)),
                history_after=value['history_after'], next_kind=value['next_kind'])

def check_metadata(value):
    require(type(value) is dict and set(value) == {'pending','prepared','arrivals',
            'observed_count','history_after','next_kind'}, 'diagnostic metadata schema')
    ids(value['pending'], 32); ids(value['prepared'], 256); ids(value['arrivals'], 256)
    n = value['observed_count']
    require(n is None or type(n) is int and 0 <= n <= 256, 'diagnostic observed bound')
    require(type(value['next_kind']) is int and value['next_kind'] in (0,1), 'diagnostic next kind')
    require(value['history_after'] is None or ids([value['history_after']], 1), 'diagnostic history ID')

def priority_snapshot(mesh, node, peer):
    # Observe the exact primitive row without touching its LRU position.
    # The actual planner remains solely responsible for admission/selection.
    key=(node.carriage_position_domain(),'native-commit-spare')
    with mesh._carriage_position_lock:
        retained=mesh._carriage_positions.get(key)
        value=None if retained is None else retained[0]
    scope=None;frames=()
    if value is not None:
        require(type(value) is tuple and len(value)==2 and type(value[1]) is tuple,
                'diagnostic priority primitive row')
        scope=value[0];ids([scope],1);ids(list(value[1]),512);frames=value[1]
    step=node.state['transit_class_steps'][peer]
    require(type(step) is int and 0<=step<=MAX_COUNTER,'diagnostic exact class step')
    matches=sorted(i for i,t in node.state['messages'].items()
                   if t['routing']['body']['frame_id'] in frames)
    ids(matches,256)
    return dict(class_step=step,pair_enabled=(step//2)%2==0,hint_scope=scope,
                frame_ids=list(frames),matching_packet_ids=matches)

def hint_value(value):
    if value is None:return None
    require(type(value) is tuple and len(value)==2 and type(value[1]) is tuple,
            'diagnostic consumed hint shape')
    ids([value[0]],1);ids(list(value[1]),512)
    return dict(scope=value[0],frame_ids=list(value[1]))

def check_selector(value):
    require(type(value) is dict and set(value)=={'hint_reads','groups','transit_checks','routes'},
            'diagnostic selector schema')
    reads=value['hint_reads'];require(type(reads) is list and len(reads)<=2,'diagnostic hint read bound')
    for hint in reads:
        if hint is None:continue
        require(type(hint) is dict and set(hint)=={'scope','frame_ids'},'diagnostic consumed hint schema')
        ids([hint['scope']],1);ids(hint['frame_ids'],512)
    groups=value['groups'];require(type(groups) is list and len(groups)<=2,'diagnostic grouping call bound')
    for call in groups:
        require(type(call) is list and len(call)==2,'diagnostic original two classes')
        all_ids=[];size=0
        for group in call:
            require(type(group) is dict and set(group)=={'size','current_ids','positions'},
                    'diagnostic focused class schema')
            require(type(group['size']) is int and 0<=group['size']<=256,'diagnostic original class size')
            current=ids(group['current_ids'],256);positions=group['positions']
            require(type(positions) is list and len(positions)==len(current)
                    and all(type(n) is int and 0<=n<group['size'] for n in positions)
                    and positions==sorted(set(positions)),'diagnostic actual current ranks')
            size+=group['size'];all_ids+=current
        require(size<=256 and len(all_ids)==len(set(all_ids)),'diagnostic disjoint current classes')
    checks=value['transit_checks'];routes=value['routes']
    require(type(checks) is dict and type(routes) is dict,'diagnostic checked route maps')
    ids(list(checks),256);ids(list(routes),256)
    require(all(type(n) is int and 1<=n<=1024 for n in checks.values())
            and sum(checks.values())<=1024,'diagnostic authenticated checks bound')
    require(set(routes)<=set(checks),'diagnostic route without preceding original transit check')
    for route in routes.values():
        require(type(route) is dict and set(route)=={'attempts','eligible','path_length'},'diagnostic route schema')
        require(type(route['attempts']) is int and 1<=route['attempts']<=1024
                and type(route['eligible']) is bool,'diagnostic original route count/eligibility')
        length=route['path_length']
        require(length is None or type(length) is int and 1<=length<=17,'diagnostic original path length')
        require(not route['eligible'] or length is not None and length>=2,'diagnostic eligible missing route')
    require(sum(v['attempts'] for v in routes.values())<=1024,'diagnostic total route count')

def check_record(row, sequenced=False):
    fields = {'peer','role','retries','before','plans','hop_attempts','suppressed_ids',
              'candidate_checks','atomic_returns','advance_active','completed','prepare_inclusive_seconds'}
    optional = {'selected','after','durable_metadata','original_error_class','return_observation_missing','priority','selector'}
    if sequenced:
        fields.add('sequence')
        require(type(row.get('sequence')) is int and 1 <= row['sequence'] <= MAX_COUNTER,
                'diagnostic typed event sequence')
    require(type(row) is dict and fields <= set(row) and not set(row)-fields-optional,
            'diagnostic record schema')
    ids([row['peer']],1); ids(row['retries'],4); ids(row['suppressed_ids'],256)
    require(row['role'] in ('outbound','input','ordinary','handler','unregistered'), 'diagnostic role')
    check_metadata(row['before'])
    if 'priority' in row:
        p=row['priority']
        require(type(p) is dict and set(p)=={'class_step','pair_enabled','hint_scope',
                'frame_ids','matching_packet_ids'},'diagnostic priority schema')
        require(type(p['class_step']) is int and 0<=p['class_step']<=MAX_COUNTER
                and type(p['pair_enabled']) is bool
                and p['pair_enabled']==((p['class_step']//2)%2==0),
                'diagnostic original priority phase')
        if p['hint_scope'] is not None:ids([p['hint_scope']],1)
        ids(p['frame_ids'],512);ids(p['matching_packet_ids'],256)
        require(p['hint_scope'] is not None or p['frame_ids']==[],
                'diagnostic missing hint had frames')
    if 'selector' in row:check_selector(row['selector'])
    require(type(row['plans']) is list and len(row['plans']) <= 2, 'diagnostic plan bound')
    for value in row['plans']: check_metadata(value)
    values = row['hop_attempts']
    require(type(values) is dict, 'diagnostic hop map'); ids(list(values),256)
    require(all(type(n) is int and 1 <= n <= 32 for n in values.values()), 'diagnostic hop counters')
    for name,cap in [('candidate_checks',1024),('atomic_returns',2)]:
        require(type(row[name]) is int and 0 <= row[name] <= cap, 'diagnostic counter bound')
    require(type(row['advance_active']) is bool and type(row['completed']) is bool,
            'diagnostic original result flags')
    elapsed = row['prepare_inclusive_seconds']
    require(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed >= 0,
            'diagnostic finite timing')
    for name in ('after','durable_metadata'):
        if name in row: check_metadata(row[name])
    if row['completed']:
        require('selected' in row and 'after' in row and 'original_error_class' not in row,
                'diagnostic success shape'); ids(row['selected'],4)
    else:
        error = row.get('original_error_class')
        require(type(error) is str and len(error) <= 64 and error.isidentifier(),
                'diagnostic original error class')

class Ring:
    def __init__(self, binding):
        require(type(binding) is dict and set(binding) == {'process_id','scope','slot','contract_sha256'},
                'diagnostic exact binding')
        require(type(binding['process_id']) is int and binding['process_id'] > 0
                and type(binding['slot']) is int and 0 <= binding['slot'] < 4
                and type(binding['scope']) is str and Path(binding['scope']).is_absolute(),
                'diagnostic typed process/scope')
        ids([binding['contract_sha256']],1)
        self.binding = json.loads(encode(binding))
        self.rows = deque()
        self.sequence = self.evicted = self.rejected = self.bytes = 0
        self.available = True
        self.lock = threading.Lock()

    def invalidate(self):
        with self.lock:
            self.available = False
            self.rejected = min(MAX_COUNTER, self.rejected + 1)

    def append(self, row):
        try:
            check_record(row)
            with self.lock:
                require(self.sequence < MAX_COUNTER, 'diagnostic sequence exhaustion')
                raw = encode(dict(row, sequence=self.sequence + 1))
                require(len(raw) <= MAX_EVENT_BYTES, 'diagnostic record byte capacity')
                self.sequence += 1
                self.rows.append(raw)
                self.bytes += len(raw)
                while len(self.rows) > MAX_EVENTS or self.bytes > MAX_EVENTS * MAX_EVENT_BYTES:
                    self.bytes -= len(self.rows.popleft())
                    self.evicted += 1
            return True
        except Exception:
            self.invalidate()
            return False

    def snapshot(self):
        with self.lock:
            value = dict(format=FORMAT, binding=dict(self.binding), authority=False,
                         available=self.available, sequence=self.sequence,
                         evicted=self.evicted, rejected=self.rejected,
                         records=[json.loads(raw) for raw in self.rows])
            require(len(encode(value)) <= MAX_BYTES, 'diagnostic publication capacity')
            return value

class Cursor:
    def __init__(self, binding):
        self.binding = Ring(binding).binding
        self.sequence = 0
        self.last_digest = None

    def drain(self, value):
        require(set(value) == {'format','binding','authority','available','sequence',
                              'evicted','rejected','records'} and value['format'] == FORMAT
                and encode(value['binding']) == encode(self.binding) and value['authority'] is False
                and value['available'] is True and type(value['rejected']) is int and value['rejected'] == 0,
                'diagnostic unavailable or foreign binding')
        n, evicted, rows = value['sequence'], value['evicted'], value['records']
        require(type(n) is int and type(evicted) is int and 0 <= evicted <= n <= MAX_COUNTER
                and n >= self.sequence and type(rows) is list and len(rows) <= MAX_EVENTS
                and len(rows) + evicted == n, 'diagnostic ring/restart inventory')
        require(len(encode(value)) <= MAX_BYTES, 'diagnostic snapshot capacity')
        for index, row in enumerate(rows):
            check_record(row, sequenced=True)
            require(type(row) is dict and row.get('sequence') == evicted + index + 1
                    and len(encode(row)) <= MAX_EVENT_BYTES, 'diagnostic exact sequence')
            if row['sequence'] == self.sequence and self.last_digest is not None:
                require(hashlib.sha256(encode(row)).hexdigest() == self.last_digest,
                        'diagnostic retained record changed')
        require((rows[0]['sequence'] if rows else n + 1) <= self.sequence + 1,
                'diagnostic interval gap')
        new = [json.loads(encode(row)) for row in rows if row['sequence'] > self.sequence]
        self.sequence = n
        if rows:
            self.last_digest = hashlib.sha256(encode(rows[-1])).hexdigest()
        return new

class Observer:
    def __init__(self, mesh_module, tcp_module, mesh_root, ring):
        self.mesh, self.tcp, self.mesh_root, self.ring = mesh_module, tcp_module, Path(mesh_root), ring
        self.local = threading.local()
        self.server = None
        self.originals = []
        self.publisher = None

    def safe(self, function, *args):
        try:
            return function(*args)
        except Exception:
            self.ring.invalidate()
            return None

    def scope(self, node, peer):
        return node.root == self.mesh_root and peer in node.state['first_carriage']

    def role(self):
        current, server = threading.current_thread(), self.server
        if server is None:
            return 'unregistered'
        if current is server.outbound_owner:
            return 'outbound'
        if current is server.input_thread:
            return 'input'
        if current is server.selection_owner:
            return 'ordinary'
        return 'handler'

    def install(self):
        m, t = self.mesh, self.tcp
        require(not self.originals and not getattr(m, '_rld_first_service_observer', None),
                'diagnostic duplicate writer')
        original_prepare, original_plan = m.Node.prepare_exchange, m.Node.first_carriage_plan
        original_sign, original_digest, original_atomic = m.sign, m.digest, m.atomic
        original_init = t.Server.__init__
        original_position, original_groups = m.carriage_position, m.Node.transit_groups
        original_check, original_route = m.transit_check, m.Node.route
        observer = self

        def prepare(node, peer, accepted_transits=None, advance_active=False, retry_packet_ids=()):
            if not observer.safe(observer.scope, node, peer):
                return original_prepare(node, peer, accepted_transits, advance_active, retry_packet_ids)
            def make_context():
                return dict(node=node, accepted=accepted_transits, peer=peer,
                            role=observer.role(), retries=ids(list(retry_packet_ids),4),
                            before=metadata(node.state['first_carriage'][peer]),
                            priority=priority_snapshot(m,node,peer),
                            priority_key=(node.carriage_position_domain(),'native-commit-spare'),
                            route_packet=None,
                            selector=dict(hint_reads=[],groups=[],transit_checks={},routes={}),
                            plans=[], hop_attempts={}, suppressed_ids=[],
                            candidate_checks=0, atomic_returns=0, advance_active=advance_active,
                            started=time.monotonic())
            context = observer.safe(make_context)
            if context is None:
                return original_prepare(node, peer, accepted_transits, advance_active, retry_packet_ids)
            previous = getattr(observer.local, 'context', None)
            if previous is not None:
                observer.ring.invalidate()
            observer.local.context = context
            try:
                bundle = original_prepare(node, peer, accepted_transits, advance_active, retry_packet_ids)
                def returned():
                    return dict(completed=True,
                                selected=[v['routing']['body']['packet_id'] for v in bundle['body']['transits']],
                                after=metadata(node.state['first_carriage'][peer]))
                context.update(observer.safe(returned) or dict(completed=True, return_observation_missing=True))
                return bundle
            except BaseException as error:
                context.update(completed=False, original_error_class=type(error).__name__)
                raise
            finally:
                observer.local.context = previous
                context['prepare_inclusive_seconds'] = time.monotonic() - context.pop('started')
                context.pop('node')
                context.pop('accepted')
                context.pop('priority_key')
                context.pop('route_packet')
                observer.safe(observer.ring.append, context)

        def plan(node, peer):
            result = original_plan(node, peer)
            context = getattr(observer.local, 'context', None)
            if context is not None and context['node'] is node and context['peer'] == peer:
                observer.safe(lambda: context['plans'].append(metadata(result)))
            return result

        def signed(key, kind, body):
            result = original_sign(key, kind, body)
            context = getattr(observer.local, 'context', None)
            if context is not None and kind == 'hop':
                def count():
                    ident = body['packet_id']
                    require(body['node_id'] == context['node'].id and body['to'] == context['peer'],
                            'diagnostic original hop role')
                    values = context['hop_attempts']
                    require(ident in values or len(values) < 256, 'diagnostic hop ID capacity')
                    values[ident] = values.get(ident, 0) + 1
                observer.safe(count)
            return result

        def digested(value):
            result = original_digest(value)
            context = getattr(observer.local, 'context', None)
            if context is not None and type(value) is dict and set(value) == {'packet','routing','hops'}:
                def seen():
                    context['candidate_checks'] += 1
                    ident = value['routing']['body']['packet_id']
                    accepted = context['accepted']
                    if accepted is not None and result in accepted and ident not in context['suppressed_ids']:
                        require(len(context['suppressed_ids']) < 256, 'diagnostic suppression bound')
                        context['suppressed_ids'].append(ident)
                observer.safe(seen)
            return result

        def atomic(path, value):
            result = original_atomic(path, value)
            context = getattr(observer.local, 'context', None)
            if context is not None and path == context['node'].path:
                def wrote():
                    context['atomic_returns'] += 1
                    context['durable_metadata'] = metadata(value['first_carriage'][context['peer']])
                observer.safe(wrote)
            return result

        def server_init(server, *args, **kwargs):
            result = original_init(server, *args, **kwargs)
            def registered():
                if Path(server.config['state']) == observer.mesh_root:
                    require(observer.server is None, 'diagnostic duplicate local server')
                    observer.server = server
            observer.safe(registered)
            return result

        def positioned(key):
            result=original_position(key)
            context=getattr(observer.local,'context',None)
            if context is not None and key==context['priority_key']:
                def captured():
                    rows=context['selector']['hint_reads']
                    require(len(rows)<2,'diagnostic hint read bound')
                    rows.append(hint_value(result))
                observer.safe(captured)
            return result

        def grouped(node,peer):
            result=original_groups(node,peer)
            context=getattr(observer.local,'context',None)
            if context is not None and context['node'] is node and context['peer']==peer:
                def captured():
                    rows=context['selector']['groups'];require(len(rows)<2,'diagnostic grouping call bound')
                    require(type(result) is list and len(result)==2,'diagnostic original classes')
                    tracked=set(context['priority']['matching_packet_ids']);groups=[]
                    for items in result:
                        require(type(items) is list and len(items)<=256,'diagnostic original group bound')
                        positions=[i for i,ident in enumerate(items) if ident in tracked]
                        groups.append(dict(size=len(items),current_ids=ids([items[i] for i in positions],256),
                                           positions=positions))
                    rows.append(groups)
                observer.safe(captured)
            return result

        def checked(transit,network,recipient=None,sender=None,*,include_frame=True):
            result=original_check(transit,network,recipient,sender,include_frame=include_frame)
            context=getattr(observer.local,'context',None)
            if context is not None and network==context['node'].network:
                def captured():
                    ident=transit['routing']['body']['packet_id'];ids([ident],1)
                    context['route_packet']=None
                    if ident not in context['priority']['matching_packet_ids']:return
                    rows=context['selector']['transit_checks']
                    require(ident in rows or len(rows)<256,'diagnostic original transit ID bound')
                    rows[ident]=rows.get(ident,0)+1
                    context['route_packet']=(ident,result[0]['destination'],len(transit['hops']),
                                             result[0]['hop_limit'])
                observer.safe(captured)
            return result

        def routed(node,destination,excluded=(),first_hop=None):
            result=original_route(node,destination,excluded,first_hop)
            context=getattr(observer.local,'context',None)
            if context is not None and context['node'] is node and first_hop==context['peer']:
                def captured():
                    marker=context['route_packet'];context['route_packet']=None
                    if marker is None or marker[1]!=destination:return
                    ident=marker[0];rows=context['selector']['routes']
                    require(ident in rows or len(rows)<256,'diagnostic original route ID bound')
                    prior=rows.get(ident,dict(attempts=0,eligible=False,path_length=None))
                    rows[ident]=dict(attempts=prior['attempts']+1,
                                     path_length=None if result is None else len(result),
                                     eligible=bool(result and len(result)>=2 and result[1]==first_hop
                                                   and marker[2]+len(result)-1<=marker[3]))
                observer.safe(captured)
            return result

        replacements = [(m.Node,'prepare_exchange',prepare),(m.Node,'first_carriage_plan',plan),
                        (m,'sign',signed),(m,'digest',digested),(m,'atomic',atomic),
                        (t.Server,'__init__',server_init),
                        (m,'carriage_position',positioned),(m.Node,'transit_groups',grouped),
                        (m,'transit_check',checked),(m.Node,'route',routed)]
        for owner, name, wrapper in replacements:
            self.originals.append((owner, name, getattr(owner, name), wrapper))
            setattr(owner, name, wrapper)
        m._rld_first_service_observer = self

    def restore(self):
        require(self.originals and getattr(self.mesh, '_rld_first_service_observer', None) is self,
                'diagnostic restore owner')
        require(all(getattr(owner,name) is wrapper for owner,name,original,wrapper in self.originals),
                'diagnostic conflicting hook owner')
        for owner, name, original, wrapper in reversed(self.originals):
            setattr(owner, name, original)
        self.originals.clear()
        del self.mesh._rld_first_service_observer

class Publisher:
    def __init__(self, observer, path):
        self.observer, self.path = observer, Path(path)
        require(not self.path.exists() and not self.path.is_symlink(), 'old observer publication refused')
        self.atomic = observer.originals[4][2]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name='fixture-first-service-observer', daemon=True)
        self.publish()
        self.thread.start()

    def publish(self):
        self.atomic(self.path, self.observer.ring.snapshot())

    def run(self):
        while not self.stop.wait(.25):
            try:
                self.publish()
            except Exception:
                self.observer.ring.invalidate()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        require(not self.thread.is_alive(), 'diagnostic publisher still alive')
        self.publish()
