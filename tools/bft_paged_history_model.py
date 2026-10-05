"""Executable retention proposal, not a native implementation or authority.

IdealAuthentication is an explicit ideal signature/owner oracle. Public model
labels have no cryptographic security. Single era, four equal voters, 3-of-4
certificates; unknown era/admission refuses. The issued slice is a premise, not
genesis issuance permission. Value execution is only a channel/import subset.
Append publication is an abstract ordering model, not filesystem durability.
No disk ledger or hashing witness can initialize replay. All complete evidence
remains in immutable 16-event pages plus a bounded complete-event manifest tail.
"""

from collections import deque
from dataclasses import dataclass, field
import hashlib
import json

DOMAIN = 'RLD-BFT-PAGED-HISTORY-MODEL-V1'
PAGE = 16
OBSERVATIONS = 64
SIGN_RECORDS = 128
OBJECT_BYTES = 8 * 1024 * 1024
FILES = 4096
ARCHIVE_BYTES = 256 * 1024 * 1024
WINDOW = 2016
COMMANDS = 16
U64 = 2**64 - 1
CAP = 10**35
KEYS = (0, 1, 2, 3)


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw):
    require(type(raw) is bytes and len(raw) <= OBJECT_BYTES, 'object bytes')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Refusal('invalid canonical object') from exc
    require(canonical(value) == raw, 'canonical bytes')
    return value


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields.split()), 'typed fields')


def integer(value, low=0, high=U64):
    require(type(value) is int and low <= value <= high, 'checked integer')
    return value


class IdealAuthentication:
    """Separate ideal authentic statements; digest agreement is insufficient.

    The model producer explicitly registers authenticated statements. A reader
    cannot authenticate a new statement by inventing a matching digest. This is
    a mathematical premise, never a production oracle or signing capability.
    """

    def __init__(self):
        self.statements = set()

    def issue(self, role, signer, payload):
        statement = {'domain': DOMAIN, 'role': role, 'signer': signer,
                     'payload': payload}
        raw = canonical(statement)
        self.statements.add(raw)
        return statement

    def check(self, statement, role, signer, payload):
        require(statement == {'domain': DOMAIN, 'role': role, 'signer': signer,
                              'payload': payload}, 'signature role/binding')
        require(canonical(statement) in self.statements, 'ideal authentication absent')


@dataclass(frozen=True)
class Limits:
    object_bytes: int = OBJECT_BYTES
    files: int = FILES
    archive_bytes: int = ARCHIVE_BYTES

    def validate(self):
        require(type(self.object_bytes) is int and 0 < self.object_bytes <= OBJECT_BYTES,
                'object limit cannot increase')
        require(type(self.files) is int and 0 < self.files <= FILES, 'file limit cannot increase')
        require(type(self.archive_bytes) is int and 0 < self.archive_bytes <= ARCHIVE_BYTES,
                'archive limit cannot increase')


class Archive:
    """Byte retention only: no receipt, signature, balance or head authorization.

    A replaceable manifest has full ordered tail events, never derived state.
    When a tail seals, its exact events remain in an immutable page. Successfully
    published old manifests are indexes; they contain no unique evidence.
    Failed publication retains the prepared object/tail and a refusing marker.
    """

    def __init__(self, genesis, limits=Limits()):
        limits.validate()
        self.genesis = genesis
        self.limits = limits
        self.objects = {}
        self.manifests = {}
        self.pending = None

    def initial_head(self, stream):
        return digest({'domain': DOMAIN, 'genesis': self.genesis, 'stream': stream})

    def initial(self, stream):
        return {'domain': DOMAIN, 'genesis': self.genesis, 'stream': stream,
                'pages': [], 'tail': [], 'count': 0, 'head': self.initial_head(stream)}

    def inventory(self):
        return canonical({'objects': self.objects, 'manifests': self.manifests,
                          'pending': self.pending})

    def bound(self, objects, manifests, pending=None):
        values = list(objects.values()) + list(manifests.values())
        require(all(type(v) is str and len(v) % 2 == 0 for v in values), 'encoded file rows')
        sizes = [len(v) // 2 for v in values]
        if pending is not None:
            sizes.append(len(canonical(pending)))
        require(all(n <= self.limits.object_bytes for n in sizes), 'object capacity')
        require(len(sizes) <= self.limits.files, 'file capacity')
        require(sum(sizes) <= self.limits.archive_bytes, 'archive capacity')

    def append(self, stream, event, interrupt=False):
        require(self.pending is None, 'incomplete publication retained')
        current = decode(bytes.fromhex(self.manifests[stream])) if stream in self.manifests \
            else self.initial(stream)
        staged = json.loads(canonical(current))
        staged['tail'].append(event)
        staged['count'] += 1
        staged['head'] = digest({'previous': current['head'], 'event': event})
        objects = dict(self.objects)
        if len(staged['tail']) == PAGE:
            previous = staged['pages'][-1]['digest'] if staged['pages'] else None
            page = {'domain': DOMAIN, 'genesis': self.genesis, 'stream': stream,
                    'offset': staged['count'] - PAGE, 'previous': previous,
                    'events': staged['tail']}
            raw = canonical(page)
            key = hashlib.sha256(raw).hexdigest()
            require(key not in objects or objects[key] == raw.hex(), 'immutable collision')
            objects[key] = raw.hex()
            staged['pages'].append({'digest': key, 'size': len(raw)})
            staged['tail'] = []
        manifests = dict(self.manifests)
        manifests[stream] = canonical(staged).hex()
        # Reserve failure residue space before making any publication visible.
        pending = {'stream': stream, 'prepared_manifest': staged}
        self.bound(objects, manifests, pending if interrupt else None)
        if interrupt:
            self.objects = objects
            self.pending = pending
            raise Refusal('publication interrupted; original manifest retained')
        self.objects, self.manifests = objects, manifests
        return staged['head']

    def events(self, stream, latest):
        require(self.pending is None, 'incomplete publication retained')
        self.bound(self.objects, self.manifests)
        require(stream in self.manifests, 'missing manifest')
        manifest = decode(bytes.fromhex(self.manifests[stream]))
        exact(manifest, 'domain genesis stream pages tail count head')
        require((manifest['domain'], manifest['genesis'], manifest['stream']) ==
                (DOMAIN, self.genesis, stream), 'manifest trust/domain')
        require(type(manifest['pages']) is list and type(manifest['tail']) is list and
                len(manifest['tail']) < PAGE, 'bounded tail')
        head, count, previous = self.initial_head(stream), 0, None
        for row in manifest['pages']:
            exact(row, 'digest size')
            require(row['digest'] in self.objects, 'missing page')
            raw = bytes.fromhex(self.objects[row['digest']])
            require(len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['digest'],
                    'page digest/length')
            page = decode(raw)
            exact(page, 'domain genesis stream offset previous events')
            require((page['domain'], page['genesis'], page['stream'], page['offset'], page['previous']) ==
                    (DOMAIN, self.genesis, stream, count, previous), 'ordered page predecessor')
            require(type(page['events']) is list and len(page['events']) == PAGE, 'complete page')
            for event in page['events']:
                head = digest({'previous': head, 'event': event})
                count += 1
                yield event
            previous = row['digest']
        for event in manifest['tail']:
            head = digest({'previous': head, 'event': event})
            count += 1
            yield event
        require(count == manifest['count'] and head == manifest['head'] == latest,
                'exact separately retained latest head')


def vote_payload(block, round_number=0):
    return {'genesis': block['genesis'], 'height': block['height'],
            'parent': block['parent'], 'round': round_number, 'proposal': digest(block)}


def quorum(votes, role, payload, auth):
    require(type(votes) is list and len(votes) == 3, 'three votes')
    signers = [v.get('signer') if type(v) is dict else None for v in votes]
    require(all(type(s) is int and s in KEYS for s in signers) and
            signers == sorted(set(signers)), 'distinct ordered admitted voters')
    for signer, vote in zip(signers, votes):
        auth.check(vote, role, signer, payload)


@dataclass
class Ledger:
    genesis: str
    issued_slice: int
    height: int = 0
    tip: str = ''
    liquid: int = 0
    transit: dict = field(default_factory=dict)
    permanent_imports: set = field(default_factory=set)
    channel: dict | None = None
    active: deque = field(default_factory=lambda: deque(maxlen=OBSERVATIONS))

    def __post_init__(self):
        integer(self.issued_slice, 1, CAP)
        self.tip = self.genesis
        self.liquid = self.issued_slice

    def audit(self):
        e = 0 if self.channel is None or self.channel['settled'] else \
            self.channel['capacity'] + self.channel['budget'] - self.channel['spent']
        require(self.liquid + e + sum(self.transit.values()) == self.issued_slice,
                'disjoint U/E/T conservation')
        require(0 <= self.liquid <= CAP and len(self.permanent_imports) <= 4096 and
                len(self.transit) <= 4096, 'permanent state bounds')

    def execute(self, certificate, auth):
        exact(certificate, 'block round prepare commit')
        block = certificate['block']
        payload = vote_payload(block, integer(certificate['round'], 0, 31))
        quorum(certificate['prepare'], 'prepare', payload, auth)
        quorum(certificate['commit'], 'commit', payload, auth)
        staged = self.stage_block(block, auth)
        staged.height, staged.tip = block['height'], digest(certificate)
        self.height, self.tip, self.liquid = staged.height, staged.tip, staged.liquid
        self.transit, self.permanent_imports, self.channel = \
            staged.transit, staged.permanent_imports, staged.channel
        self.active.append(digest(certificate))

    def stage_block(self, block, auth):
        exact(block, 'domain genesis era height parent actions')
        integer(block['height'], 1)
        require((block['domain'], block['genesis'], block['era'], block['height'], block['parent']) ==
                (DOMAIN, self.genesis, 0, self.height + 1, self.tip), 'sequential genesis/era/parent')
        require(type(block['actions']) is list and len(block['actions']) <= COMMANDS, 'command bound')
        # All changes are staged. Even an authenticated invalid tail cannot debit.
        staged = Ledger(self.genesis, self.issued_slice)
        staged.height, staged.tip, staged.liquid = self.height, self.tip, self.liquid
        staged.transit = dict(self.transit)
        staged.permanent_imports = set(self.permanent_imports)
        staged.channel = None if self.channel is None else dict(self.channel)
        for action in block['actions']:
            staged.action(action, block['height'], auth)
            staged.audit()
        return staged

    def action(self, action, height, auth):
        exact(action, 'operation authorization')
        operation = action['operation']
        auth.check(action['authorization'], 'owner', 'model-owner', operation)
        kind = operation.get('kind')
        if kind == 'close':
            exact(operation, 'kind capacity budget fee_limit')
            capacity = integer(operation['capacity'], 1, CAP)
            budget = integer(operation['budget'], 1, CAP)
            fee_limit = integer(operation['fee_limit'], 1, CAP)
            require(self.channel is None and capacity + budget <= self.liquid and
                    budget >= fee_limit * WINDOW * COMMANDS and height <= U64 - WINDOW,
                    'new close/full fee coverage/checked deadline')
            self.liquid -= capacity + budget
            self.channel = {'close': height, 'deadline': height + WINDOW, 'capacity': capacity,
                            'budget': budget, 'fee_limit': fee_limit, 'spent': 0,
                            'sequence': 0, 'generation': 0, 'settled': False}
        elif kind == 'challenge':
            exact(operation, 'kind sequence generation fee')
            c = self.channel
            require(c is not None and not c['settled'] and c['close'] < height <= c['deadline'],
                    'absolute challenge window')
            sequence = integer(operation['sequence'], 1)
            fee = integer(operation['fee'], 1, CAP)
            require(sequence > c['sequence'] and operation['generation'] == c['generation'] and
                    type(operation['generation']) is int and
                    fee <= c['fee_limit'] and c['spent'] + fee <= c['budget'], 'exact fee predecessor')
            c.update(sequence=sequence, generation=c['generation'] + 1, spent=c['spent'] + fee)
            self.liquid += fee
        elif kind == 'settle':
            exact(operation, 'kind')
            c = self.channel
            require(c is not None and not c['settled'] and height > c['deadline'], 'settle once after deadline')
            self.liquid += c['capacity'] + c['budget'] - c['spent']
            c['settled'] = True
        elif kind == 'export':
            exact(operation, 'kind id amount')
            value = integer(operation['amount'], 1, CAP)
            require(type(operation['id']) is str and operation['id'] and
                    operation['id'] not in self.transit and operation['id'] not in self.permanent_imports and
                    value <= self.liquid, 'unique export/input')
            self.transit[operation['id']] = value
            self.liquid -= value
        elif kind == 'import':
            exact(operation, 'kind id')
            require(operation['id'] in self.transit and operation['id'] not in self.permanent_imports,
                    'permanent duplicate import refusal')
            self.liquid += self.transit.pop(operation['id'])
            self.permanent_imports.add(operation['id'])
        else:
            raise Refusal('unknown value operation')


@dataclass
class Signer:
    signer: int
    height: int = 0
    round: int = 0
    lock: str | None = None
    prepared: bool = False
    committed: bool = False
    active: deque = field(default_factory=lambda: deque(maxlen=SIGN_RECORDS))

    def execute(self, record, previous, ledger, auth):
        exact(record, 'previous request response')
        require(record['previous'] == previous, 'signing request previous caller head')
        request = record['request']
        exact(request, 'role payload observed block prepare timeout')
        payload = request['payload']
        exact(payload, 'genesis height parent round proposal')
        height = integer(payload['height'], 1)
        round_number = integer(payload['round'], 0, 31)
        require((payload['genesis'], height, payload['parent'], request['observed']) ==
                (ledger.genesis, ledger.height + 1, ledger.tip, ledger.tip),
                'full certified signing-height predecessor')
        require(vote_payload(request['block'], round_number) == payload, 'complete proposal bytes')
        ledger.stage_block(request['block'], auth)
        require(height >= self.height, 'old-height signing refusal')
        lock, prepared, committed, current_round = self.lock, self.prepared, self.committed, self.round
        if height > self.height:
            # Advancement needs the old height's actual complete certificate.
            require(self.height == 0 or ledger.height >= self.height,
                    'uncertified signing advance')
            lock, prepared, committed, current_round = None, False, False, 0
        require(round_number >= current_round, 'old round refusal')
        if round_number > current_round:
            timeout_payload = {k: payload[k] for k in ('genesis', 'height', 'parent')}
            timeout_payload['round'] = round_number - 1
            quorum(request['timeout'], 'timeout', timeout_payload, auth)
            prepared, committed = False, False  # the prepare lock survives
        else:
            require(request['timeout'] == [], 'unexpected timeout')
        require(lock is None or lock == payload['proposal'], 'retained prepare-QC lock')
        role = request['role']
        if role == 'prepare':
            require(not prepared and request['prepare'] == [], 'duplicate prepare')
            prepared = True
        elif role == 'commit':
            require(not committed, 'duplicate commit')
            quorum(request['prepare'], 'prepare', payload, auth)
            lock, committed = payload['proposal'], True
        else:
            raise Refusal('unsupported signer role')
        auth.check(record['response'], role, self.signer, payload)
        self.height, self.round, self.lock = height, round_number, lock
        self.prepared, self.committed = prepared, committed
        self.active.append(digest(record))


def replay(archive, heads, issued_slice, auth):
    """Return derived state only AFTER every ledger/signer tail and head validates."""
    require(set(heads) == {'ledger', 'voter-0', 'voter-1', 'voter-2', 'voter-3'} and
            set(archive.manifests) == set(heads), 'exact stream inventory')
    ledger = Ledger(archive.genesis, issued_slice)
    signers = [Signer(signer) for signer in KEYS]
    streams = [f'voter-{signer}' for signer in KEYS]
    readers = [iter(archive.events(stream, heads[stream])) for stream in streams]
    previous = [archive.initial_head(stream) for stream in streams]
    pending = [next(reader, None) for reader in readers]

    def at_height(height):
        for i, reader in enumerate(readers):
            while pending[i] is not None:
                record = pending[i]
                exact(record, 'previous request response')
                exact(record['request'], 'role payload observed block prepare timeout')
                target = integer(record['request']['payload']['height'], 1)
                require(target >= height, 'historical signer record out of order')
                if target > height:
                    break
                signers[i].execute(record, previous[i], ledger, auth)
                previous[i] = digest({'previous': previous[i], 'event': record})
                pending[i] = next(reader, None)

    for certificate in archive.events('ledger', heads['ledger']):
        at_height(ledger.height + 1)
        ledger.execute(certificate, auth)
    at_height(ledger.height + 1)  # fully checked unfinalized voting tail, if any
    require(all(event is None for event in pending), 'unverified future signer tail')
    ledger.audit()
    return ledger, signers


def build_trace(heights=2018):
    """Finite model producer; ideal statements explicitly authored, no real keys."""
    integer(heights, 1, 2018)
    genesis = digest({'domain': DOMAIN, 'fixture': 'zero-real-value', 'era': 0})
    issued = 100000
    auth, archive = IdealAuthentication(), Archive(genesis)
    heads = {stream: archive.initial_head(stream) for stream in
             ('ledger', 'voter-0', 'voter-1', 'voter-2', 'voter-3')}
    archive.manifests = {stream: canonical(archive.initial(stream)).hex() for stream in heads}
    ledger = Ledger(genesis, issued)
    counts = [0] * 4
    old_heads = None
    for height in range(1, heights + 1):
        operations = []
        if height == 1:
            operations = [{'kind': 'close', 'capacity': 60, 'budget': WINDOW * COMMANDS, 'fee_limit': 1}]
        elif height == 2:
            operations = [{'kind': 'challenge', 'sequence': 1, 'generation': 0, 'fee': 1}]
        elif height == 3:
            operations = [{'kind': 'export', 'id': 'permanent-export-1', 'amount': 10}]
        elif height == 4:
            operations = [{'kind': 'import', 'id': 'permanent-export-1'}]
        elif height == 2017:
            operations = [{'kind': 'challenge', 'sequence': 2, 'generation': 1, 'fee': 1}]
        elif height == 2018:
            operations = [{'kind': 'settle'}]
        actions = [{'operation': op, 'authorization': auth.issue('owner', 'model-owner', op)} for op in operations]
        block = {'domain': DOMAIN, 'genesis': genesis, 'era': 0, 'height': height,
                 'parent': ledger.tip, 'actions': actions}
        payload = vote_payload(block)
        voters = sorted((height + i) % 4 for i in range(3))
        prepare = [auth.issue('prepare', signer, payload) for signer in voters]
        commit = [auth.issue('commit', signer, payload) for signer in voters]
        certificate = {'block': block, 'round': 0, 'prepare': prepare, 'commit': commit}
        for role, responses in (('prepare', prepare), ('commit', commit)):
            for signer, response in zip(voters, responses):
                stream = f'voter-{signer}'
                request = {'role': role, 'payload': payload, 'observed': ledger.tip,
                           'block': block, 'prepare': prepare if role == 'commit' else [], 'timeout': []}
                record = {'previous': heads[stream], 'request': request, 'response': response}
                heads[stream] = archive.append(stream, record)
                counts[signer] += 1
        ledger.execute(certificate, auth)
        heads['ledger'] = archive.append('ledger', certificate)
        if height == 64:
            old_heads = dict(heads)
    return archive, heads, issued, auth, counts, old_heads
