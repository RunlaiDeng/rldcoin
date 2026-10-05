"""Read-only experiment entry model. Stored observations grant no Native rights."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from regional_fixture_native_json import decode_native_json

RULES = 'RLD-REGIONAL-BFT-PAGED-VALUE-CHANNELS-FIXTURE-V1'
REGIONS = ('earth', 'proxima', 'andromeda')
LIMIT = 8 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def hex32(value):
    require(type(value) is str and len(value) == 64
            and all(c in '0123456789abcdef' for c in value), 'scope digest differs')
    return value


def safe(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute scope path required')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'scope symlink refused')
    return path


def raw(path, limit=LIMIT):
    path = safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'scope input capacity')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            data = f.read(limit + 1)
        require(len(data) <= limit, 'scope input grew beyond bound')
        return data
    finally:
        os.close(fd)


def digest(path):
    return hashlib.sha256(raw(path, 64 * 1024 * 1024)).hexdigest()


def document(path, expected=None):
    data = raw(path)
    if expected is not None:
        require(hashlib.sha256(data).hexdigest() == hex32(expected), 'scope document pin differs')
    return decode_native_json(data)


def inventory(root):
    root = safe(root)
    rows, total = {}, 0
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'scope inventory symlink refused')
        if path.is_dir():
            continue
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode), 'scope inventory special file refused')
        total += info.st_size
        require(len(rows) < 65536 and total <= 6 * 1024**3, 'combined fixture inventory capacity')
        rows[path.relative_to(root).as_posix()] = [digest(path), info.st_mode, info.st_uid,
                                                  info.st_size, info.st_mtime_ns]
    return rows


@dataclass(frozen=True)
class ReplicaPin:
    region: str
    index: int
    height: int
    history_head: str
    caller_head: str
    key: str
    region_id: str


@dataclass(frozen=True)
class Pins:
    checks: str
    stage: str
    inventory: str
    currency: str
    implementation: str
    native_source: str
    binary: str
    core_manifest: str
    replicas: tuple
    owner_heads: tuple
    owner_intents: tuple


@dataclass(frozen=True)
class Scope:
    currency: str
    replicas: tuple
    caps: tuple
    stage_seconds: int = 600
    round_seconds: int = 60
    max_new_heights: int = 24
    maturity: int = 2
    quorum: int = 3
    native_authority: bool = False
    independent_freshness: bool = False

    def missing_leader_gate(self, region, absent):
        rows = tuple(p for p in self.replicas if p.region == region)
        require(len(rows) == 4 and len({p.height for p in rows}) == 1,
                'complete current regional height required')
        keys = tuple(p.key for p in rows)
        require(keys == tuple(sorted(set(keys))) and absent in keys,
                'exact ordered membership required')
        height = rows[0].height
        cap = dict(self.caps)[region]
        require(type(height) is int and 0 <= height < cap, 'scope height cap reached')
        parent = height
        while keys[parent % 4] != absent:
            parent += 1
        require(parent + 1 <= cap and parent + 1 - height <= self.max_new_heights,
                'missing leader exceeds original cap')
        return parent + 1


def review_scope(project, root, checks_path, stage_path, inventory_path, binary_path,
                 core_manifest_path, pins):
    """Pins must come from the reviewed stopped scope, never current Native sampling.

    This checks exact stored provenance and experiment limits only. A future driver
    must still authenticate Native history/envelopes and each independent caller
    head before startup. No private state is copied, restored or opened by Native.
    """
    require(type(pins) is Pins and type(pins.replicas) is tuple
            and type(pins.owner_heads) is tuple and type(pins.owner_intents) is tuple,
            'immutable explicit scope pins required')
    for value in (pins.currency, pins.implementation, pins.native_source, pins.binary,
                  *pins.owner_heads, *pins.owner_intents):
        require(hex32(value) != '0' * 64, 'nonzero scope pin required')
    project, root = safe(project), safe(root)
    checks = document(checks_path, pins.checks)
    stage = document(stage_path, pins.stage)
    retained = document(inventory_path, pins.inventory)
    core = document(core_manifest_path, pins.core_manifest)
    require(digest(binary_path) == pins.binary, 'actual binary bytes differ')
    require(type(retained) is dict and set(retained) == {str(root)}, 'exact retained root required')
    require(inventory(root) == retained[str(root)], 'stopped inventory differs')
    require(checks['format'] == 'RLD-PAGED-ORDINARY-CYCLE-PINNED-COLD-V4-CHECKS'
            and stage['format'] == 'RLD-PAGED-ORDINARY-CYCLE-PINNED-COLD-V4-STAGE'
            and checks['stage_sha256'] == pins.stage
            and checks['private_inventory_sha256'] == pins.inventory
            and checks['completed'] is True and checks['helper_exit_code'] == 0
            and checks['failed'] is None and checks['pin_error'] is None
            and checks['old_source_private_freeze_pins_unchanged'] is True
            and checks['helper_terminal'] is True and checks['budget_exhausted'] is False
            and checks['active_own_service_pids'] == []
            and 0 < checks['duration_seconds'] < 600, 'exact clean completed cycle required')
    require(len(checks['service_terminals']) == 27
            and all(t['exit_code'] == 0 for t in checks['service_terminals']),
            'all original services must terminate cleanly')
    require(stage['budget_seconds'] == checks['budget_seconds'] == 600
            and stage['attempts'] == checks['attempts_used'] == 1
            and stage['original_network']['round_seconds'] == 60
            and stage['max_new_heights_per_region_entire_scope'] == 24
            and stage['absolute_height_caps'] == dict(earth=27, proxima=24, andromeda=24)
            and stage['bounds'] == dict(object_bytes=8388608, archive_files=4096,
                archive_bytes=268435456, logical_checkpoints=64, logical_blocks=256,
                wire_bytes=3145728, page_records=16), 'original experiment limits differ')
    for field, value in (('source_commitment', pins.native_source),
                         ('implementation', pins.implementation), ('cli_binary_sha256', pins.binary)):
        require(checks[field] == stage[field] == value, 'source/profile identity differs')
    for field in ('native_source_sha256', 'python_source_sha256'):
        for name, expected in stage[field].items():
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts
                    and relative.as_posix() == name, 'scope source path differs')
            require(digest(project / relative) == expected, 'bound source bytes differ')
    for row in core['files']:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts
                and relative.as_posix() == row['path'], 'core source path differs')
        require(digest(project / relative) == row['sha256'], 'bound core source differs')
    require(core['format'] == 'RLD-EARTH-IMPLEMENTATION-SOURCE'
            and core['commitment'] == stage['core_171_commitment']
            and core['file_count'] == len(core['files']) == 171,
            'complete core source identity differs')
    result = checks['result']
    require(result['completed'] is True and result['maturity'] == 2
            and result['original_owner_first_sign_count'] == 3
            and result['owner_heads_original_unchanged'] is True
            and result['no_refund_or_new_owner_request'] is True
            and len(result['ordinary_phase_results']) == 6, 'original owner cycle differs')
    expected_slots = tuple((region, n) for region in REGIONS for n in range(4))
    require(len(pins.replicas) == 12 and all(type(p) is ReplicaPin for p in pins.replicas)
            and tuple((p.region, p.index) for p in pins.replicas) == expected_slots,
            'twelve ordered explicit custody pins required')
    bootstrap = document(root / 'signed-fresh-bootstrap.json')
    require(bootstrap['currency']['implementation'] == pins.implementation
            and bootstrap['currency']['maturity'] == 2
            and len(bootstrap['admissions']) == 3, 'bootstrap profile differs')
    admissions = bootstrap['admissions']
    for label, admission in zip(REGIONS, admissions):
        keys = admission['validators']
        require(admission['rules'] == RULES and admission['currency'] == pins.currency
                and len(keys) == 4 and keys == sorted(set(keys)), 'paged admission/membership differs')
        for n in range(4):
            p = pins.replicas[expected_slots.index((label, n))]
            for value in (p.history_head, p.caller_head, p.key, p.region_id):
                require(hex32(value) != '0' * 64, 'nonzero custody pin required')
            head = document(root / label / f'observed-native-head-{n}.json')
            caller = document(root / label / f'caller-{n}' / 'head.json')
            require(type(p.height) is int and p.height == result['final_native_heights'][label][n]
                    == head['height'] and p.history_head == head['history_head']
                    and 0 <= p.height < stage['absolute_height_caps'][label]
                    and head['currency'] == pins.currency and head['region'] == p.region_id
                    and head['fixture_only'] is True and head['live_rld'] is False
                    and head['logical_native_replay_complete'] is True
                    and head['independent_latest_state_anchor_qualified'] is False,
                    'retained Native head observation differs')
            require(p.key == keys[n] and caller['head'] == p.caller_head
                    and caller['pending'] is None and caller['outbox'] is None
                    and caller['binding']['key'] == p.key
                    and caller['binding']['currency'] == pins.currency
                    and caller['binding']['region'] == p.region_id, 'retained caller observation differs')
            native_header = document(root / label / f'native-{n}' / 'ledger-header.json')
            voter_header = document(root / label / f'voter-{n}' / 'bft-header.json')
            require(native_header['format'] == head['format'] == 'RLD-NATIVE-PAGED-BFT-STORE-V1'
                    and native_header['region'] == p.region_id
                    and native_header['bootstrap'] == bootstrap
                    and voter_header['format'] == 'RLD-NATIVE-PAGED-BFT-SIGNER-V1'
                    and voter_header['journal']['binding'] == caller['binding'],
                    'original paged custody layout required')
    require(len(pins.owner_heads) == len(pins.owner_intents) == 3, 'three original owner pins required')
    for n in range(3):
        owner = root / f'owner-{n}'
        caller = document(owner / 'caller' / 'head.json')
        response = document(owner / 'signed-response.json')
        require(caller['pending'] is None and caller['head'] == response['wallet_head']
                == pins.owner_heads[n] and response['intent_id'] == pins.owner_intents[n]
                and response['recovered_exact_retry'] is False
                and response['retained_approvals_complete'] is True
                and caller['binding']['currency'] == pins.currency,
                'original owner/caller response differs')
    require(inventory(root) == retained[str(root)], 'stopped inventory changed during review')
    return Scope(pins.currency, pins.replicas,
                 tuple((label, stage['absolute_height_caps'][label]) for label in REGIONS))
