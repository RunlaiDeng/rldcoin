"""Immutable full-fault configuration blueprint; never initialize or start custody."""
from dataclasses import dataclass
import json
from pathlib import Path

from regional_paged_fault_scope import REGIONS, RULES, Scope, digest, hex32, require, safe

SLOTS = tuple((region, n) for region in REGIONS for n in range(4))
PHASES = ('isolated-missing-leader', 'offline-catchup', 'restored-maturity', 'keyless-drain')


@dataclass(frozen=True)
class Source:
    native: str
    implementation: str
    binary: str
    authority: str
    origin_miner: str
    remote_miner: str
    python_target: str
    rules: str = RULES


@dataclass(frozen=True)
class Carrier:
    region: str
    index: int
    node: str
    certificate: str
    port: int


@dataclass(frozen=True)
class Funding:
    region: str
    owner: str
    recipient: str
    payment: int
    input_minimum: int
    destination: str | None = None
    fee: int = 1
    maturity: int = 2
    requires_actual_native_input: bool = True


@dataclass(frozen=True)
class Config:
    phase: str
    region: str
    index: int
    started: bool
    mesh: bytes
    bft: bytes
    argv: tuple


@dataclass(frozen=True)
class Blueprint:
    root: str
    currency: str
    source: Source
    configs: tuple
    funding: tuple
    missing_leader_gate: int
    starting_heights: tuple
    caps: tuple
    relay_ports: tuple
    phase_seconds: int = 600
    round_seconds: int = 60
    new_height_limit: int = 24
    cleanup_seconds: int = 5
    native_setup_required: bool = True
    network_authority: bool = False
    signing_authority: bool = False


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def blueprint(reference, source, project, protected_roots, fresh_root, fresh_currency,
              starts, carriers, relay_ports, binary, python, source_owner, recipient, local_recipient):
    """Describe all original fault stages using fresh paths and declared public pins.

    Reference observations select a profile, never seed a ledger. Fresh Native
    setup must independently authenticate genesis, admissions, every funding
    input, signer/caller/owner head and transport identity before any argv is used.
    No filesystem write, key copy, Native invocation or network occurs here.
    """
    require(type(reference) is Scope and type(source) is Source
            and reference.native_authority is False and reference.independent_freshness is False,
            'reviewed observation scope required; it grants no Native rights')
    require(source.rules == RULES, 'explicit paged profile required')
    for value in (source.native, source.implementation, source.binary, source.authority,
                  source.origin_miner, source.remote_miner, fresh_currency, source_owner,
                  recipient, local_recipient, source.python_target):
        require(hex32(value) != '0'*64, 'nonzero explicit public pin required')
    require(fresh_currency != reference.currency, 'fresh signed zero-allocation currency required')
    root, binary, project = map(safe, (fresh_root, binary, project))
    # A standard venv executable may be a leaf symlink. Keep its invocation path
    # so Python retains venv package lookup; pin the actual interpreter separately.
    python = Path(python)
    require(python.is_absolute() and '..' not in python.parts, 'absolute Python path required')
    safe(python.parent)
    target = safe(python.resolve(strict=True))
    require(target.is_file() and digest(target) == source.python_target,
            'explicit Python interpreter target pin differs')
    require(root.is_relative_to(project/'tmp'), 'fresh setup must stay in the authorized workspace tmp')
    require(type(protected_roots) is tuple and protected_roots, 'explicit protected fixture roots required')
    for retained_root in protected_roots:
        retained_root = safe(retained_root)
        require(not root.is_relative_to(retained_root) and not retained_root.is_relative_to(root),
                'fresh setup overlaps retained custody')
    require(not root.exists(), 'fresh setup root must not exist; no copy/merge/restore')
    require(type(starts) is tuple and tuple(name for name, _ in starts) == REGIONS
            and type(carriers) is tuple and type(relay_ports) is tuple,
            'immutable ordered setup inputs required')
    require(reference.caps == (('earth', 27), ('proxima', 24), ('andromeda', 24))
            and (reference.stage_seconds, reference.round_seconds, reference.max_new_heights,
                 reference.maturity, reference.quorum) == (600, 60, 24, 2, 3),
            'original scope limits required')
    caps = dict(reference.caps)
    for region, height in starts:
        require(type(height) is int and 0 <= height < caps[region], 'fresh starting height outside cap')
    require(len(carriers) == 12 and all(type(c) is Carrier for c in carriers)
            and tuple((c.region, c.index) for c in carriers) == SLOTS,
            'twelve ordered declared carriers required')
    require(len({c.node for c in carriers}) == len({c.certificate for c in carriers}) == 12,
            'distinct fresh transport identities and TLS pins required')
    for c in carriers:
        require(hex32(c.node) != '0'*64 and hex32(c.certificate) != '0'*64,
                'complete transport pins required')
    ports = tuple(c.port for c in carriers) + relay_ports
    require(len(relay_ports) == 2 and len(set(ports)) == 14
            and all(type(port) is int and 1 <= port <= 65535 for port in ports),
            'distinct literal listener and two directed outage ports required')
    require(tuple((p.region, p.index) for p in reference.replicas) == SLOTS,
            'reference custody slots differ')
    members = {region: tuple(p.key for p in reference.replicas if p.region == region)
               for region in REGIONS}
    for keys in members.values():
        require(len(keys) == 4 and keys == tuple(sorted(set(keys))), 'ordered four-member profile required')
    parent = dict(starts)['earth']
    while members['earth'][parent % 4] != members['earth'][0]:
        parent += 1
    gate = parent + 1
    require(gate <= caps['earth'] and gate - dict(starts)['earth'] <= 24,
            'missing leader exceeds original cap')
    # These are required future Native-reviewed requests, not allocated balances.
    # Remote regions have no origin issuance. Their local2 inputs must come from
    # real mature imported value, never owner20 rewards or a fabricated fixture coin.
    funding = (Funding('earth', source_owner, recipient, 10, 11, 'proxima'),
               Funding('proxima', source.remote_miner, local_recipient, 1, 2),
               Funding('andromeda', source.remote_miner, local_recipient, 1, 2))
    by_slot = {(c.region, c.index): c for c in carriers}
    configs = []
    for phase in PHASES:
        for region, n in SLOTS:
            local = by_slot[region, n]
            neighbors = [(region, j) for j in range(4) if abs(j-n) == 1]
            if n == 1:
                index = REGIONS.index(region)
                neighbors += [(other, 1) for j, other in enumerate(REGIONS) if abs(j-index) == 1]
            contacts = []
            for other in neighbors:
                peer = by_slot[other]
                port = peer.port
                if (region, n, *other) == ('earth', 1, 'proxima', 1):
                    port = relay_ports[0]
                elif (region, n, *other) == ('proxima', 1, 'earth', 1):
                    port = relay_ports[1]
                contacts.append(dict(peer=peer.node, host='127.0.0.1', port=port,
                                     tls_cert_sha256=peer.certificate))
            mesh = dict(format='RLD-CONTACT-MESH-V3', state=str(root/'mesh'/f'{region}-{n}'),
                        network=fresh_currency, contacts=contacts)
            key_file = root/region/f'public-fixture-key-{n}.json'
            if phase == 'keyless-drain':
                key_file = root/'keyless-absent'/f'{region}-{n}.json'
            bft = dict(format='RLD-REGIONAL-BFT-NODE-V1',
                state=str(root/'runtime'/f'{region}-{n}'),
                signer_dir=str(root/region/f'voter-{n}'),
                head_file=str(root/region/f'caller-{n}'/'head.json'),
                key_file=str(key_file), key=members[region][n],
                miner=source.origin_miner if region == 'earth' else source.remote_miner,
                validators=[dict(key=key, node_id=by_slot[region,j].node)
                            for j,key in enumerate(members[region])],
                block_interval=1, round_timeout=60, stop_height=caps[region])
            mesh_path = root/'configs'/phase/f'mesh-{region}-{n}.json'
            bft_path = root/'configs'/phase/f'bft-{region}-{n}.json'
            argv = (str(binary), '--dir', str(root/region/f'native-{n}'),
                    '--authority', source.authority, '--currency', fresh_currency,
                    '--mesh-config', str(mesh_path), '--bft-config', str(bft_path),
                    '--mesh-listen', f'127.0.0.1:{local.port}',
                    '--transport-python', str(python), '--interval', '0.25')
            configs.append(Config(phase,region,n,not (phase == PHASES[0] and (region,n)==('earth',0)),
                                  encoded(mesh),encoded(bft),argv))
    return Blueprint(str(root),fresh_currency,source,tuple(configs),funding,gate,starts,
                     reference.caps,relay_ports)
