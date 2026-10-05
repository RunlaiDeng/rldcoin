"""Explicit read-only prepared-source binding; metadata never authorizes value.

Fully pinned Native history replay follows the exact successful preparation's
source/inventory/custody evidence. No Runtime, recovery, first-sign, socket or
private-store initialization. Returned configurations still grant no launch right.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_bft_pinned_cold import checked_history
from regional_contact_campaign import public
from regional_paged_fault_launch import Config, PHASES, SLOTS, encoded
from regional_paged_fault_preflight import HistoryOnly
from regional_paged_fault_scope import REGIONS, RULES, ReplicaPin, Scope, digest, document, hex32, inventory, raw, require, safe


@dataclass(frozen=True)
class Pins:
    checks: str
    stage: str
    inventory: str
    native_source: str
    implementation: str
    binary: str
    core: str
    currency: str
    python_target: str


@dataclass(frozen=True)
class Bound:
    root: str
    output: str
    currency: str
    configs: tuple
    native_history_checks: int
    missing_leader_gate: int
    preparation_inventory: str
    stage_seconds: int = 600
    round_seconds: int = 60
    new_height_limit: int = 24
    maturity: int = 2
    quorum: int = 3
    network_authority: bool = False
    signing_authority: bool = False
    independent_freshness: bool = False


def native_matches(current, retained):
    require(all(current.get(k) == retained[k] for k in
        ('history_head','currency','region','height','tip','state','finality','validator_epoch')),
        'Native current complete checkpoint differs from retained preparation')
    require(current['logical_native_replay_complete'] is True
        and current['fixture_only'] is True and current['live_rld'] is False
        and current['independent_latest_state_anchor_qualified'] is False,
        'Native preparation observation grants no external freshness')


def ports_valid(ports, relays):
    require(type(ports) is tuple and type(relays) is tuple and len(ports)==12 and len(relays)==2,
            'explicit twelve endpoints/two directed relay endpoints required')
    require(len(set(ports+relays))==14 and all(type(n) is int and 1<=n<=65535 for n in ports+relays),
            'distinct literal endpoint ports required; no learned endpoint')


def transport_pin(root, label, n, currency, region):
    record = document(root/'transport-preparation'/f'{label}-{n}.json')
    config, pin = record['config'], record['pin']
    directory = root/'mesh'/f'{label}-{n}'
    require(config == dict(format=mesh.VERSION,state=str(directory),network=currency,contacts=[])
            and pin['network']==currency, 'actual fresh mesh setup binding differs')
    identity = document(directory/'identity.private.json')
    require(set(identity)=={'format','network','region','label','public_key','private_key',
            'transit_scheduler','active_storage','archive_storage','receipt_scheduler'}
        and identity['format']==mesh.VERSION and identity['network']==currency
        and identity['region']==region and identity['transit_scheduler']==mesh.TRANSIT_SCHEDULER
        and identity['active_storage']==mesh.ACTIVE_STORAGE and identity['archive_storage']==mesh.ARCHIVE_STORAGE
        and identity['receipt_scheduler']==mesh.RECEIPT_SCHEDULER,
        'actual transport identity/domain differs')
    require((directory/'identity.private.json').stat().st_mode&0o077==0, 'private mesh permissions')
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex32(identity['private_key'])))
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    require(pub==identity['public_key'] and mesh.node_id(pub)==pin['node_id'], 'actual mesh identity pin differs')
    pem_path=directory/'tcp-tls.private.pem'; pem=raw(pem_path,8192)
    require(pem_path.stat().st_mode&0o077==0, 'private TLS permissions')
    certificate=x509.load_pem_x509_certificate(pem)
    tls_key=serialization.load_pem_private_key(pem,password=None)
    require(isinstance(tls_key,Ed25519PrivateKey), 'TLS key algorithm')
    tcp.certificate_check(certificate,currency,pin['node_id'])
    require(tls_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        ==certificate.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),
        'actual TLS certificate/private key differs')
    canonical=certificate.public_bytes(serialization.Encoding.PEM)+tls_key.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    require(canonical==pem and hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        ==pin['tls_cert_sha256'] and certificate.not_valid_after_utc.isoformat()==pin['certificate_valid_until_utc'],
        'actual exact TLS material/fingerprint differs')
    return pin


def bind(project, root, output, checks_path, stage_path, retained_path, binary, python,
         pins, ports, relays, deadline):
    """All external pins are reviewed observations, never sampled current heads.

    Original preparation custody/envelope/owner qualification is reused only under
    exact complete source and inventory. Native replays each retained latest head
    independently; no metadata or ledger cache initializes any Native authority.
    This function does not create output or modify any private custody directory.
    """
    require(type(pins) is Pins, 'explicit immutable prepared provenance pins required')
    for value in vars(pins).values():require(hex32(value)!='0'*64,'nonzero prepared pin required')
    project,root,output,binary=map(safe,(project,root,output,binary))
    require(project==Path('/Users/galaxy/GitHub/rldcoin') and root.is_relative_to(project/'tmp')
        and output.is_relative_to(project/'tmp') and not output.exists()
        and not output.is_relative_to(root) and not root.is_relative_to(output),
        'separate fresh configuration output required; no existing-root shortcut')
    ports_valid(ports,relays)
    checks=document(checks_path,pins.checks);stage=document(stage_path,pins.stage)
    retained=document(retained_path,pins.inventory)
    require(set(retained)=={str(root)} and len(retained[str(root)])==668
        and inventory(root)==retained[str(root)], 'exact complete prepared668-file inventory differs')
    require(checks['format']=='RLD-PAGED-FAULT-NATIVE-PREPARATION-CHECKS-V1'
        and checks['completed'] is True and checks['helper_exit_code']==0 and checks['helper_terminal'] is True
        and checks['pin_error'] is None and checks['budget_exhausted'] is False
        and checks['old_private_source_freeze_unchanged'] is True
        and checks['failed_currency_sealed'] is False and checks['old_custody_copied'] is False
        and checks['private_inventory_sha256']==pins.inventory and checks['stage_sha256']==pins.stage
        and stage['budget_seconds']==checks['budget_seconds']==180
        and stage['attempts']==checks['attempts_used']==1 and 0<checks['duration_seconds']<180
        and stage['new_private_root']==str(root) and stage['new_root_absent'] is True,
        'only exact clean successful fresh preparation is eligible')
    require(stage['stage_seconds']==600 and stage['round_seconds']==60 and stage['new_height_limit']==24
        and stage['absolute_height_caps']==dict(earth=27,proxima=24,andromeda=24)
        and stage['maturity']==2 and stage['quorum']==3
        and stage['network_budget']==stage['runtime_budget']==stage['private_copy_budget']==0,
        'original scope limits or zero-network preparation differs')
    for field,value in (('source_commitment',pins.native_source),('implementation',pins.implementation),
                        ('cli_binary_sha256',pins.binary)):
        require(stage[field]==checks[field]==value,'prepared Native implementation identity differs')
    require(stage['core_171_commitment']==pins.core and digest(binary)==pins.binary,
            'actual Native binary/Core identity differs')
    for path,expected in stage['protected_sha256'].items():
        require(digest(path)==expected,'complete prepared source/controller/evidence/freeze binding differs')
    # Reject output below any historical protected fixture, not only current root.
    for path,expected in stage['private_inventory_sha256'].items():
        for old in document(path,expected):
            old=safe(old)
            require(not output.is_relative_to(old) and not old.is_relative_to(output),
                    'configuration output overlaps sealed/stopped private custody')
    python=Path(python);require(python.is_absolute() and '..' not in python.parts,'explicit venv path required')
    safe(python.parent);require(digest(safe(python.resolve(strict=True)))==pins.python_target,
                              'resolved actual Python interpreter pin differs')
    creation=document(root/'fresh-creation.json');observation=document(root/'native-prepared-observation.json')
    require(creation['root_absent_before_creation'] is True and creation['copies']==creation['network_starts']==0
        and creation['controller_preparation_only'] is True and creation['fixture_only'] is True
        and creation['live_rld'] is False and creation['implementation']==pins.implementation
        and creation['binary_sha256']==pins.binary and creation['inode']==root.stat().st_ino
        ==observation['root_inode'],'exact fresh Native creation provenance differs')
    require(observation['format']=='RLD-PAGED-FAULT-NATIVE-PREPARED-OBSERVATION-V1'
        and observation['currency']==pins.currency and observation['implementation']==pins.implementation
        and observation['rules']==RULES and observation['controller_preparation_only'] is True
        and observation['network_starts']==0 and observation['full_fault_qualified'] is False
        and observation['independent_freshness'] is False and observation['launch_authority'] is False
        and observation['configuration_bound'] is False,'actual prepared observation/profile differs')
    result=checks['result']
    require(result['completed'] is True and result['native_replicas']==result['voter_caller_pairs']==12
        and result['zero_allocation_from_fresh_signed_genesis'] is True
        and result['no_state_or_value_copy'] is True and result['preparation_owner_first_signs']==3
        and result['fault_owner_first_signs']==0 and result['unsigned_fault_reviews']==3
        and result['destination_receipts_fully_native_verified']==8 and result['maturity']==2
        and result['native_accounting']['conserved'] is True
        and result['fresh_mesh_tls_identities']==12 and result['fresh_tls_reopen_retention'] is True
        and result['network_starts']==result['runtime_starts']==0
        and result['full_fault_qualified'] is False,'complete Native preparation behavior differs')
    bootstrap=document(root/'signed-fresh-bootstrap.json')
    require(bootstrap['currency']['implementation']==pins.implementation
        and bootstrap['currency']['fixture_only'] is True and bootstrap['currency']['maturity']==2
        and bootstrap['currency']['cap']==str(10**35)
        and bootstrap['currency']['block_reward']==str(250000*10**24)
        and len(bootstrap['admissions'])==3,'exact signed preparation bootstrap required')
    authority=bootstrap['currency']['authority'];hex32(authority)
    replicas=[];carriers=[]
    require(len(observation['heads'])==12 and len(observation['transport_pins'])==12,'complete prepared slots required')
    for index,(label,n) in enumerate(SLOTS):
        admission=bootstrap['admissions'][REGIONS.index(label)]
        require(admission['currency']==pins.currency and admission['rules']==RULES
            and admission['validators']==sorted(public(k) for k in range(2,6)), 'explicit original paged membership')
        head=document(root/label/f'observed-native-head-{n}.json')
        require(head==observation['heads'][index] and head['currency']==pins.currency
            and head['height']==result['actual_heights'][label][n]
            and head['height']==dict(earth=8,proxima=5,andromeda=5)[label], 'actual ordered prepared Native height/head')
        caller=document(root/label/f'caller-{n}'/'head.json')
        header=document(root/label/f'native-{n}'/'ledger-header.json')
        voter=document(root/label/f'voter-{n}'/'bft-header.json')
        require(header['bootstrap']==bootstrap and header['region']==head['region']
            and header['format']==head['format']=='RLD-NATIVE-PAGED-BFT-STORE-V1'
            and voter['format']=='RLD-NATIVE-PAGED-BFT-SIGNER-V1'
            and voter['journal']['binding']==caller['binding']
            and caller['binding']==dict(currency=pins.currency,region=head['region'],key=admission['validators'][n])
            and caller['pending'] is None and caller['outbox'] is None,'exact original Native/voter/caller custody')
        replica=ReplicaPin(label,n,head['height'],head['history_head'],caller['head'],caller['binding']['key'],head['region'])
        for value in (replica.history_head,replica.caller_head,replica.region_id):hex32(value)
        native=HistoryOnly(project,binary,root/label/f'native-{n}',authority,pins.currency,replica.history_head,deadline)
        native_matches(checked_history(native,replica.history_head),head)
        replicas.append(replica)
        pin=transport_pin(root,label,n,pins.currency,head['region'])
        require(pin==observation['transport_pins'][index],'ordered retained transport pin differs')
        carriers.append(pin)
    require(len({p['node_id'] for p in carriers})==len({p['tls_cert_sha256'] for p in carriers})==12,
            'actual unique transport slots differ')
    require(len(observation['funding'])==3,'three complete unsigned fault owners required')
    for index,(label,seed,recipient,amount) in enumerate((('earth',13,21,95),('proxima',20,15,2),('andromeda',20,16,2))):
        owner_root=root/'fault-owners'/label;review=document(owner_root/'unsigned-review.json')
        caller=document(owner_root/'caller'/'head.json');wallet=document(owner_root/'wallet'/'wallet.json')
        funding=observation['funding'][index];request=document(owner_root/'request.json')
        head=observation['heads'][REGIONS.index(label)*4]
        require(funding['region']==label and funding['first_signed'] is False and funding['amount']==str(amount)
            and type(funding['mature_height']) is int and funding['mature_height']<=head['height']
            and funding['native_height']==head['height'] and digest(owner_root/'unsigned-review.json')==funding['review_sha256']
            and caller['pending'] is None and caller['head']==funding['owner_head']==review['wallet_head']
            and caller['binding']==wallet['binding'] and wallet['records']==[]
            and caller['binding']==dict(currency=pins.currency,region=head['region'],owner=public(seed)),
            'exact retained unsigned owner custody/funding differs')
        expected=dict(owner=public(seed),inputs=[funding['input_id']],fee='1',valid_for_blocks=8,
            outputs=[] if label=='earth' else [dict(owner=public(recipient),amount='1')],
            remote=dict(destination=replicas[4].region_id,recipient=dict(owner=public(recipient),amount='10'),destination_fee='1')
                   if label=='earth' else None)
        require(request==review['draft']['request']==expected
            and review['draft']['input_owners']=={funding['input_id']:public(seed)}
            and review['draft']['input_amounts']=={funding['input_id']:str(amount)}
            and review['draft']['selected_input_total']==str(amount)
            and review['draft']['change']==str(84 if label=='earth' else 0)
            and all(review['draft']['pin'][k]==head[k] for k in ('currency','region','height','tip','state','finality')),
            'actual Native unsigned input/request/conservation review differs')
    scope=Scope(pins.currency,tuple(replicas),(('earth',27),('proxima',24),('andromeda',24)))
    gate=scope.missing_leader_gate('earth',replicas[0].key)
    require(gate==9 and not (root/'keyless-absent').exists(),'actual absent leader/keyless path differs')
    configs=[]
    for phase in PHASES:
        for index,(label,n) in enumerate(SLOTS):
            neighbor_slots=[(label,j) for j in range(4) if abs(j-n)==1]
            if n==1:neighbor_slots += [(other,1) for j,other in enumerate(REGIONS) if abs(j-REGIONS.index(label))==1]
            contacts=[]
            for other in neighbor_slots:
                j=SLOTS.index(other);port=ports[j]
                if (label,n,*other)==('earth',1,'proxima',1):port=relays[0]
                elif (label,n,*other)==('proxima',1,'earth',1):port=relays[1]
                contacts.append(dict(peer=carriers[j]['node_id'],host='127.0.0.1',port=port,
                                     tls_cert_sha256=carriers[j]['tls_cert_sha256']))
            mesh_config=dict(format=mesh.VERSION,state=str(root/'mesh'/f'{label}-{n}'),network=pins.currency,contacts=contacts)
            bft=dict(format='RLD-REGIONAL-BFT-NODE-V1',state=str(root/'runtime'/f'{label}-{n}'),
                signer_dir=str(root/label/f'voter-{n}'),head_file=str(root/label/f'caller-{n}'/'head.json'),
                key_file=str(root/'keyless-absent'/f'{label}-{n}.json') if phase=='keyless-drain'
                         else str(root/label/f'public-fixture-key-{n}.json'),key=replicas[index].key,
                miner=public(10 if label=='earth' else 20),
                validators=[dict(key=replicas[REGIONS.index(label)*4+j].key,
                    node_id=carriers[REGIONS.index(label)*4+j]['node_id']) for j in range(4)],
                block_interval=1,round_timeout=60,stop_height=dict(scope.caps)[label])
            argv=(str(binary),'--dir',str(root/label/f'native-{n}'),'--authority',authority,'--currency',pins.currency,
                '--mesh-config',str(output/phase/f'mesh-{label}-{n}.json'),
                '--bft-config',str(output/phase/f'bft-{label}-{n}.json'),
                '--mesh-listen',f'127.0.0.1:{ports[index]}','--transport-python',str(python),'--interval','0.25')
            configs.append(Config(phase,label,n,not (phase==PHASES[0] and (label,n)==('earth',0)),
                                  encoded(mesh_config),encoded(bft),argv))
    require(time.monotonic()<deadline and inventory(root)==retained[str(root)],
            'prepared source changed during Native binding or deadline exhausted')
    return Bound(str(root),str(output),pins.currency,tuple(configs),12,gate,pins.inventory)
