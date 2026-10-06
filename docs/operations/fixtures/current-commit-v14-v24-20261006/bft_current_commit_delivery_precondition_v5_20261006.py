"""Ordinary signed ground-delivery prerequisite; never ledger authority.

This guard only reads public/source evidence. Missing, failed or source-changed
proof refuses before any Native/Runtime/fixture imports or allocation.
"""
from pathlib import Path
import hashlib
import json

PROJECT=Path('/Users/galaxy/GitHub/rldcoin')
EVIDENCE=PROJECT/'docs/operations/evidence'
BASE=PROJECT/'tmp/default-relay-20260930'
RECEIPT=EVIDENCE/'regional-bft-current-commit-delivery-qualified-v14-20261006.json'
CHECKS=EVIDENCE/'regional-bft-current-commit-delivery-v14-qualified-checks-20261006.json'
STAGE=EVIDENCE/'regional-bft-current-commit-delivery-v14-qualified-stage-20261006.json'
HELPER=BASE/'observe-bft-current-commit-delivery-final-v14-20261006.py'
IDENTITY=EVIDENCE/'regional-bft-current-commit-v14-identity-20261006.json'
STATIC=EVIDENCE/'regional-bft-current-commit-delivery-v14-static-checks-20261006.json'
STATIC_STAGE=EVIDENCE/'regional-bft-current-commit-delivery-v14-static-stage-20261006.json'

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def read_json(path):
    require(path.is_absolute() and '..' not in path.parts
            and not any(p.is_symlink() for p in (path,*path.parents)),
            'ordinary delivery proof path refused')
    require(path.is_file(),'ordinary signed delivery remains unqualified')
    require(path.stat().st_size<=1024*1024,'ordinary delivery proof byte capacity')
    raw=path.read_bytes()
    def unique(pairs):
        out={}
        for key,value in pairs:
            require(key not in out,'ordinary delivery duplicate proof field')
            out[key]=value
        return out
    def constant(value):raise ValueError('ordinary delivery nonfinite proof number')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=constant),sha(raw)

def require_current_delivery():
    require(Path.cwd()==PROJECT,'ordinary delivery explicit migrated cwd')
    receipt,_=read_json(RECEIPT)
    require(type(receipt) is dict and set(receipt)=={'format','completed','python_source_commitment',
            'checks_sha256','stage_sha256'} and receipt['format']=='RLD-ORDINARY-SIGNED-DELIVERY-QUALIFICATION-V1'
            and receipt['completed'] is True,'ordinary signed delivery receipt refused')
    checks,checks_hash=read_json(CHECKS);stage,stage_hash=read_json(STAGE)
    identity,_=read_json(IDENTITY);static,_=read_json(STATIC);static_stage,static_stage_hash=read_json(STATIC_STAGE)
    require(receipt['checks_sha256']==checks_hash and receipt['stage_sha256']==stage_hash
            and checks['stage_sha256']==stage_hash,'ordinary delivery exact proof differs')
    require(receipt['python_source_commitment']==identity['python_source_commitment'],
            'ordinary delivery source commitment differs')
    require(checks['completed'] is True and checks['helper_exit_code']==0
            and checks['failure'] is None and checks['pin_error']==[]
            and checks['original_budget_seconds']==60
            and type(checks['combined_stage_seconds']) in (int,float)
            and 0<checks['combined_stage_seconds']<=60,'ordinary delivery failed or over budget')
    require(static['completed'] is True and static['result']['all_actual_global_providers_resolved']
            and static_stage_hash==static['stage_sha256']
            and static_stage['protected_sha256'].get(str(HELPER))==checks['helper_sha256']
            and sha(HELPER.read_bytes())==checks['helper_sha256'],'ordinary delivery qualified helper differs')
    result=checks['result'];delivery=result['ordinary_delivery']
    require(result['completed'] is True and result['tests_run']==1 and not result['failed_tests']
            and not result['error_tests'] and result['current_profile']==identity['profile']
            and result['fresh_ground_only'] is True and result['old_failed_fixture_reopens']==0
            and result['actual_Native_Runtime_TLS_calls']==0
            and result['original_pending_pair_full4_auth_atomic_floor_cold_checked_on_this_same_target'] is True,
            'ordinary delivery original guards refused')
    for key in ('ordinary_source_tick_count','destination_ordinary_tick_count'):
        require(type(delivery[key]) is int and delivery[key]==1,'ordinary delivery original finite ticks')
    for key in ('source_signed_packet_routing_bytes_exact','complete_hop_and_destination_receipt_authenticated',
                'destination_cold_open_with_transit_witnesses_cleared','ground_source2_destination1_role_analogue'):
        require(delivery[key] is True,'ordinary delivery complete signed cold proof missing')
    require(delivery['original_frame_sha256']==delivery['destination_original_frame_export_sha256']
            and delivery['original_failed_Native_Proposal_copied_or_signed'] is False
            and delivery['Native_Proposal_inner_signature_or_ledger_maturity_qualified'] is False,
            'ordinary delivery evidence or authority differs')
    sources=identity['python_source_sha256'];require(len(sources)==192,'ordinary delivery full Python source set')
    require(stage['actual_source_changes']==[],'ordinary delivery source changed during prerequisite')
    for name,digest in sources.items():
        path=PROJECT/name
        require(stage['protected_sha256'].get(str(path))==digest and sha(path.read_bytes())==digest,
                'ordinary delivery source changed')
    require(checks['new180_allocated']==checks['new600_allocated']==0
            and result['new180_allocated']==result['new600_allocated']==0
            and checks['full_fault_qualified'] is False and checks['whole_goal_completed'] is False,
            'ordinary ground delivery is not Native allocation or goal authority')
    return receipt


ALLOCATED=EVIDENCE/'regional-bft-four-cli-current-commit-v24-decision-allocated-20261006.json'
CONTRACT=BASE/'first_service_diagnostic_entry_contract_v12_20261006.json'
NATIVE_HELPER=BASE/'observe-bft-four-cli-service-first-service-diag-v24-20261006.py'
NATIVE_CONTROLLER=BASE/'check-bft-four-cli-service-first-service-diag-v24-allocated-preview-20261006.py'

def require_native_allocation():
    require(ALLOCATED.is_file(),'Native180 scope remains unallocated')
    allocation,_=read_json(ALLOCATED);contract,contract_hash=read_json(CONTRACT);identity,_=read_json(IDENTITY)
    require(type(allocation) is dict and allocation.get('format')=='RLD-UNSERVED-PRIORITY-NATIVE-ALLOCATION-V1'
            and allocation.get('task_id')=='01a100ac-5340-7b13-b661-eedc397b003a'
            and allocation.get('owner_authorized') is True and allocation.get('completed') is True,
            'Native180 needs explicit owner scope decision')
    for field,value in [('new180_allocated',1),('new600_allocated',0),('budget_seconds',180),('attempts',1),
                        ('owner_first_signs',1),('old_failed_reopens',0),('custody_copies',0)]:
        require(type(allocation.get(field)) is int and allocation[field]==value,'Native original allocation limits')
    require(allocation.get('root')==contract['root']
            and json.dumps(allocation.get('original_parameters'),sort_keys=True,separators=(',',':'),allow_nan=False)
                ==json.dumps(contract['original_parameters'],sort_keys=True,separators=(',',':'),allow_nan=False)
            and allocation.get('python_source_commitment')==identity['python_source_commitment']
            and allocation.get('native_implementation')==identity['implementation']
            and allocation.get('core_source_commitment')==identity['core_source_commitment']
            and allocation.get('actual_binary_sha256')==identity['actual_cli_sha256'],
            'Native original source or bounds allocation differs')
    require(allocation.get('helper_sha256')==sha(NATIVE_HELPER.read_bytes())
            and allocation.get('controller_sha256')==sha(NATIVE_CONTROLLER.read_bytes())
            and allocation.get('contract_sha256')==contract_hash
            and allocation.get('delivery_receipt_sha256')==sha(RECEIPT.read_bytes()),
            'Native reviewed source allocation differs')
    root=Path(contract['root'])
    require(root==BASE/'native-bft-four-cli-service-first-service-diag-v24-private-20261006'
            and not root.exists(),'Native failed or existing fixture cannot reopen')
    return allocation

def require_ready_native_scope():
    receipt=require_current_delivery()
    allocation=require_native_allocation()
    return receipt,allocation
