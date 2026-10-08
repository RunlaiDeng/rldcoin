"""One locked Native signature/envelope; independent caller persistence first.

No fallback after a mutating attempt. Failed output retains the original native
response/head for existing recover-only; no serialized status authorizes voting.
"""
import hashlib
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_local_envelope import check

FORMAT='RLD-BFT-SIGN-LOCAL-ENVELOPE-V1'
MAX_BYTES=8*1024*1024


def sign(runtime,request,native_head):
    mesh.hex32(native_head)
    raw=wire.canonical(request)
    mesh.require(0<len(raw)<=wire.MAX_PAYLOAD,'composed request payload bound')
    result=runtime.with_json('bft-sign-local-envelope',request,
        '--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
        '--expected-native-head',native_head,'--expected-key',runtime.key,
        '--key-file',runtime.key_file)
    mesh.require(type(result) is dict and set(result)=={'format','currency','region','request_sha256',
        'native_history_head','signed','status','envelope','checked','signature_retained',
        'carriage_released','ledger_changed','independent_freshness_qualified'}
        and len(wire.canonical(result))<=MAX_BYTES and result['format']==FORMAT
        and result['currency']==runtime.native.currency and result['region']==runtime.region
        and result['request_sha256']==hashlib.sha256(raw).hexdigest()
        and result['native_history_head']==native_head and result['signature_retained'] is True
        and result['carriage_released'] is False and result['ledger_changed'] is False
        and result['independent_freshness_qualified'] is False,'composed Native response binding differs')
    signed=result['signed'];status=result['status']
    mesh.require(type(signed) is dict and set(signed)=={'message','previous_head','head','recovered_exact_retry'}
        and type(signed['recovered_exact_retry']) is bool,'composed signed response shape differs')
    mesh.hex32(signed['head']);mesh.hex32(signed['previous_head'])
    mesh.require(signed['previous_head']==runtime.head['head'] or
        signed['recovered_exact_retry'] is True and signed['head']==runtime.head['head'],
        'composed signed response previous head differs')
    mesh.require(type(status) is dict and set(status)=={'binding','creation','head','state','records',
        'external_rollback_anchor_qualified'} and status['binding']==runtime.signing_binding
        and status['head']==signed['head'] and status['external_rollback_anchor_qualified'] is False
        and type(status['records']) is int and 0<=status['records']<=4096
        and (status['state'] is None or type(status['state']) is dict),
        'composed current signer observation differs')
    envelope,checked=check(runtime,{'Signed':signed['message']},result['envelope'],result['checked'])
    return signed,envelope,checked,status
