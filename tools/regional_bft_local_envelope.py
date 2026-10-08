"""One operation-local Native proof, pack and full wire verification."""
import hashlib
import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT='RLD-BFT-LOCAL-ENVELOPE-V1'
MAX_BYTES=8*1024*1024


def pack(runtime, body):
    raw=wire.canonical(body)
    mesh.require(0<len(raw)<=wire.MAX_PAYLOAD,'local Native body payload bound')
    result=runtime.with_json('bft-network-local-envelope',body)
    mesh.require(type(result) is dict and set(result)=={'format','currency','region',
        'request_sha256','envelope','checked','verified','ledger_changed','signing_authority'}
        and len(wire.canonical(result))<=MAX_BYTES and result['format']==FORMAT
        and result['currency']==runtime.native.currency and result['region']==runtime.region
        and result['request_sha256']==hashlib.sha256(raw).hexdigest()
        and result['verified'] is True and result['ledger_changed'] is False
        and result['signing_authority'] is False,'local Native response binding differs')
    envelope=result['envelope'];checked=result['checked']
    fields={'format','currency','region','evidence','body'}
    origin=type(envelope) is dict and envelope.get('format')=='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3'
    if origin:fields.add('origins')
    mesh.require(type(envelope) is dict and set(envelope)==fields
        and (envelope['format']=='RLD-REGIONAL-BFT-NETWORK-V2' or origin)
        and (not origin or type(envelope['origins']) is list and len(envelope['origins'])<=4)
        and envelope['currency']==runtime.native.currency and envelope['region']==runtime.region
        and wire.canonical(envelope['body'])==raw and len(wire.canonical(envelope))<=wire.MAX_PAYLOAD,
        'local complete Native envelope differs')
    mesh.require(type(checked) is dict and set(checked)=={'message_id','value','evidence','epochs'}
        and type(checked['evidence']) is dict and set(checked['evidence'])=={'snapshots'}
        and type(checked['evidence']['snapshots']) is list and len(checked['evidence']['snapshots'])<=64
        and type(checked['epochs']) is list and len(checked['epochs'])<=16,
        'local complete Native verification shape differs')
    mesh.hex32(checked['message_id'])
    if checked['value'] is not None:mesh.hex32(checked['value'])
    return envelope,checked
