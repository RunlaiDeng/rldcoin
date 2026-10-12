"""Native complete packet/frame/route/hop composition; no ledger authority."""
import base64
import interstellar_crypto as crypto
import interstellar_frame_native as opaque
import interstellar_transfer as wire
FORMAT='RLD-NATIVE-CONTACT-TRANSIT-V1'

def _limits():
    import interstellar_mesh as mesh
    if type(mesh.MAX_HOPS) is not int or not 0<=mesh.MAX_HOPS<=16:
        raise ValueError('native transit limits differ')
    opaque._profile()
    return dict(hops=mesh.MAX_HOPS,**opaque._limits())

def _check(mode,value,network,recipient=None,sender=None):
    fields=dict(network=network,limits=_limits())
    if mode=='packet':request={'Packet':dict(fields,signed=value)};signed=value
    else:request={'Check':dict(fields,transit=value,recipient=recipient,sender=sender)};signed=value.get('packet') if type(value) is dict else None
    result=crypto.backend().call({'Transit':request})
    if (type(result) is not dict or set(result)!={'format','mode','network','body','frame','visited',
        'transport_authenticated','ledger_authority','custody_acknowledgment'}
        or result['format']!=FORMAT or result['mode']!=mode or result['network']!=network
        or result['transport_authenticated'] is not True or result['ledger_authority'] is not False
        or result['custody_acknowledgment'] is not False or type(signed) is not dict
        or type(result['body']) is not dict or result['body']!=signed.get('body')
        or type(result['frame']) is not dict or type(result['visited']) is not list):
        raise ValueError('native transit receipt binding differs')
    body=result['body'];raw=base64.b64decode(body['frame'],validate=True)
    frame=wire.decode_json(raw)
    expected=[] if mode=='packet' else [body['node_id']]+[hop['body']['to'] for hop in value['hops']]
    if result['frame']!=frame or result['visited']!=expected:
        raise ValueError('native transit assembled frame/path differs')
    return body,raw,frame,result['visited']

def packet(value,network):
    body,raw,frame,_=_check('packet',value,network)
    return body,raw,frame

def transit(value,network,recipient=None,sender=None):
    body,raw,_,visited=_check('transit',value,network,recipient,sender)
    return body,raw,visited
