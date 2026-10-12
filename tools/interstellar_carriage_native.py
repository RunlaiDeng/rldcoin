"""Stateless native candidate planning with original ordered native eligibility."""
import ctypes
import hashlib
import struct
import interstellar_crypto as crypto
from interstellar_routing_native import _id
CODEC=b'RLD-FIRST-CARRIAGE-BYTES-V1\0'
FORMAT='RLD-NATIVE-FIRST-CARRIAGE-V1'
MAX_BYTES=64*1024
MAX_CHECKS=1056
CALLBACK=ctypes.CFUNCTYPE(ctypes.c_int32,ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t,ctypes.c_void_p)

def _rows(values,limit):
    if type(values) is not list or len(values)>limit or any(type(v) is not str for v in values) or len(set(values))!=len(values):raise ValueError('carriage row capacity/schema')
    return struct.pack('>H',len(values))+b''.join(_id(v) for v in values)
def _optional(value):return b'\0' if value is None else b'\1'+_id(value)
def _encode(node,peer,maximum,recent_limit):
    if type(maximum) is not int or not 0<=maximum<=256 or type(recent_limit) is not int or not 0<=recent_limit<=32:raise ValueError('carriage limits differ')
    value=node.state['first_carriage'][peer]
    if set(value)!={'pending','prepared','arrivals','observed','history_after','next_kind'}:raise ValueError('carriage fields differ')
    kind=value['next_kind']
    if type(kind) is not int or not 0<=kind<=1:raise ValueError('carriage kind differs')
    parts=[CODEC,struct.pack('>H',maximum),bytes([recent_limit]),_id(node.network),_id(node.id),_id(peer)]
    for values,limit in [(list(node.state['messages']),maximum),(list(node.state['receipts']),maximum),
            (node.state['recent_transits'],recent_limit),(node.state['first_arrivals'],maximum),
            (value['pending'],recent_limit),(value['prepared'],maximum),(value['arrivals'],maximum)]:parts.append(_rows(values,limit))
    parts.append(b'\0' if value['observed'] is None else b'\1'+_rows(value['observed'],maximum))
    parts.extend([_optional(value['history_after']),bytes([kind])]);raw=b''.join(parts)
    if len(raw)>MAX_BYTES:raise ValueError('carriage byte bound')
    return raw

def _invoke(raw,eligible):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:raise ValueError('carriage byte bound')
    engine=crypto.backend();domain=crypto.validation_domain()
    digest=hashlib.sha256(CODEC+b'ELIGIBILITY-V1\0');observed=[];errors=[]
    def check(pointer,size,context):
        try:
            if errors or size!=32 or not pointer or context is not None or len(observed)>=MAX_CHECKS:raise ValueError('carriage callback binding/capacity')
            if crypto.validation_domain()!=domain:raise ValueError('carriage eligibility provider differs')
            raw_id=ctypes.string_at(pointer,size);ident=raw_id.hex();value=eligible(ident)
            if type(value) is not bool:raise ValueError('carriage eligibility boolean differs')
            if crypto.validation_domain()!=domain:raise ValueError('carriage eligibility provider differs')
            digest.update(raw_id+bytes([value]));observed.append((ident,value));return int(value)
        except BaseException as error:
            if not errors:errors.append(error)
            return -1
    callback=CALLBACK(check);operation=engine.library.rld_contact_first_carriage
    operation.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t,CALLBACK,ctypes.c_void_p];operation.restype=crypto.Buffer
    try:result=engine.invoke_raw(operation,raw,callback,None)
    except BaseException:
        if errors:raise errors[0]
        raise
    if errors:raise errors[0]
    if crypto.validation_domain()!=domain:raise ValueError('carriage eligibility provider differs')
    if (type(result) is not dict or set(result)!={'format','network','node','peer','plan','eligibility_count','eligibility_sha256',
            'candidate_only','ledger_authority','custody_acknowledgment'} or result['format']!=FORMAT
            or type(result['eligibility_count']) is not int or result['eligibility_count']!=len(observed)
            or result['eligibility_sha256']!=digest.hexdigest() or result['candidate_only'] is not True
            or result['ledger_authority'] is not False or result['custody_acknowledgment'] is not False):raise ValueError('carriage result/callback binding differs')
    return result,observed

def first_carriage_plan(node,peer):
    import interstellar_mesh as mesh
    raw=_encode(node,peer,mesh.MAX_MESSAGES,mesh.MAX_RECENT_TRANSITS)
    value=node.state['first_carriage'][peer];active=node.state['messages'];receipted=node.state['receipts']
    def eligible(ident):
        if ident not in active or ident in receipted:return False
        transit=active[ident];packet,_,visited=mesh.transit_check(transit,node.network,include_frame=False);route=node.route(packet['destination'],visited[:-1],first_hop=peer)
        return bool(route and len(route)>=2 and route[1]==peer and len(transit['hops'])+len(route)-1<=packet['hop_limit'])
    result,observations=_invoke(raw,eligible)
    if result['network']!=node.network or result['node']!=node.id or result['peer']!=peer:raise ValueError('carriage role binding differs')
    plan=result['plan']
    if type(plan) is not dict or set(plan)!=set(value):raise ValueError('carriage plan fields differ')
    for name,limit in [('pending',mesh.MAX_RECENT_TRANSITS),('prepared',mesh.MAX_MESSAGES),('arrivals',mesh.MAX_MESSAGES),('observed',mesh.MAX_MESSAGES)]:
        _rows(plan[name],limit)
        if any(ident not in active for ident in plan[name]):raise ValueError('carriage plan active binding differs')
    if (plan['observed']!=sorted(active) or plan['prepared']!=[ident for ident in value['prepared'] if ident in active]
            or set(plan['pending'])&set(plan['prepared']) or set(plan['arrivals'])&(set(plan['pending'])|set(plan['prepared']))):raise ValueError('carriage plan retained binding differs')
    checked={ident for ident,allowed in observations if allowed}
    if not set(plan['pending']+plan['arrivals'])<=checked:raise ValueError('carriage plan eligibility binding differs')
    _optional(plan['history_after'])
    if plan['history_after']!=value['history_after'] and plan['history_after'] not in checked:raise ValueError('carriage history position differs')
    if type(plan['next_kind']) is not int or not 0<=plan['next_kind']<=1:raise ValueError('carriage next kind differs')
    return plan
