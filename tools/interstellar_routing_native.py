"""Checked pure candidate BFS; the caller's full signed-state checks stay separate."""
import ctypes
import struct
import interstellar_crypto as crypto
FORMAT='RLD-NATIVE-CONTACT-ROUTING-V1'
CODEC=b'RLD-CANDIDATE-ROUTE-BYTES-V1\0'
MAX_BYTES=70*1024

def _id(value):
    if type(value) is not str or len(value)!=64:raise ValueError('invalid candidate identity')
    try:raw=bytes.fromhex(value)
    except ValueError as error:raise ValueError('invalid candidate identity') from error
    if raw.hex()!=value:raise ValueError('invalid candidate identity')
    return raw

def _encode(network,node,destination,excluded,first,outgoing,graph,nodes,contacts):
    if len(graph)>nodes or len(outgoing)>contacts or len(excluded)>1025:raise ValueError('native candidate graph capacity differs')
    parts=[CODEC,bytes([nodes,contacts]),_id(network),_id(node),_id(destination),bytes([first is not None])]
    if first is not None:parts.append(_id(first))
    parts += [struct.pack('>H',len(excluded)),b''.join(_id(v) for v in excluded),bytes([len(outgoing)]),b''.join(_id(v) for v in outgoing),bytes([len(graph)])]
    for key,peers in sorted(graph.items()):
        if type(peers) is not list or len(peers)>contacts:raise ValueError('native neighbor capacity differs')
        parts += [_id(key),bytes([len(peers)]),b''.join(_id(v) for v in peers)]
    raw=b''.join(parts)
    if len(raw)>MAX_BYTES:raise ValueError('candidate byte bound')
    return raw

def _invoke(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES:raise ValueError('candidate byte bound')
    engine=crypto.backend();operation=engine.library.rld_contact_routing_bytes
    operation.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t];operation.restype=crypto.Buffer
    return engine.invoke_raw(operation,raw)

def route(node,destination,excluded=(),first_hop=None):
    import interstellar_mesh as mesh
    if (type(mesh.MAX_NODES) is not int or not 0<=mesh.MAX_NODES<=64
        or type(mesh.MAX_CONTACTS) is not int or not 0<=mesh.MAX_CONTACTS<=16):
        raise ValueError('native routing limits differ')
    if destination==node.id:
        graph={};outgoing=[];excluded=[];first_hop=None
    else:
        graph={ident:advert['body']['neighbors'] for ident,advert in node.state['adverts'].items() if advert}
        outgoing=[peer for peer,contact in node.contacts.items() if mesh.outgoing_contact(contact)]
        excluded=list(excluded)
    raw=_encode(node.network,node.id,destination,excluded,first_hop,outgoing,graph,mesh.MAX_NODES,mesh.MAX_CONTACTS)
    result=_invoke(raw)
    if (type(result) is not dict or set(result)!={'format','network','node','destination','path','candidate_only',
        'labels_authenticated','ledger_authority','custody_acknowledgment','codec'} or result['format']!=FORMAT
        or result['codec']!=CODEC[:-1].decode('ascii') or result['network']!=node.network or result['node']!=node.id or result['destination']!=destination
        or result['candidate_only'] is not True or result['labels_authenticated'] is not False
        or result['ledger_authority'] is not False or result['custody_acknowledgment'] is not False):
        raise ValueError('native candidate route receipt differs')
    path=result['path']
    if path is not None:
        if (type(path) is not list or not 1<=len(path)<=65 or path[0]!=node.id or path[-1]!=destination
            or any(type(p) is not str for p in path) or len(set(path))!=len(path)):
            raise ValueError('native candidate path binding differs')
        if destination!=node.id:
            if (len(path)<2 or path[1] not in outgoing or first_hop is not None and path[1]!=first_hop
                or any(peer in excluded for peer in path[1:])
                or any(right not in graph.get(left,[]) for left,right in zip(path,path[1:]))):
                raise ValueError('native candidate edge/contact binding differs')
    return path
