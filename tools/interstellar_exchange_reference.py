"""Original signed exchange/TCP checks; independent Python signature tests only."""
import hashlib
import interstellar_mesh as real_mesh
import interstellar_transfer as wire
from interstellar_crypto_reference import verify_reference
from interstellar_schema_reference import inventory_check
class _MeshOracle:
    def __getattr__(self,name):
        if name=='verify':return verify_reference
        if name=='digest':return lambda value:hashlib.sha256(wire.canonical(value)).hexdigest()
        return getattr(real_mesh,name)
mesh=_MeshOracle()
verify=verify_reference
require=real_mesh.require
incoming_contact=real_mesh.incoming_contact
MAX_NODES=real_mesh.MAX_NODES
MAX_MESSAGES=real_mesh.MAX_MESSAGES
MAX_PACKET_BATCH=real_mesh.MAX_PACKET_BATCH
ADAPTER='RLD-CONTACT-TCP-V4'

def exchange_check(self, bundle, peer):
    body = verify(bundle, 'exchange', self.network)
    require(set(body) == {'format', 'network', 'node_id', 'to', 'adverts', 'transits', 'receipts', 'inventory'}
            and body['node_id'] == peer and body['to'] == self.id, 'wrong contact peer')
    require(peer in self.contacts and incoming_contact(self.contacts[peer]),
            'unconfigured incoming inventory peer')
    require(inventory_check(body['inventory'],self.network)['node_id']==peer,'exchange inventory differs from sender')
    for name, bound in [('adverts', MAX_NODES), ('transits', MAX_PACKET_BATCH), ('receipts', MAX_MESSAGES)]:
        require(isinstance(body[name], list) and len(body[name]) <= bound, 'exchange item limit')
    return body


def check_challenge(value, network, peer, fingerprint):
    body=mesh.verify(value,'tcp-challenge',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','nonce','tls_cert_sha256'}
        and body['adapter']==ADAPTER and body['node_id']==peer
        and body['tls_cert_sha256']==fingerprint,'TCP connection challenge binding mismatch')
    return mesh.hex32(body['nonce'])


def check_request(value, network, recipient, peers, connection_nonce):
    body = mesh.verify(value,'tcp-request',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','to','nonce','challenge','bundle'}
        and body['adapter']==ADAPTER and body['to']==recipient and body['node_id'] in peers
        and body['challenge']==connection_nonce,
        'TCP request identity or configured peer mismatch')
    mesh.hex32(body['nonce'])
    mesh.require(len(wire.canonical(body['bundle'])) <= mesh.MAX_BATCH,'TCP exchange byte bound')
    exchange = mesh.verify(body['bundle'],'exchange',network)
    mesh.require(exchange['node_id']==body['node_id'] and exchange['to']==recipient,'TCP request/bundle identity mismatch')
    return body


def check_response(value, network, requester, peer, sent):
    body=mesh.verify(value,'tcp-response',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','to','nonce','challenge','exchange_id','accepted','bundle','error'}
        and body['adapter']==ADAPTER and body['node_id']==peer and body['to']==requester
        and body['nonce']==sent['body']['nonce'] and body['challenge']==sent['body']['challenge']
        and body['exchange_id']==mesh.digest(sent['body']['bundle']),
        'TCP response identity, nonce or exact exchange mismatch')
    mesh.require(type(body['accepted']) is bool, 'invalid TCP acknowledgment')
    if not body['accepted']:
        mesh.require(body['bundle'] is None and body['error']=='CONTACT_REJECTED','invalid TCP refusal')
        raise ValueError('TCP peer refused custody; retain queued evidence')
    mesh.require(body['error'] is None and isinstance(body['bundle'],dict)
        and len(wire.canonical(body['bundle']))<=mesh.MAX_BATCH,'invalid TCP success bundle')
    exchange=mesh.verify(body['bundle'],'exchange',network)
    mesh.require(exchange['node_id']==peer and exchange['to']==requester,'TCP response/bundle identity mismatch')
    return body['bundle']
