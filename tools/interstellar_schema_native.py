"""Native exact transport schemas; all native ledger/value gates remain separate."""
from interstellar_crypto import backend
FORMAT='RLD-NATIVE-CONTACT-SCHEMA-V1'
KINDS=('advert','inventory','receipt-route','receipt')
def check(value,kind,network):
    import interstellar_mesh as mesh
    if (kind not in KINDS or type(mesh.MAX_CONTACTS) is not int or not 0<=mesh.MAX_CONTACTS<=16
        or type(mesh.MAX_MESSAGES) is not int or not 0<=mesh.MAX_MESSAGES<=256):
        raise ValueError('native contact schema limits/kind differ')
    result=backend().call({'Schema':dict(kind=kind,network=network,signed=value,
                             limits=dict(contacts=mesh.MAX_CONTACTS,messages=mesh.MAX_MESSAGES))})
    if (type(result) is not dict or set(result)!={'format','kind','network','body','transport_authenticated','ledger_authority','custody_acknowledgment'}
        or result['format']!=FORMAT or result['kind']!=kind or result['network']!=network
        or result['transport_authenticated'] is not True or result['ledger_authority'] is not False
        or result['custody_acknowledgment'] is not False or type(result['body']) is not dict
        or type(value) is not dict or result['body']!=value.get('body')):
        raise ValueError('native contact schema receipt binding differs')
    return result['body']
