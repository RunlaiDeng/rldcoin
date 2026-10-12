"""Native outer signed exchange/TCP bindings; durable custody stays separate."""
import interstellar_crypto as crypto
import interstellar_mesh as mesh
FORMAT='RLD-NATIVE-CONTACT-EXCHANGE-V1'

def _limits():
    import interstellar_tcp as tcp
    if tcp.ADAPTER!='RLD-CONTACT-TCP-V4':raise ValueError('native TCP adapter differs')
    fields=dict(contacts=mesh.MAX_CONTACTS,nodes=mesh.MAX_NODES,transits=mesh.MAX_PACKET_BATCH,
                messages=mesh.MAX_MESSAGES,exchange=mesh.MAX_BATCH)
    caps=dict(contacts=16,nodes=64,transits=4,messages=256,exchange=20*1024*1024)
    if any(type(value) is not int or not 0<=value<=caps[name] for name,value in fields.items()):
        raise ValueError('native exchange limits differ')
    return fields

def _check(mode,variant,signed,network,**fields):
    result=crypto.backend().call({'Exchange':{variant:dict(network=network,signed=signed,**fields)}})
    if (type(result) is not dict or set(result)!={'format','mode','network','body','envelope_authenticated',
        'ledger_authority','durable_custody_acknowledgment'} or result['format']!=FORMAT
        or result['mode']!=mode or result['network']!=network or result['envelope_authenticated'] is not True
        or result['ledger_authority'] is not False or result['durable_custody_acknowledgment'] is not False
        or type(signed) is not dict or type(result['body']) is not dict or result['body']!=signed.get('body')):
        raise ValueError('native exchange receipt binding differs')
    expected=(result['body']['nonce'] if mode=='challenge' else result['body']['bundle'] if mode=='response' else result['body'])
    return expected

def exchange_check(node,bundle,peer):
    return _check('exchange','Exchange',bundle,node.network,peer=peer,recipient=node.id,limits=_limits(),
        incoming_allowed=peer in node.contacts and mesh.incoming_contact(node.contacts[peer]))

def check_challenge(value,network,peer,fingerprint):
    _limits()
    return _check('challenge','Challenge',value,network,peer=peer,fingerprint=fingerprint)

def check_request(value,network,recipient,peers,connection_nonce):
    return _check('request','TcpRequest',value,network,recipient=recipient,peers=sorted(peers),
                  nonce=connection_nonce,limits=_limits())

def check_response(value,network,requester,peer,sent):
    return _check('response','TcpResponse',value,network,requester=requester,peer=peer,sent=sent,limits=_limits())
