"""Native configured contact checks; filesystem creation keeps original order."""
import os
from pathlib import Path
import interstellar_crypto as crypto
FORMAT='RLD-NATIVE-CONTACT-CONFIG-V1'

def _call(mode,variant,**fields):
    result=crypto.backend().call({'Config':{variant:fields}})
    if (type(result) is not dict or set(result)!={'format','mode','value','configured_input_only','ledger_authority','custody_acknowledgment'}
        or result['format']!=FORMAT or result['mode']!=mode or result['configured_input_only'] is not True
        or result['ledger_authority'] is not False or result['custody_acknowledgment'] is not False):
        raise ValueError('native contact config receipt differs')
    return result['value']

def header(config):
    if not isinstance(config,dict):raise ValueError('invalid config fields')
    if _call('header','Header',keys=list(config),version=config.get('format')) is not None:
        raise ValueError('native config header output differs')

def identifier(value):
    checked=_call('identifier','Identifier',value=value)
    if type(checked) is not str or checked!=value:raise ValueError('native identifier output differs')
    return checked

def _contact(value):
    if not isinstance(value,dict):return value
    return {k:os.fspath(v) if k in ('inbox','outbox') and isinstance(v,os.PathLike) else v for k,v in value.items()}

def contact_schema(value):
    prepared=_contact(value);checked=_call('shape','Shape',contact=prepared)
    if checked!=prepared:raise ValueError('native contact shape output differs')
    return value

def tcp_endpoint(host,port,listening=False):
    checked=_call('endpoint','Endpoint',host=host,port=port,listening=bool(listening))
    if (type(checked) is not dict or set(checked)!={'host','port'} or checked['host']!=host
        or type(checked['port']) is not int or checked['port']!=port):
        raise ValueError('native endpoint output differs')
    return checked['host'],checked['port']

def _spools(paths,pair=False):
    if _call('spools','Spools',paths=[str(p) for p in paths],pair=pair) is not None:
        raise ValueError('native spool validation output differs')

def contacts(config,node):
    import interstellar_mesh as mesh
    limit=mesh.MAX_CONTACTS
    if type(limit) is not int or not 0<=limit<=16:raise ValueError('native contact limit differs')
    values=config['contacts'];count=len(values) if isinstance(values,list) else 0
    checked=_call('capacity','Capacity',is_list=isinstance(values,list),count=count,limit=limit)
    if type(checked) is not int or checked!=count:raise ValueError('native contact count differs')
    result={}
    for value in values:
        prepared=_contact(value)
        checked=_call('resolve','Resolve',contact=prepared,node=node,seen=list(result))
        if (type(checked) is not dict or set(checked)!={'peer','contact'} or not isinstance(value,dict)
            or checked['peer']!=value.get('peer') or type(checked['contact']) is not dict):
            raise ValueError('native contact resolution output differs')
        peer=checked['peer'];resolved=checked['contact']
        if 'host' in prepared:
            expected={k:prepared[k] for k in ('host','port','tls_cert_sha256') if k in prepared}
        else:
            expected={k:prepared[k] for k in ('inbox','outbox') if k in prepared}
            if prepared.get('adapter')==mesh.spool_codec.FORMAT:expected['adapter']=prepared['adapter']
        if resolved!=expected or ('port' in resolved and type(resolved['port']) is not int):
            raise ValueError('native configured contact binding differs')
        # These paths still go through the existing native nofollow directory
        # interface in original inbox/outbox and contact order. No cleanup or
        # all-config preflight hides an earlier creation failure/residue.
        if 'host' in resolved:result[peer]=resolved
        else:
            result[peer]={k:mesh.safe_dir(resolved[k]) for k in ('inbox','outbox') if k in resolved}
            if 'adapter' in resolved:result[peer]['adapter']=resolved['adapter']
            if 'inbox' in resolved and 'outbox' in resolved:_spools([result[peer]['inbox'],result[peer]['outbox']],True)
    _spools([p for c in result.values() for k,p in c.items() if k in ('inbox','outbox')])
    return result
