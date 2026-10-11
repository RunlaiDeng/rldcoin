"""Bounded Native phase bridge; no Python selection or failure fallback."""
import hashlib
import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT='RLD-NATIVE-BFT-PHASE-OBSERVATION-V1'
def action(runtime,context,round_number,mode):
    mesh.require(runtime.head.get('pending') is None and runtime.head.get('outbox') is None,
        'Native BFT phase requires reconciled caller custody')
    request=dict(context=context,order=list(runtime.state['messages']))
    result=runtime.with_json('bft-phase-action',request,
        '--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
        '--state-dir',runtime.root,'--expected-state-sha256',runtime._archive_head,
        '--expected-key',runtime.key,'--runtime-format',runtime.format,
        '--round',str(round_number),'--mode',mode)
    fields={'format','context','round','key','caller_head','archive_sha256','mode',
        'authenticated_messages','request_sha256','action','ledger_changed','signing_authority','independent_freshness_qualified'}
    mesh.require(type(result) is dict and set(result)==fields and result['format']==FORMAT
        and result['context']==context and type(result['round']) is int and result['round']==round_number
        and result['key']==runtime.key and result['caller_head']==runtime.head['head']
        and result['archive_sha256']==runtime._archive_head and result['mode']==mode
        and result['request_sha256']==hashlib.sha256(wire.canonical(request)).hexdigest()
        and type(result['authenticated_messages']) is int
        and 0<=result['authenticated_messages']<=len(runtime.state['messages'])
        and result['ledger_changed'] is False and result['signing_authority'] is False
        and result['independent_freshness_qualified'] is False,
        'Native BFT phase observation binding differs')
    selected=result['action']
    if selected=='Idle':return selected
    mesh.require(type(selected) is dict and len(selected)==1,'Native BFT phase action shape differs')
    kind=next(iter(selected));payload=selected[kind]
    wanted={'Prepare':{'proposal','prepared','value'},'Commit':{'proposal','prepared','value'},'Finalize':{'snapshot'}}
    mesh.require(kind in wanted and type(payload) is dict and set(payload)==wanted[kind],
        'Native BFT phase payload shape differs')
    if kind=='Finalize':mesh.require(type(payload['snapshot']) is dict,'Native finality shape differs')
    else:
        mesh.hex32(payload['value'])
        mesh.require(type(payload['proposal']) is dict and (type(payload['prepared']) is dict
            or kind=='Prepare' and payload['prepared'] is None),'Native phase proposal/quorum shape differs')
    return selected
