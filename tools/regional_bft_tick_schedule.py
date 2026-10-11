"""Exact native ordinary tick bridge; no scheduling or failure fallback."""
import hashlib
import math
import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT='RLD-NATIVE-BFT-TICK-OBSERVATION-V1'
def request(runtime,context,stage,stopped,proposed):
    return dict(context=context,order=list(runtime.state['messages']),stage=stage,proposed=proposed,
        entered_at=float(runtime.entered_at),interval=float(runtime.block_interval),timeout=float(runtime.round_timeout),
        stopped=stopped,initial_wait=callable(getattr(runtime,'before_initial_proposal',None))
            and not getattr(runtime,'_initial_proposal_wait_used',False),
        timeout_refresh=callable(getattr(runtime,'before_timeout',None)) and not getattr(runtime,'_timeout_refresh_used',False))

def plan(runtime,context,round_number,stage,stopped=False,proposed=None):
    mesh.require(runtime.head.get('pending') is None and runtime.head.get('outbox') is None,
        'Native BFT tick requires reconciled caller custody')
    payload=request(runtime,context,stage,stopped,proposed)
    result=runtime.with_json('bft-tick-observation',payload,
        '--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
        '--state-dir',runtime.root,'--expected-state-sha256',runtime._archive_head,
        '--expected-key',runtime.key,'--runtime-format',runtime.format,'--round',str(round_number))
    fields={'format','context','round','key','caller_head','archive_sha256','request_sha256',
        'authenticated_messages','monotonic_now','action','ledger_changed','signing_authority','independent_freshness_qualified'}
    mesh.require(type(result) is dict and set(result)==fields and result['format']==FORMAT
        and result['context']==context and type(result['round']) is int and result['round']==round_number
        and result['key']==runtime.key and result['caller_head']==runtime.head['head']
        and result['archive_sha256']==runtime._archive_head
        and result['request_sha256']==hashlib.sha256(wire.canonical(payload)).hexdigest()
        and type(result['authenticated_messages']) is int
        and 0<=result['authenticated_messages']<=len(runtime.state['messages'])
        and type(result['monotonic_now']) is float and math.isfinite(result['monotonic_now'])
        and result['monotonic_now']>=payload['entered_at']
        and result['ledger_changed'] is False and result['signing_authority'] is False
        and result['independent_freshness_qualified'] is False,'Native BFT tick observation binding differs')
    selected=result['action']
    if selected=='RefreshTimeout':return selected
    mesh.require(type(selected) is dict and len(selected)==1,'Native BFT tick action shape differs')
    kind=next(iter(selected));body=selected[kind]
    if kind=='Phase':
        if body=='Idle':return selected
        mesh.require(type(body) is dict and len(body)==1,'Native BFT tick phase shape differs')
        phase=next(iter(body));value=body[phase]
        fields={'Prepare':{'proposal','prepared','value'},'Commit':{'proposal','prepared','value'},'Finalize':{'snapshot'}}
        mesh.require(phase in fields and type(value) is dict and set(value)==fields[phase],
            'Native BFT tick phase payload differs')
        if phase=='Finalize':mesh.require(type(value['snapshot']) is dict,'Native tick snapshot differs')
        else:
            mesh.hex32(value['value'])
            mesh.require(type(value['proposal']) is dict and (type(value['prepared']) is dict
                or phase=='Prepare' and value['prepared'] is None),'Native tick proposal/quorum differs')
    elif kind=='Propose':
        mesh.require(type(body) is dict and set(body)=={'round','timeout','high'}
            and type(body['round']) is int and 0<=body['round']<32
            and (body['timeout'] is None or type(body['timeout']) is dict), 'Native tick Propose differs')
        if body['high'] is not None:mesh.hex32(body['high'])
    elif kind=='WaitInitial':
        mesh.require(type(body) is dict and set(body)=={'deadline'}
            and type(body['deadline']) is float and math.isfinite(body['deadline'])
            and body['deadline']==payload['entered_at']+payload['interval'],'Native tick deadline differs')
    elif kind=='Timeout':
        mesh.require(type(body) is dict and set(body)=={'context','round'} and body['context']==context
            and type(body['round']) is int and body['round']==round_number,'Native tick Timeout differs')
    else:raise ValueError('Native BFT tick action differs')
    return selected
