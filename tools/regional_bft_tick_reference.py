"""Independent former Python ordinary tick choices for tests only."""
from regional_bft_phase_reference import action_reference
from regional_bft_proposal_reference import opportunity_reference
import interstellar_transfer as wire

def plan_reference(runtime,context,number,stage,now,stopped=False,proposed=None,status=None):
    status=runtime.signer_status()['state'] if status is None else status
    active=status if status is not None and status['context']==context else dict(round=0,prepared=None,committed=None,proposed=False)
    if stopped:return {'Phase':action_reference(runtime,context,number,'finalize',status)}
    if stage in ('commit','committed'):return {'Phase':action_reference(runtime,context,number,stage,status)}
    if stage=='after-proposal':
        if (active['proposed'] and active['prepared'] is None and active['committed'] is None):
            for proposal,value in runtime.signed(context,number,'Proposal'):
                if (proposal['leader']['key']==runtime.key and proposal['round']==proposed['round']
                        and wire.canonical(proposal['snapshot'])==wire.canonical(proposed['snapshot'])
                        and wire.canonical(proposal['timeout'])==wire.canonical(proposed['timeout'])):
                    return {'Phase':{'Prepare':dict(proposal=proposal,prepared=None,value=value)}}
        return {'Phase':'Idle'}
    current=action_reference(runtime,context,number,'start',status)
    if current!='Idle':return {'Phase':current}
    choice=opportunity_reference(runtime,context,number,active)
    age=now-runtime.entered_at
    if choice['can_propose'] and age>=runtime.block_interval:
        return {'Propose':dict(round=choice['proposed_round'],timeout=choice['timeout'],high=choice['high'])}
    from regional_bft_node import ORIGIN_RUNTIME_FORMAT
    origin=runtime.format==ORIGIN_RUNTIME_FORMAT
    if (choice['can_propose'] and origin and number==choice['proposed_round']==0
            and active['prepared'] is None and active['committed'] is None
            and callable(getattr(runtime,'before_initial_proposal',None)) and not runtime._initial_proposal_wait_used):
        return {'WaitInitial':dict(deadline=runtime.entered_at+runtime.block_interval)}
    future=action_reference(runtime,context,number,'future',status)
    if future!='Idle':return {'Phase':future}
    if age>=min(3600,runtime.round_timeout*(number+1)):
        if origin and callable(getattr(runtime,'before_timeout',None)) and not runtime._timeout_refresh_used:
            return 'RefreshTimeout'
        return {'Timeout':dict(context=context,round=number)}
    return {'Phase':'Idle'}
