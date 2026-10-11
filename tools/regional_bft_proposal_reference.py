"""Independent Python proposal policy retained for tests only.

The caller supplies observations; this reference has no Native signing rights.
"""
def opportunity_reference(runtime,context,round_number,active):
    current=runtime.signed(context,round_number,'Proposal')
    future=[]
    for later in range(round_number+1,32):future.extend(runtime.signed(context,later,'Proposal'))
    eligible=[]
    if not future:
        for later in range(round_number+1,32):
            if sorted(runtime.peers)[(context['parent_height']+later)%4]!=runtime.key:continue
            voters={v['approval']['key'] for v,_ in runtime.signed(context,later-1,'Timeout')}
            if len(voters)>=3:eligible.append(later)
    proposed_round=max(eligible,default=round_number)
    leader=sorted(runtime.peers)[(context['parent_height']+proposed_round)%4]
    tc=None if proposed_round==0 else runtime.timeout_certificate(context,proposed_round-1)
    can_propose=(not current and not future and leader==runtime.key
        and (proposed_round>round_number or not active['proposed'])
        and (proposed_round==0 or tc is not None))
    highs=[v['high'] for v in tc['votes'] if v['high'] is not None] if tc else []
    high=max(highs,key=lambda q:q['round'])['value'] if highs else None
    return dict(current_proposals=bool(current),future_proposals=bool(future),proposed_round=proposed_round,
                leader=leader,timeout=tc,high=high,can_propose=bool(can_propose))
