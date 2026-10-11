"""Independent old Python phase policy for tests, never production authority."""
def action_reference(runtime,context,round_number,mode,status=None):
    status=runtime.signer_status()['state'] if status is None else status
    state=status if status is not None and status['context']==context else dict(round=0,prepared=None,committed=None,lock=None)
    if mode!='commit':
        for number in range(32):
            for proposal,value in runtime.signed(context,number,'Proposal'):
                if mode=='committed' and (number!=state['round'] or state['committed']!=value):continue
                committed=runtime.quorum(context,number,'Commit',value)
                if committed is None:continue
                prepared=runtime.quorum(context,number,'Prepare',value)
                if prepared is not None:
                    snapshot=runtime.with_json('bft-certify',dict(proposal=proposal,prepared=prepared,committed=committed))
                    return {'Finalize':dict(snapshot=snapshot)}
    if mode in ('finalize','committed'):return 'Idle'
    def eligible(proposal,value):
        lock=state.get('lock')
        if lock is None:return True
        highs=[v['high'] for v in proposal['timeout']['votes'] if v['high'] is not None] if proposal['timeout'] else []
        return lock is None or lock['value']==value or any(q['round']>lock['round'] for q in highs)
    for proposal,value in runtime.signed(context,round_number,'Proposal'):
        prepared=runtime.quorum(context,round_number,'Prepare',value)
        if state['prepared'] is None and mode!='commit':
            if eligible(proposal,value):return {'Prepare':dict(proposal=proposal,prepared=prepared,value=value)}
        elif state['prepared']==value and state['committed'] is None and prepared is not None:
            return {'Commit':dict(proposal=proposal,prepared=prepared,value=value)}
    if mode=='future':
        future=[]
        for number in range(round_number+1,32):future.extend(runtime.signed(context,number,'Proposal'))
        for proposal,value in sorted(future,key=lambda p:p[0]['round'],reverse=True):
            if eligible(proposal,value):return {'Prepare':dict(proposal=proposal,prepared=None,value=value)}
    return 'Idle'
