"""Current Native signer observations for stop eligibility, never authority.

No custody, signing, network or Native operation occurs in these functions.
All stopped Native checks and complete cold/value acceptance remain mandatory.
"""
import interstellar_mesh as mesh

FORMAT = 'RLD-NATIVE-KEYLESS-DRAIN-OBSERVATION-V1'
CONTEXT_FIELDS = {'currency','region','epoch','previous','parent_height','parent_block','parent_state'}


def current_commits(context, messages, key, caller_head):
    """Summarize a fresh, caller-pinned Native retained-message response only."""
    mesh.require(type(messages) is list, 'complete Native retained messages required')
    votes=set()
    for message in messages:
        mesh.require(type(message) is dict, 'invalid Native retained message')
        vote=message.get('Vote')
        if vote is None:continue
        mesh.require(type(vote) is dict, 'invalid Native retained vote')
        if vote.get('phase')!='Commit' or vote.get('context')!=context:continue
        approval=vote['approval'];round_number=vote['round'];value=vote['value']
        mesh.require(type(round_number) is int and 0<=round_number<32
                     and type(approval) is dict and approval['key']==key,
                     'current Native Commit differs from own signer')
        mesh.hex32(value);votes.add((round_number,value,key))
    mesh.require(len(votes)<=32, 'current Native signer Commit round bound')
    return dict(format=FORMAT, context=dict(context), caller_head=caller_head,
                commits=[dict(round=n,value=value,key=key) for n,value,key in sorted(votes)],
                signing_authority=False,independent_freshness_qualified=False)


def reports_drained(reports, bindings, heights, currency, regions):
    """All current own observations precede stopping; no retained proof reuse."""
    if set(reports)!=set(bindings):return False
    mesh.require(all(slot[0] in regions for slot in bindings), 'unknown keyless drain region')
    for label in regions:
        slots=[slot for slot in bindings if slot[0]==label]
        mesh.require(len(slots)==4 and len({bindings[slot]['key'] for slot in slots})==4,
                     'four distinct keyless Native signer observations required')
        groups={};context=None
        for slot, binding in bindings.items():
            if slot[0]!=label:continue
            report=reports[slot]
            mesh.require(type(report) is dict and set(report)=={'format','context','caller_head','commits',
                'signing_authority','independent_freshness_qualified'} and report['format']==FORMAT
                and report['signing_authority'] is False and report['independent_freshness_qualified'] is False,
                'Native keyless drain observation domain differs')
            current=report['context']
            mesh.require(type(current) is dict and set(current)==CONTEXT_FIELDS
                and current['currency']==currency and current['region']==regions[label]
                and type(current['parent_height']) is int and current['parent_height']>=0,
                'Native keyless drain context domain differs')
            for name in ('currency','region','epoch','parent_block','parent_state'):mesh.hex32(current[name])
            if current['previous'] is not None:mesh.hex32(current['previous'])
            mesh.hex32(report['caller_head'])
            if current['parent_height']!=heights[slot] or report['caller_head']!=binding['head']:return False
            if context is None:context=current
            elif context!=current:return False
            commits=report['commits']
            mesh.require(type(commits) is list and len(commits)<=32,'Native keyless drain Commit bound')
            unique=set()
            for vote in commits:
                mesh.require(type(vote) is dict and set(vote)=={'round','value','key'}
                    and type(vote['round']) is int and 0<=vote['round']<32
                    and vote['key']==binding['key'],'Native keyless drain own vote differs')
                mesh.hex32(vote['value']);mesh.hex32(vote['key'])
                ident=(vote['round'],vote['value'],vote['key'])
                mesh.require(ident not in unique,'duplicate Native keyless drain vote');unique.add(ident)
                groups.setdefault((vote['round'],vote['value']),set()).add(vote['key'])
        if any(len(keys)>=3 for keys in groups.values()):return False
    return True
