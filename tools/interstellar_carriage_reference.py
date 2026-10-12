"""Complete original first-carriage planner for explicit independent tests."""
from bisect import bisect_right
from interstellar_mesh import transit_check,require,MAX_MESSAGES,MAX_RECENT_TRANSITS

def first_carriage_plan(self,peer):
    """Bounded first admission with durable arrival waiting, never authority."""
    value=self.state['first_carriage'][peer];active=self.state['messages'];receipted=self.state['receipts'];prepared=[i for i in value['prepared'] if i in active]
    def eligible(ident):
        if ident not in active or ident in receipted:return False
        transit=active[ident];packet,_,visited=transit_check(transit,self.network,include_frame=False);route=self.route(packet['destination'],visited[:-1],first_hop=peer)
        return bool(route and len(route)>=2 and route[1]==peer and len(transit['hops'])+len(route)-1<=packet['hop_limit'])
    pending=[i for i in value['pending'] if eligible(i)];known=set(prepared)|set(pending);initial=value['observed'] is None
    # At this peer's first preparation, existing recent traffic takes its
    # previous32 admission places; older history remains ordinary/background.
    # Afterwards new complete IDs retain original arrival order independent of
    # recent label and sorted canonical mapping keys. Never replace pending IDs.
    if initial:
        for ident in self.state['recent_transits']:
            if len(pending)==MAX_RECENT_TRANSITS:break
            if ident not in known and eligible(ident):pending.append(ident);known.add(ident)
        arrivals=[]
    else:
        arrivals=[i for i in value['arrivals'] if i not in known and eligible(i)];seen=set(value['observed']);already=set(arrivals)
        for ident in self.state['first_arrivals']:
            if ident not in seen and ident not in known and ident not in already and eligible(ident):arrivals.append(ident);already.add(ident)
    require(len(arrivals)<=MAX_MESSAGES,'first arrival backlog capacity')
    priority=iter(arrivals);reserved=set(arrivals);history=sorted(i for i in active if i not in known and i not in reserved and i not in receipted);after=value['history_after'];start=0 if after is None or not history else bisect_right(history,after)%len(history);background=iter(history[start:]+history[:start]);next_kind=value['next_kind']
    def take(kind):
        for ident in priority if kind==0 else background:
            if ident not in known and eligible(ident):return ident
        return None
    while len(pending)<MAX_RECENT_TRANSITS:
        kind=next_kind;ident=take(kind)
        if ident is None:kind=1-kind;ident=take(kind)
        if ident is None:break
        pending.append(ident);known.add(ident)
        if kind==1:after=ident
        next_kind=1-kind
    # Plan construction is pure. The existing complete atomic preparation
    # publishes this provisional ID metadata only on success; full4retry skips.
    return dict(pending=pending,prepared=prepared,arrivals=[i for i in arrivals if i not in known],observed=sorted(active),history_after=after,next_kind=next_kind)
