from pathlib import Path
import ast,hashlib,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'first_service_diagnostic_observer_v5_20261007.py';new=b/'first_service_diagnostic_observer_v6_20261007.py';assert not new.exists();source=old.read_text();pairs=[]
def replace(a,z):
 global source
 assert source.count(a)==1,(a[:80],source.count(a));pairs.append((a,z));source=source.replace(a,z)
replace("FORMAT = 'RLD-FIRST-SERVICE-DIAGNOSTIC-V3'","FORMAT = 'RLD-FIRST-SERVICE-DIAGNOSTIC-V4'")
replace('''        for group in call:ids(group,256)
        require(len(set(call[0]+call[1]))==len(call[0]+call[1])<=256,'diagnostic disjoint classes')''','''        all_ids=[];size=0
        for group in call:
            require(type(group) is dict and set(group)=={'size','current_ids','positions'},
                    'diagnostic focused class schema')
            require(type(group['size']) is int and 0<=group['size']<=256,'diagnostic original class size')
            current=ids(group['current_ids'],256);positions=group['positions']
            require(type(positions) is list and len(positions)==len(current)
                    and all(type(n) is int and 0<=n<group['size'] for n in positions)
                    and positions==sorted(set(positions)),'diagnostic actual current ranks')
            size+=group['size'];all_ids+=current
        require(size<=256 and len(all_ids)==len(set(all_ids)),'diagnostic disjoint current classes')''')
replace('''        require(type(route) is dict and set(route)=={'attempts','path'},'diagnostic route schema')
        require(type(route['attempts']) is int and 1<=route['attempts']<=1024,'diagnostic route count')
        if route['path'] is not None:ids(route['path'],17)''','''        require(type(route) is dict and set(route)=={'attempts','eligible','path_length'},'diagnostic route schema')
        require(type(route['attempts']) is int and 1<=route['attempts']<=1024
                and type(route['eligible']) is bool,'diagnostic original route count/eligibility')
        length=route['path_length']
        require(length is None or type(length) is int and 1<=length<=17,'diagnostic original path length')
        require(not route['eligible'] or length is not None and length>=2,'diagnostic eligible missing route')''')
replace('''                    rows.append([ids(list(group),256) for group in result])''','''                    tracked=set(context['priority']['matching_packet_ids']);groups=[]
                    for items in result:
                        require(type(items) is list and len(items)<=256,'diagnostic original group bound')
                        positions=[i for i,ident in enumerate(items) if ident in tracked]
                        groups.append(dict(size=len(items),current_ids=ids([items[i] for i in positions],256),
                                           positions=positions))
                    rows.append(groups)''')
replace('''                    rows=context['selector']['transit_checks']
                    require(ident in rows or len(rows)<256,'diagnostic original transit ID bound')
                    rows[ident]=rows.get(ident,0)+1
                    context['route_packet']=(ident,result[0]['destination'])''','''                    context['route_packet']=None
                    if ident not in context['priority']['matching_packet_ids']:return
                    rows=context['selector']['transit_checks']
                    require(ident in rows or len(rows)<256,'diagnostic original transit ID bound')
                    rows[ident]=rows.get(ident,0)+1
                    context['route_packet']=(ident,result[0]['destination'],len(transit['hops']),
                                             result[0]['hop_limit'])''')
replace('''                    prior=rows.get(ident,dict(attempts=0,path=None))
                    rows[ident]=dict(attempts=prior['attempts']+1,
                                     path=None if result is None else ids(list(result),17))''','''                    prior=rows.get(ident,dict(attempts=0,eligible=False,path_length=None))
                    rows[ident]=dict(attempts=prior['attempts']+1,
                                     path_length=None if result is None else len(result),
                                     eligible=bool(result and len(result)>=2 and result[1]==first_hop
                                                   and marker[2]+len(result)-1<=marker[3]))''')
compile(source,str(new),'exec');back=source
for a,z in reversed(pairs):assert back.count(z)==1;back=back.replace(z,a)
assert back==old.read_text();new.write_text(source)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();oc=b/'first_service_diagnostic_collector_v3_20261007.py';collector=b/'first_service_diagnostic_collector_v4_20261007.py';assert not collector.exists();cs=oc.read_text();cp=[(old.name,new.name),(sha(old),sha(new))]
for a,z in cp:assert cs.count(a)==1;cs=cs.replace(a,z)
compile(cs,str(collector),'exec');back=cs
for a,z in reversed(cp):back=back.replace(z,a)
assert back==oc.read_text();collector.write_text(cs)
out=b/'selector-observer-v6-reversal-20261007.json';assert not out.exists();out.write_text(json.dumps(dict(completed=True,pairs=pairs,collector_pairs=cp,observer_sha256=sha(new),collector_sha256=sha(collector),exact_prior_text_after_reversal=True,focus='Only original prepare-entry current IDs, actual original-group ranks/sizes and route eligible/path length; no all-traffic ID maps/full paths. V5 not allocated Native: avoid forecast all-traffic journal cost before scope.',original_limits32events192KiB8MiB_unchanged=True),indent=2)+'\n');print(json.dumps(dict(completed=True,observer_sha256=sha(new),collector_sha256=sha(collector))))
