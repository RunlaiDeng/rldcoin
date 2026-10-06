from pathlib import Path
import ast,hashlib,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'first_service_diagnostic_observer_v4_20261007.py';new=b/'first_service_diagnostic_observer_v5_20261007.py';assert not new.exists();source=old.read_text();pairs=[]
def replace(a,z):
 global source
 assert source.count(a)==1,(a[:80],source.count(a));pairs.append((a,z));source=source.replace(a,z)
replace("FORMAT = 'RLD-FIRST-SERVICE-DIAGNOSTIC-V2'","FORMAT = 'RLD-FIRST-SERVICE-DIAGNOSTIC-V3'")
extra='''def hint_value(value):
    if value is None:return None
    require(type(value) is tuple and len(value)==2 and type(value[1]) is tuple,
            'diagnostic consumed hint shape')
    ids([value[0]],1);ids(list(value[1]),512)
    return dict(scope=value[0],frame_ids=list(value[1]))

def check_selector(value):
    require(type(value) is dict and set(value)=={'hint_reads','groups','transit_checks','routes'},
            'diagnostic selector schema')
    reads=value['hint_reads'];require(type(reads) is list and len(reads)<=2,'diagnostic hint read bound')
    for hint in reads:
        if hint is None:continue
        require(type(hint) is dict and set(hint)=={'scope','frame_ids'},'diagnostic consumed hint schema')
        ids([hint['scope']],1);ids(hint['frame_ids'],512)
    groups=value['groups'];require(type(groups) is list and len(groups)<=2,'diagnostic grouping call bound')
    for call in groups:
        require(type(call) is list and len(call)==2,'diagnostic original two classes')
        for group in call:ids(group,256)
        require(len(set(call[0]+call[1]))==len(call[0]+call[1])<=256,'diagnostic disjoint classes')
    checks=value['transit_checks'];routes=value['routes']
    require(type(checks) is dict and type(routes) is dict,'diagnostic checked route maps')
    ids(list(checks),256);ids(list(routes),256)
    require(all(type(n) is int and 1<=n<=1024 for n in checks.values())
            and sum(checks.values())<=1024,'diagnostic authenticated checks bound')
    require(set(routes)<=set(checks),'diagnostic route without preceding original transit check')
    for route in routes.values():
        require(type(route) is dict and set(route)=={'attempts','path'},'diagnostic route schema')
        require(type(route['attempts']) is int and 1<=route['attempts']<=1024,'diagnostic route count')
        if route['path'] is not None:ids(route['path'],17)
    require(sum(v['attempts'] for v in routes.values())<=1024,'diagnostic total route count')

'''
replace('def check_record(row, sequenced=False):\n',extra+'def check_record(row, sequenced=False):\n')
replace("'return_observation_missing','priority'}","'return_observation_missing','priority','selector'}")
replace("    require(type(row['plans']) is list", "    if 'selector' in row:check_selector(row['selector'])\n    require(type(row['plans']) is list")
replace('        original_init = t.Server.__init__\n','''        original_init = t.Server.__init__
        original_position, original_groups = m.carriage_position, m.Node.transit_groups
        original_check, original_route = m.transit_check, m.Node.route
''')
replace('                            priority=priority_snapshot(m,node,peer),\n','''                            priority=priority_snapshot(m,node,peer),
                            priority_key=(node.carriage_position_domain(),'native-commit-spare'),
                            route_packet=None,
                            selector=dict(hint_reads=[],groups=[],transit_checks={},routes={}),
''')
replace("                context.pop('accepted')\n","                context.pop('accepted')\n                context.pop('priority_key')\n                context.pop('route_packet')\n")
wrappers='''        def positioned(key):
            result=original_position(key)
            context=getattr(observer.local,'context',None)
            if context is not None and key==context['priority_key']:
                def captured():
                    rows=context['selector']['hint_reads']
                    require(len(rows)<2,'diagnostic hint read bound')
                    rows.append(hint_value(result))
                observer.safe(captured)
            return result

        def grouped(node,peer):
            result=original_groups(node,peer)
            context=getattr(observer.local,'context',None)
            if context is not None and context['node'] is node and context['peer']==peer:
                def captured():
                    rows=context['selector']['groups'];require(len(rows)<2,'diagnostic grouping call bound')
                    require(type(result) is list and len(result)==2,'diagnostic original classes')
                    rows.append([ids(list(group),256) for group in result])
                observer.safe(captured)
            return result

        def checked(transit,network,recipient=None,sender=None,*,include_frame=True):
            result=original_check(transit,network,recipient,sender,include_frame=include_frame)
            context=getattr(observer.local,'context',None)
            if context is not None and network==context['node'].network:
                def captured():
                    ident=transit['routing']['body']['packet_id'];ids([ident],1)
                    rows=context['selector']['transit_checks']
                    require(ident in rows or len(rows)<256,'diagnostic original transit ID bound')
                    rows[ident]=rows.get(ident,0)+1
                    context['route_packet']=(ident,result[0]['destination'])
                observer.safe(captured)
            return result

        def routed(node,destination,excluded=(),first_hop=None):
            result=original_route(node,destination,excluded,first_hop)
            context=getattr(observer.local,'context',None)
            if context is not None and context['node'] is node and first_hop==context['peer']:
                def captured():
                    marker=context['route_packet'];context['route_packet']=None
                    if marker is None or marker[1]!=destination:return
                    ident=marker[0];rows=context['selector']['routes']
                    require(ident in rows or len(rows)<256,'diagnostic original route ID bound')
                    prior=rows.get(ident,dict(attempts=0,path=None))
                    rows[ident]=dict(attempts=prior['attempts']+1,
                                     path=None if result is None else ids(list(result),17))
                observer.safe(captured)
            return result

'''
replace('        replacements = [(m.Node,',wrappers+'        replacements = [(m.Node,')
replace("                        (t.Server,'__init__',server_init)]","""                        (t.Server,'__init__',server_init),
                        (m,'carriage_position',positioned),(m.Node,'transit_groups',grouped),
                        (m,'transit_check',checked),(m.Node,'route',routed)]""")
compile(source,str(new),'exec');rev=source
for a,z in reversed(pairs):assert rev.count(z)==1;rev=rev.replace(z,a)
assert rev==old.read_text();assert ast.dump(ast.parse(rev),include_attributes=False)==ast.dump(ast.parse(old.read_text()),include_attributes=False)
new.write_text(source);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
collector=b/'first_service_diagnostic_collector_v3_20261007.py';assert not collector.exists();oc=b/'first_service_diagnostic_collector_v2_20261007.py';cs=oc.read_text();cp=[(old.name,new.name),(sha(old),sha(new))]
for a,z in cp:assert cs.count(a)==1;cs=cs.replace(a,z)
compile(cs,str(collector),'exec');reverse=cs
for a,z in reversed(cp):reverse=reverse.replace(z,a)
assert reverse==oc.read_text();collector.write_text(cs)
out=b/'selector-observer-v5-reversal-20261007.json';assert not out.exists();out.write_text(json.dumps(dict(completed=True,observer_sha256=sha(new),previous_sha256=sha(old),collector_sha256=sha(collector),pairs=pairs,collector_pairs=cp,exact_original_text_after_reversal=True,original_limits32events192KiB8MiB_unchanged=True,original_functions_execute_once_no_new_LRU_get=True),indent=2)+'\n');print(json.dumps(dict(completed=True,observer_sha256=sha(new),collector_sha256=sha(collector))))
