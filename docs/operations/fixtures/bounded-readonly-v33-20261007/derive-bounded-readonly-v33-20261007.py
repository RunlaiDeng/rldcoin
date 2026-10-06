from pathlib import Path
import ast,re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930'
helper_old=b/'observe-bft-four-cli-service-first-service-diag-v32-20261006.py';controller_old=b/'check-bft-four-cli-service-first-service-diag-v32-allocated-preview-20261006.py'
m={'bft_warm_owner_delivery_precondition_v13_20261006':'bft_bounded_readonly_delivery_precondition_v14_20261007','bft_four_cli_first_service_diagnostic_v17_20261006':'bft_four_cli_first_service_diagnostic_v18_20261007','regional-bft-warm-owner-v22-identity-20261006.json':'regional-bft-bounded-readonly-v33-identity-20261007.json','service-first-service-diag-v32':'service-first-service-diag-v33','regional-bft-four-cli-warm-owner-v32-decision-allocated-20261006.json':'regional-bft-four-cli-bounded-readonly-v33-decision-allocated-20261007.json','regional-bft-warm-owner-entry-start-allocated-v32-20261006.json':'regional-bft-bounded-readonly-entry-start-allocated-v33-20261007.json','bind_bft_four_cli_warm_owner_v32_20261006':'bind_bft_four_cli_bounded_readonly_v33_20261007'}
def literals(s):return re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda z:m[z[0]],s)
h=literals(helper_old.read_text());a=h.index(' for label,rows in p.regions.items():\n  states[label]=[]\n');z=h.index(' wallet,caller,_=p.owner;',a);old=h[a:z]
a2=old.index('   p.remaining();');z2=old.index("  assert all(state==states[label][0]");body=old[a2:z2]
body=body.replace("states[label].append(state)","local_state=state").replace("cold_messages+=report['messages_authenticated']","local_messages=report['messages_authenticated']").replace("mesh_files+=len(inventory(Path(transport[n]['state'])))","local_mesh_files=len(inventory(Path(transport[n]['state'])))")
body='\n'.join(line[3:] if line.startswith('   ') else line for line in body.splitlines())
replacement=""" from concurrent.futures import ThreadPoolExecutor
 def verify_replica_readonly(job):
  label,n,row=job
  local_messages=local_mesh_files=0
"""+'\n'.join('  '+line for line in body.splitlines())+"""
  return label,n,local_state,local_messages,local_mesh_files
 jobs=[(label,n,row) for label,rows in p.regions.items() for n,row in enumerate(rows)]
 assert len(jobs)==8 and len({str(row['ledger']) for _,_,row in jobs})==8
 with ThreadPoolExecutor(max_workers=4) as pool:
  checked=list(pool.map(verify_replica_readonly,jobs))
 for label,n,state,messages,files in checked:
  states.setdefault(label,[]).append(state);cold_messages+=messages;mesh_files+=files
 for label,rows in p.regions.items():
  assert len(states[label])==4
  assert all(state==states[label][0] for state in states[label]),'four certified Native ledgers differ'
"""
h=h[:a]+replacement+h[z:]
c=literals(controller_old.read_text());a=c.index(' for p,rows in sealed.items():');z=c.index(' for p,h in typed.items():',a);cold=c[a:z]
replacement2=""" from concurrent.futures import ThreadPoolExecutor
 worker=b/'readonly_inventory_worker_v1_20261007.py'
 def verify_inventory_readonly(job):
  p,d=job
  assert sha(Path(p))==seals[p]
  answer=subprocess.run([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(worker),d,p,seals[p]],cwd=r,capture_output=True,timeout=30,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
  assert answer.returncode==0 and answer.stderr==b'' and json.loads(answer.stdout)['completed'],'retained sealed private bytes changed'
 jobs=[(p,d) for p,rows in sealed.items() for d in rows]
 with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(verify_inventory_readonly,jobs))
"""
c=c[:a]+replacement2+c[z:]
for name,s in [('observe-bft-four-cli-service-first-service-diag-v33-20261006.py',h),('check-bft-four-cli-service-first-service-diag-v33-allocated-preview-20261006.py',c)]:
 path=b/name;assert not path.exists();compile(s,str(path),'exec');path.write_text(s)
# Publish exact transformations, old blocks, and new blocks for independent AST checks.
import json
out=b/'bounded-readonly-v33-transformation-20261007.json';assert not out.exists();out.write_text(json.dumps(dict(literals=m,old_cold=old,new_cold=replacement,old_pins=cold,new_pins=replacement2),indent=2)+'\n')
