import ast,json,os,subprocess,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';p=b/'bind-bft-prepared-commit-v15-native-v25-20261006.py'
s=p.read_text();anchor='# Added Native hint byte guard';assert s.count(anchor)==1
s=s.replace(anchor,"""v15=(r/'tools/interstellar_mesh.py').read_text();v14=original('tools/interstellar_mesh.py')
reverted=v15.replace('RLD-CONTACT-TRANSIT-SCHEDULER-V15','RLD-CONTACT-TRANSIT-SCHEDULER-V14').replace('commits=[i for items in pending for i in items','commits=[i for i in arrivals')
ast_equal(reverted,v14)
# Added Native hint byte guard""")
compile(s,str(p),'exec');p.write_text(s)
# Resolve actual paths/literal names before invoking the one source-only scope.
q=b/'observe-bft-current-commit-delivery-final-v15-20261006.py';assert q.is_file();compile(q.read_text(),str(q),'exec')
start=time.monotonic();x=subprocess.run([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(p)],cwd=r,timeout=60,capture_output=True,text=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));print(x.stdout);print(x.stderr)
if x.returncode:
 out=r/'docs/operations/evidence/regional-bft-prepared-commit-v15-v25-source-binding-entry-failure-20261006.json';assert not out.exists();out.write_text(json.dumps(dict(completed=False,budget_seconds=60,attempts=1,duration_seconds=time.monotonic()-start,exit_code=x.returncode,stderr=x.stderr,Native_Node_Runtime_socket_fixture_calls=0,new180_allocated=0,new600_allocated=0),indent=2)+'\n')
raise SystemExit(x.returncode)
