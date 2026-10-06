import json,os,subprocess,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');p=r/'tmp/default-relay-20260930/bind-bft-current-commit-v14-native-v24-20261006.py';start=time.monotonic();x=subprocess.run([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(p)],cwd=r,timeout=60,capture_output=True,text=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));print(x.stdout);print(x.stderr)
if x.returncode:
 out=r/'docs/operations/evidence/regional-bft-current-commit-v14-v24-source-binding-entry-failure-20261006.json';assert not out.exists();out.write_text(json.dumps(dict(completed=False,budget_seconds=60,attempts=1,duration_seconds=time.monotonic()-start,exit_code=x.returncode,stderr=x.stderr,Native_Node_Runtime_socket_fixture_calls=0,new180_allocated=0,new600_allocated=0),indent=2)+'\n')
raise SystemExit(x.returncode)
