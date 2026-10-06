from pathlib import Path
import datetime,hashlib,json,os,subprocess
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin')
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence'
controller=b/'check-bft-four-cli-service-first-service-diag-v35-allocated-preview-20261006.py'
decision=e/'regional-bft-four-cli-deferred-slot-v35-decision-allocated-20261006.json'
receipt=e/'regional-bft-four-cli-v35-owned-controller-launch-20261007.json'
log=b/'regional-bft-four-cli-v35-owned-controller-20261007.log'
assert not receipt.exists() and not log.exists()
q=json.loads(decision.read_text());assert q['new180_allocated']==1 and q['conditional_real_scope_budget_seconds']==180 and q['conditional_real_scope_attempts']==1
assert not Path(q['root']).exists()
assert not (e/'regional-bft-four-cli-service-first-service-diag-v35-20261006-stage.json').exists()
assert not (e/'regional-bft-deferred-slot-entry-start-allocated-v35-20261006.json').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for path,digest in q['protected_sha256'].items():assert sha(Path(path))==digest
with log.open('xb') as stream:
 child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(controller)],cwd=r,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
out=dict(recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),owned_controller_pid=child.pid,controller_sha256=sha(controller),launcher_sha256=sha(Path(__file__)),decision_sha256=sha(decision),workdir=str(r),original_budget_seconds=180,attempts=1,finite_original_controller_detached_from_interactive_session=True,no_new_task_or_permission_change=True)
with receipt.open('x') as stream:stream.write(json.dumps(out,indent=2)+'\n')
print(json.dumps(out),flush=True)
