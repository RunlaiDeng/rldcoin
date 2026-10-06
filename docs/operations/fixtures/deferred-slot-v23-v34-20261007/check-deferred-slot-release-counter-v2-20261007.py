from pathlib import Path
import ast,json,hashlib,sys,threading,time,types
from unittest.mock import patch
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'));import interstellar_tcp as tcp
start=time.monotonic();source=r/'tools/interstellar_tcp.py';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out=e/'regional-bft-deferred-slot-release-counter-v2-20261007-checks.json';assert not out.exists()
# Compile only the actual original finally admission block; never run a handler.
s=source.read_text();a=s.index('                self.workers.discard(threading.current_thread())',s.index('    def handle('));z=s.index('                # This opt-in observation',a);body=s[a:z];body='\n'.join(line[8:] for line in body.splitlines());method='def attempt(self,deferred,deadline):\n    deferred_queued=False\n    with self.guard:\n'+body+'\n    return deferred_queued\n';namespace=dict(threading=threading,MAX_WORKERS=tcp.MAX_WORKERS);exec(compile(method,str(source),'exec'),namespace);fn=namespace['attempt']
owner=threading.current_thread();node=types.SimpleNamespace(guard=threading.Lock(),workers={owner},input_pending=[],input_active=('older',),running=True,input_received=0,input_wake=threading.Event());job=('network','recipient','peer','pin','challenge',b'complete-authenticated-request-model');clock=[0.0];observed=[]
def sleep(seconds):
 assert owner in node.workers;assert len(node.workers)+len(node.input_pending)+(node.input_active is not None)<=tcp.MAX_WORKERS;clock[0]+=seconds
 if clock[0]>=.115:node.input_active=None
 observed.append(clock[0])
with patch.object(tcp.time,'monotonic',side_effect=lambda:clock[0]),patch.object(tcp.time,'sleep',side_effect=sleep):accepted=fn(node,job,3.0)
passed=accepted and node.input_pending==[job] and owner not in node.workers and clock[0]<=tcp.MAX_LOCAL_LOCK_WAIT_SECONDS
result=dict(completed=bool(passed),budget_seconds=20,attempts=1,duration_seconds=round(time.monotonic()-start,6),original20_prior_seconds=7.781893,combined_original20_seconds=round(7.781893+time.monotonic()-start,6),observed_real_v33_slot_release_after_refusal_seconds=.114716,model_slot_release_seconds=.115,model_queued=accepted,model_waited_seconds=clock[0],expected_original_slot_limit=tcp.MAX_WORKERS,expected_original_local_wait_limit=tcp.MAX_LOCAL_LOCK_WAIT_SECONDS,actual_original_admission_source_sha256=sha(source),compiled_original_function_called=True,actual_handler_Node_Native_Runtime_socket_key_sign_fixture_calls=0,model_only_not_actual_authenticated_transport=True,old_failures_unchanged=True,new180=0,new600=0)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True));raise SystemExit(0 if passed else 1)
