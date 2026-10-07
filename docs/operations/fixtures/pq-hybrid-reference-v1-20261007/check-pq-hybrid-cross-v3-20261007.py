from pathlib import Path
import os,json,time,hashlib,subprocess,signal,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-hybrid-cross-v3-20261007';stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');log=b/(name+'.log');assert not any(p.exists() for p in (stagep,out,log));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();crate=r/'tools/fixtures/pq-hybrid-cross-implementation';manifest=crate/'Cargo.toml';lock=crate/'Cargo.lock';assert not lock.exists();original=b/'pq-hybrid-provider-v1-20261007-private';previous=json.loads((e/'pq-hybrid-policy-v2-20261007-checks.json').read_text());assert previous['completed'];protected={str(p):sha(p) for p in [Path(__file__),manifest,crate/'src/main.rs',r/'tools/pq_authorization_candidate.py',original/'PRIVATE_INVENTORY.json',e/'pq-hybrid-provider-v1-20261007-checks.json',e/'pq-hybrid-policy-v2-20261007-checks.json',e/'core-era-integrated-v11-20261007-checks.json',e/'core-era-continuity-reference-v1-qualified-profile-20261007.json',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json']};core=json.loads((e/'core-era-integrated-v11-20261007-core-source.json').read_text());protected.update({str(r/v['path']):v['sha256'] for v in core['files']});public_names=['ed-public.der','pq-public.der','wrong-pq-public.der','ed-signature.bin','pq-signature.bin','ed-altered-signature.bin','pq-altered-signature.bin','intent.bin','changed-intent.bin'];protected.update({str(original/n):sha(original/n) for n in public_names})
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
base=['--manifest-path',str(manifest),'--target-dir','target/pq-tests-rust198-opt1','--config','profile.dev.opt-level=1','--config','profile.dev.debug-assertions=true','--config','profile.dev.overflow-checks=true'];commands=[['cargo','generate-lockfile','--manifest-path',str(manifest)],['cargo','fetch','--manifest-path',str(manifest),'--locked'],['cargo','clippy',*base,'--locked','--offline','--no-deps','--','-D','warnings'],['cargo','build',*base,'--locked','--offline']]
stage=dict(format='RLD-PQ-HYBRID-CROSS-V3',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=120,attempts=1,hypothesis='Independent Rust fips2040.4.6 ML-DSA-87 and ed25519-dalek2.1.1 both verify exactly the public OpenSSL3.6.3 dual signature vector and reject either bad/missing half, altered message/context/key. Original120 includes dependency resolution/fetch/strict compilation and all actual checks; no private-key reads or network disclosure of vectors.',exit='First error/pin failure or original120 deadline; retain FAIL and actual build artifacts; no unchanged retry.',commands=commands,protected_sha256=protected,core_source=core['commitment'],core_file_count=core['file_count'],cargo_registry_reads_only=True,standard_KAT_qualification=False,native_integration_qualification=False,whole_goal_completed=False)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');start=time.monotonic();deadline=start+120;results=[];cases=[];error=None;timedout=False;env=dict(os.environ,RUSTUP_TOOLCHAIN='1.98.0')
def run(command,expected=0):
 global timedout
 pins();at=time.monotonic();assert at<deadline
 with log.open('ab') as stream:
  process=subprocess.Popen(command,cwd=r,env=env,stdout=stream,stderr=stream,start_new_session=True)
  try:code=process.wait(timeout=max(.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   timedout=True;os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
   code=process.returncode
 results.append(dict(command=command,expected=expected,exit_code=code,duration_seconds=round(time.monotonic()-at,6),terminal=process.poll() is not None));assert code==expected and not timedout,('unexpected outcome',command[0],code,expected)
try:
 for n,command in enumerate(commands):
  run(command)
  if n==0:protected[str(lock)]=sha(lock)
 binary=r/'target/pq-tests-rust198-opt1/debug/rld-pq-hybrid-interop-candidate';protected[str(binary)]=sha(binary)
 common=[str(binary),str(original/'ed-public.der'),str(original/'pq-public.der'),str(original/'ed-signature.bin'),str(original/'pq-signature.bin'),str(original/'intent.bin')]
 def case(label,command,expected):run(command,expected);cases.append(dict(case=label,exit_code=expected))
 case('both-real-provider-signatures',common,0)
 altered=common.copy();altered[3]=str(original/'ed-altered-signature.bin');case('valid-pq-forged-ed',altered,1)
 altered=common.copy();altered[4]=str(original/'pq-altered-signature.bin');case('valid-ed-forged-pq',altered,1)
 altered=common.copy();altered[2]=str(original/'wrong-pq-public.der');case('wrong-pinned-pq-key',altered,1)
 altered=common.copy();altered[5]=str(original/'changed-intent.bin');case('changed-intent',altered,1)
 case('wrong-nist-purpose-context',common+['RLDCOIN-WRONG-PURPOSE'],1)
 empty=b/(name+'-empty-public-signature.bin');assert not empty.exists();empty.write_bytes(b'');protected[str(empty)]=sha(empty)
 for index,label in [(3,'missing-ed-half'),(4,'missing-pq-half')]:
  altered=common.copy();altered[index]=str(empty);case(label,altered,1)
 pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:400]
duration=round(time.monotonic()-start,6);completed=error is None and not timedout and duration<=120;binary=r/'target/pq-tests-rust198-opt1/debug/rld-pq-hybrid-interop-candidate';report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=120,attempts=1,error=error,budget_exhausted=timedout,results=results,cases=cases,controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),log_sha256=sha(log) if log.exists() else None,cargo_lock_sha256=sha(lock) if lock.exists() else None,actual_binary_sha256=sha(binary) if binary.exists() else None,core_source=core['commitment'],core_source_unchanged=error is None,openssl_to_rust_dual_signature_interoperability=completed,standard_KAT_qualified=False,independent_security_audit=False,independent_custody=False,adopted_pq_profile=False,native_integration=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}));raise SystemExit(0 if completed else 1)
