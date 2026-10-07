from pathlib import Path
import os,json,time,hashlib,subprocess,signal,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-nist-external-v5-20261007';stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');log=b/(name+'.log');vectors=b/(name+'-public');assert not any(p.exists() for p in (stagep,out,log,vectors));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();crate=r/'tools/fixtures/pq-hybrid-cross-implementation';source=b/'pq-nist-external-source-v4-20261007-public';receipt=e/'pq-nist-external-source-v4-20261007-checks.json';acquired=json.loads(receipt.read_text());assert acquired['completed'];core=json.loads((e/'core-era-integrated-v11-20261007-core-source.json').read_text());protected={str(p):sha(p) for p in [Path(__file__),receipt,source/'prompt.json',source/'expectedResults.json',crate/'Cargo.toml',crate/'Cargo.lock',crate/'src/main.rs',crate/'src/bin/rld-ml-dsa-87-kat-candidate.rs',r/'tools/pq_authorization_candidate.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json']};protected.update({str(r/v['path']):v['sha256'] for v in core['files']});openssl=Path('/opt/homebrew/opt/openssl@3/bin/openssl');protected.update({str(p):sha(p) for p in [openssl,Path('/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib'),Path('/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libssl.3.dylib')]})
def pins():assert all(sha(Path(p))==h for p,h in protected.items()),'source pin differs'
base=['--manifest-path',str(crate/'Cargo.toml'),'--target-dir','target/pq-tests-rust198-opt1','--config','profile.dev.opt-level=1','--config','profile.dev.debug-assertions=true','--config','profile.dev.overflow-checks=true','--locked','--offline'];commands=[['cargo','fmt','--manifest-path',str(crate/'Cargo.toml'),'--','--check'],['cargo','clippy',*base,'--all-targets','--no-deps','--','-D','warnings'],['cargo','build',*base,'--bin','rld-ml-dsa-87-kat-candidate']]
stage=dict(format='RLD-PQ-NIST-EXTERNAL-V5',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=120,attempts=1,hypothesis='All fifteen exact official NIST ML-DSA-87 external/pure SigVer vectors including context0/255 produce expected validity in OpenSSL3.6.3 and fips2040.4.6, using external message encoding. One120 includes all strict offline compilation and actual verification.',exit='First mismatch, unavailable, pin change or original120 deadline stops; preserve failures; no unchanged retry.',commands=commands,protected_sha256=protected,nist_commit=acquired['nist_commit'],selected_count=15,core_source=core['commitment'],no_private_key_reads=True,no_network=True,no_native_calls=True,adopted_pq_profile=False,whole_goal_completed=False)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');start=time.monotonic();deadline=start+120;results=[];cases=[];files=[];error=None;timedout=False;env=dict(os.environ,RUSTUP_TOOLCHAIN='1.98.0',OPENSSL_CONF='/dev/null');env.pop('OPENSSL_MODULES',None)
def run(command,expected=0):
 global timedout
 pins();at=time.monotonic();assert at<deadline,'deadline exhausted'
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
 for command in commands:run(command)
 binary=r/'target/pq-tests-rust198-opt1/debug/rld-ml-dsa-87-kat-candidate';protected[str(binary)]=sha(binary)
 prompt=json.loads((source/'prompt.json').read_text());answers=json.loads((source/'expectedResults.json').read_text());expected={(g['tgId'],t['tcId']):t['testPassed'] for g in answers['testGroups'] for t in g['tests']};groups=[g for g in prompt['testGroups'] if g['parameterSet']=='ML-DSA-87' and g['signatureInterface']=='external' and g['preHash']=='pure'];assert len(groups)==1 and len(groups[0]['tests'])==15;vectors.mkdir(mode=0o700)
 for g in groups:
  for t in g['tests']:
   label=f"tg{g['tgId']}-tc{t['tcId']}";root=vectors/label;root.mkdir(mode=0o700);key=bytes.fromhex(t['pk']);signature=bytes.fromhex(t['signature']);message=bytes.fromhex(t['message']);context=bytes.fromhex(t['context']);assert len(key)==2592 and len(signature)==4627 and len(message)<=65536 and len(context)<=255
   vals={'public-key.bin':key,'public-key.der':bytes.fromhex('30820a32300b060960864801650304031303820a2100')+key,'signature.bin':signature,'message.bin':message,'context.bin':context}
   for n,data in vals.items():
    p=root/n;p.write_bytes(data);protected[str(p)]=sha(p);files.append(dict(path=str(p.relative_to(r)),sha256=sha(p),bytes=len(data)))
   valid=expected[(g['tgId'],t['tcId'])];assert type(valid) is bool;code=0 if valid else 1
   run([str(binary),str(root/'public-key.bin'),str(root/'signature.bin'),str(root/'message.bin'),str(root/'context.bin')],code)
   command=[str(openssl),'pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',str(root/'public-key.der'),'-in',str(root/'message.bin'),'-sigfile',str(root/'signature.bin'),'-provider','default']
   if context:command+=['-pkeyopt','hexcontext-string:'+context.hex()]
   run(command,code);cases.append(dict(tg_id=g['tgId'],tc_id=t['tcId'],expected_valid=valid,rust_exit=code,openssl_exit=code,message_bytes=len(message),context_bytes=len(context)))
 assert len(cases)==15 and sum(v['expected_valid'] for v in cases)==3;pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:400]
duration=round(time.monotonic()-start,6);completed=error is None and not timedout and duration<=120;binary=r/'target/pq-tests-rust198-opt1/debug/rld-ml-dsa-87-kat-candidate';report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=120,attempts=1,error=error,budget_exhausted=timedout,results=results,cases=cases,files=files,controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),log_sha256=sha(log) if log.exists() else None,cargo_lock_sha256=sha(crate/'Cargo.lock'),actual_binary_sha256=sha(binary) if binary.exists() else None,nist_commit=acquired['nist_commit'],core_source=core['commitment'],core_source_unchanged=error is None,exact_scope='ML-DSA-87 external pure SigVer group5 cases61..75',standard_subset_verified=completed,complete_FIPS204=False,CAVP_validation=False,FIPS140_provider_validation=False,independent_security_audit=False,adopted_pq_profile=False,native_integration=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('results','files')}));raise SystemExit(0 if completed else 1)
