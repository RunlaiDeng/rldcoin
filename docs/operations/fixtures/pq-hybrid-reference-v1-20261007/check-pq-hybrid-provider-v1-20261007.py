from pathlib import Path
import json,os,time,hashlib,subprocess,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-hybrid-provider-v1-20261007';private=b/(name+'-private');stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');log=b/(name+'.log');assert not any(p.exists() for p in (private,stagep,out,log))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();exe=Path('/opt/homebrew/opt/openssl@3/bin/openssl').resolve();libs=[Path('/opt/homebrew/Cellar/openssl@3/3.6.3/lib')/n for n in ('libcrypto.3.dylib','libssl.3.dylib')];protected={str(p):sha(p) for p in [exe,*libs,Path(__file__),r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',e/'core-era-integrated-v11-20261007-checks.json',e/'core-era-continuity-reference-v1-qualified-profile-20261007.json',e/'regional-paged-full-fault-head-v16-20261007-checks.json']}
manifest=json.loads((e/'core-era-integrated-v11-20261007-core-source.json').read_text());protected.update({str(r/v['path']):v['sha256'] for v in manifest['files']});receipt=json.loads((r/'docs/WHITEPAPER_FREEZE_RECEIPT.json').read_text())
for field in ('canonical_markdown','pdf'):protected[str(r.parent/'rldcoin-website'/receipt[field]['path'])]=receipt[field]['sha256']
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
stage=dict(format='RLD-PQ-HYBRID-PROVIDER-V1',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),hypothesis='Existing pinned OpenSSL3.6.3 can execute Ed25519 AND ML-DSA-87 over the same candidate intent and refuse changed messages/context/key and either missing/altered half. Capability experiment only; no cryptographic profile adoption or Native integration.',budget_seconds=60,attempts=1,exit='First unexpected command outcome, assertion, source pin failure or original60 deadline; preserve all new private files, no retry or existing fixture opens.',protected_sha256=protected,network_calls=0,native_runtime_node_calls=0,mainnet=False,whole_goal_completed=False)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');os.umask(0o077);private.mkdir(mode=0o700);started=time.monotonic();deadline=started+60;commands=[];observations={};error=None;env=dict(os.environ,OPENSSL_CONF='/dev/null');env.pop('OPENSSL_MODULES',None)
def call(args,expected=0):
 at=time.monotonic();remaining=deadline-at;assert remaining>0
 result=subprocess.run([str(exe),*args],cwd=r,env=env,capture_output=True,timeout=min(5,remaining));commands.append(dict(command=[str(exe),*args],expected=expected,exit_code=result.returncode,duration_seconds=round(time.monotonic()-at,6)))
 with log.open('ab') as f:f.write(result.stdout+result.stderr)
 assert result.returncode==expected,(args[0],result.returncode,expected)
 return result.stdout
def verify(label,message,signature,expected=0,context='RLDCOIN-PQ-AUTH-CANDIDATE-V1',pub=None):
 opts=['-pkeyopt','context-string:'+context] if label=='pq' else []
 call(['pkeyutl','-verify','-rawin','-pubin','-inkey',str(pub or private/(label+'-public.pem')),'-in',str(message),'-sigfile',str(signature),'-provider','default',*opts],expected)
try:
 observations['openssl_version']=call(['version']).decode().strip()
 for label,algorithm in [('ed','ED25519'),('pq','ML-DSA-87'),('wrong-pq','ML-DSA-87')]:
  call(['genpkey','-algorithm',algorithm,'-provider','default','-out',str(private/(label+'-secret.pem'))])
  call(['pkey','-in',str(private/(label+'-secret.pem')),'-pubout','-provider','default','-out',str(private/(label+'-public.pem'))])
  call(['pkey','-in',str(private/(label+'-secret.pem')),'-pubout','-outform','DER','-provider','default','-out',str(private/(label+'-public.der'))])
 message=private/'intent.bin';message.write_bytes(b'RLDCOIN-HYBRID-AUTH-CANDIDATE-V1\0'+json.dumps(dict(candidate_only=True,currency_root='01'*32,region_root='02'*32,purpose='PAYMENT',epoch=1,nonce=1,payload_root='03'*64),sort_keys=True,separators=(',',':')).encode());changed=private/'changed-intent.bin';changed.write_bytes(message.read_bytes()+b'X')
 for label in ('ed','pq'):
  opts=['-pkeyopt','context-string:RLDCOIN-PQ-AUTH-CANDIDATE-V1'] if label=='pq' else []
  signature=private/(label+'-signature.bin');call(['pkeyutl','-sign','-rawin','-inkey',str(private/(label+'-secret.pem')),'-in',str(message),'-out',str(signature),'-provider','default',*opts]);assert signature.stat().st_size=={'ed':64,'pq':4627}[label];verify(label,message,signature);verify(label,changed,signature,1)
 verify('pq',message,private/'pq-signature.bin',1,context='RLDCOIN-WRONG-PURPOSE')
 verify('pq',message,private/'pq-signature.bin',1,pub=private/'wrong-pq-public.pem')
 for label in ('ed','pq'):
  data=bytearray((private/(label+'-signature.bin')).read_bytes());data[len(data)//2]^=1;altered=private/(label+'-altered-signature.bin');altered.write_bytes(data);verify(label,message,altered,1)
 observations.update(ed_signature_bytes=64,pq_signature_bytes=4627,combined_signature_bytes=4691,ed_public_der_bytes=(private/'ed-public.der').stat().st_size,pq_public_der_bytes=(private/'pq-public.der').stat().st_size,changed_message_both_refused=True,changed_pq_context_refused=True,wrong_pq_key_refused=True,changed_signature_both_refused=True)
 pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:350]
duration=round(time.monotonic()-started,6);completed=error is None and duration<=60;inventory=[dict(path=str(p.relative_to(private)),sha256=sha(p),bytes=p.stat().st_size,mode=oct(p.stat().st_mode&0o777)) for p in sorted(private.iterdir()) if p.is_file()];seal=private/'PRIVATE_INVENTORY.json';seal.write_text(json.dumps(dict(files=inventory),indent=2)+'\n');report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=60,attempts=1,error=error,observations=observations,commands=commands,controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),log_sha256=sha(log) if log.exists() else None,private_inventory_sha256=sha(seal),private_file_count=len(inventory),openssl_binary_sha256=protected[str(exe)],openssl_library_sha256={str(p):protected[str(p)] for p in libs},core_source=manifest['commitment'],core_source_unchanged=error is None,primitive_and_negative_checks_only=True,hybrid_AND_policy_implemented=False,standard_KAT_qualified=False,independent_implementation_qualified=False,native_integration_qualified=False,mainnet=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','openssl_library_sha256')}));raise SystemExit(0 if completed else 1)
