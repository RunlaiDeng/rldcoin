from pathlib import Path
import os,json,time,hashlib,subprocess,signal,selectors,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-tls-native-v1-20261007';stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');root=b/(name+'-private');log=b/(name+'.log');binary=b/(name+'-binary');assert not any(p.exists() for p in (stagep,out,root,log,binary));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();source=r/'tools/fixtures/pq-tls-candidate/transport.c';openssl=Path('/opt/homebrew/opt/openssl@3/bin/openssl');prefix=Path('/opt/homebrew/Cellar/openssl@3/3.6.3');clang=Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang');core=json.loads((e/'core-hybrid-integrated-v9-20261007-core-source.json').read_text());headers=sorted((prefix/'include/openssl').glob('*.h'));assert 1<len(headers)<512;protected={str(p):sha(p) for p in [Path(__file__),source,openssl,clang,prefix/'lib/libssl.3.dylib',prefix/'lib/libcrypto.3.dylib',r/'tools/interstellar_tcp.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',e/'core-hybrid-integrated-v9-20261007-checks.json',e/'core-hybrid-bounded-reference-v2-qualified-profile-20261007.json',b/'core-hybrid-integrated-v9-20261007-qualified-test-binary',*headers]};protected.update({str(r/v['path']):v['sha256'] for v in core['files']})
def pins():assert all(sha(Path(p))==h for p,h in protected.items()),'source/provider/compiler pin differs'
build=[str(clang),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-pedantic','-I'+str(prefix/'include'),'-L'+str(prefix/'lib'),'-Wl,-rpath,'+str(prefix/'lib'),'-DRLD_TLS_CANDIDATE_SOURCE="'+sha(source)+'"',str(source),'-lssl','-lcrypto','-o',str(binary)]
stage=dict(format='RLD-PQ-TLS-NATIVE-V1',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=60,attempts=1,hypothesis='Existing Python ssl3.14.7 set_ecdh_curve rejects provider-only hybrid group and exposes no negotiated-group getter; actual owned native OpenSSL API is required. Loopback candidate must enforce TLS1.3, onlyX25519MLKEM768, onlymldsa87 authentication, AES256GCM_SHA384, mutual exact self-signed peer trust/pins and validity before any public marker. Verify actual negotiated group by supportedSSL_get0_group_name, refuse classical group/auth/TLS1.2, absent clientcert and wrongpin. One60 includes strict native compile, fresh fixture keys/certificates, six actual sessions and immutable sealing. No default Node/source/config modification, external network or old fixture.',exit='First compile/pin/outcome error or original60 stops; retain FAIL, owned-process terminal state and fresh private fixture; no unchanged retry.',build=build,protected_sha256=protected,core_source=core['commitment'],header_count=len(headers),native_Node_Runtime_calls=0,loopback_only=True,existing_production_source_unchanged=True,adopted_transport_profile=False,independent_review=False,whole_goal_completed=False)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');start=time.monotonic();deadline=start+60;results=[];cases=[];owned=[];error=None;timedout=False;oldmask=os.umask(0o077);root.mkdir(mode=0o700);env=dict(os.environ,OPENSSL_CONF='/dev/null');env.pop('OPENSSL_MODULES',None)
def remaining(limit=10):
 left=deadline-time.monotonic();assert left>0,'original60 exhausted';return min(limit,left)
def record(command,code,stdout,stderr,at):
 with log.open('ab') as stream:stream.write(stdout+stderr)
 results.append(dict(command=command,exit_code=code,duration_seconds=round(time.monotonic()-at,6)))
def run(command,expected=0,stdin=None,limit=10):
 at=time.monotonic();pins();p=subprocess.Popen(command,cwd=r,env=env,stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);owned.append(p)
 output,errors=p.communicate(input=stdin,timeout=remaining(limit));record(command,p.returncode,output,errors,at);assert p.returncode==expected,('unexpected exit',command[0],p.returncode,expected);return output,errors
try:
 run(build);protected[str(binary)]=sha(binary);assert sha(source).encode() in binary.read_bytes()
 for role in ('server','client'):
  run([str(openssl),'genpkey','-algorithm','ML-DSA-87','-provider','default','-out',str(root/(role+'-key.pem'))])
  run([str(openssl),'req','-new','-x509','-key',str(root/(role+'-key.pem')),'-out',str(root/(role+'-cert.pem')),'-days','90','-subj','/CN=RLD-PQ-TLS-CANDIDATE-'+role,'-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=serverAuth,clientAuth','-addext','subjectAltName=IP:127.0.0.1','-provider','default'])
  run([str(openssl),'x509','-in',str(root/(role+'-cert.pem')),'-outform','DER','-out',str(root/(role+'-cert.der'))])
  for suffix in ('key.pem','cert.pem','cert.der'):protected[str(root/(role+'-'+suffix))]=sha(root/(role+'-'+suffix))
 serverpin=sha(root/'server-cert.der');clientpin=sha(root/'client-cert.der')
 for label in ('genuine-mutual-hybrid','classical-group','classical-auth','TLS1.2','missing-client-cert','wrong-server-pin'):
  pins();at=time.monotonic();command=[str(binary),'server','0',str(root/'server-cert.pem'),str(root/'server-key.pem'),str(root/'client-cert.pem'),clientpin];server=subprocess.Popen(command,cwd=r,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);owned.append(server)
  with selectors.DefaultSelector() as selector:
   selector.register(server.stdout,selectors.EVENT_READ);assert selector.select(remaining(3.5)),'server readiness unavailable';ready=server.stdout.readline()
  assert ready.startswith(b'READY '),('server rejected before ready',ready[:80]);port=int(ready.split()[1]);assert 1<=port<=65535
  if label in ('genuine-mutual-hybrid','wrong-server-pin'):
   clientcommand=[str(binary),'client',str(port),str(root/'client-cert.pem'),str(root/'client-key.pem'),str(root/'server-cert.pem'),serverpin if label=='genuine-mutual-hybrid' else '00'*32];clientoutput,clienterrors=run(clientcommand,0 if label=='genuine-mutual-hybrid' else 1,limit=4)
  else:
   clientcommand=[str(openssl),'s_client','-connect','127.0.0.1:'+str(port),'-brief','-no_ign_eof','-verify_return_error','-CAfile',str(root/'server-cert.pem'),'-groups','X25519' if label=='classical-group' else 'X25519MLKEM768','-sigalgs','ed25519' if label=='classical-auth' else 'mldsa87','-tls1_2' if label=='TLS1.2' else '-tls1_3','-provider','default']
   if label!='missing-client-cert':clientcommand+=['-cert',str(root/'client-cert.pem'),'-key',str(root/'client-key.pem')]
   clientoutput,clienterrors=run(clientcommand,1,stdin=b'RLD-PQ-TLS-CANDIDATE-V1:ping',limit=4)
  output,errors=server.communicate(timeout=remaining(4));record(command,server.returncode,ready+output,errors,at);expected=0 if label=='genuine-mutual-hybrid' else 1;assert server.returncode==expected,('server unexpected',label,server.returncode)
  if expected==0:
   reports=[json.loads(v.decode().strip()) for v in (clientoutput,output)]
   assert all(v['group']=='X25519MLKEM768' and v['tls']=='TLSv1.3' and v['cipher']=='TLS_AES_256_GCM_SHA384' and v['peer_algorithm']=='ML-DSA-87' and v['public_marker_verified'] and v['implementation_source']==sha(source) for v in reports)
  else:
   assert b'public_marker_verified' not in output+clientoutput
   if label=='wrong-server-pin':assert b'peer or negotiated policy refused' in clienterrors
   else:assert b'TLS handshake refused' in errors
  cases.append(dict(case=label,client_exit=expected,server_exit=expected,application_marker_accepted=expected==0,loopback_port=port));pins()
 assert len(cases)==6;pins()
except BaseException as ex:
 error=type(ex).__name__+': '+str(ex)[:400];timedout=isinstance(ex,subprocess.TimeoutExpired) or time.monotonic()>=deadline
finally:
 for p in owned:
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=2)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2)
 os.umask(oldmask)
files=[]
for p in sorted(root.iterdir()):
 st=p.lstat();assert p.is_file() and not p.is_symlink();files.append(dict(path=p.name,sha256=sha(p),bytes=st.st_size,mode=oct(st.st_mode&0o777),uid=st.st_uid,inode=st.st_ino,mtime_ns=st.st_mtime_ns))
seal=root/'PRIVATE_INVENTORY.json';seal.write_text(json.dumps(dict(format='RLD-PQ-TLS-PRIVATE-INVENTORY-V1',private=True,files=files),indent=2)+'\n');duration=round(time.monotonic()-start,6);completed=error is None and not timedout and duration<=60 and all(p.poll() is not None for p in owned);report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=60,attempts=1,error=error,budget_exhausted=timedout,results=results,cases=cases,owned_processes_stopped=all(p.poll() is not None for p in owned),controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),log_sha256=sha(log) if log.exists() else None,source_sha256=sha(source),actual_binary_sha256=sha(binary) if binary.exists() else None,openssl_binary_sha256=sha(openssl),private_inventory_sha256=sha(seal),private_file_count=len(files),core_source=core['commitment'],core_source_unchanged=error is None,existing_tcp_source_unchanged=error is None,native_Node_Runtime_calls=0,loopback_only=True,hybrid_group_negotiated=completed,MLDSA87_mutual_peer_authentication=completed,independent_security_review=False,existing_node_transport_integration=False,physical_link=False,adopted_profile=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}));raise SystemExit(0 if completed else 1)
