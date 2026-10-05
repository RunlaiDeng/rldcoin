"""One bounded V8 no-value ground drill; never an adopted/mainnet operation.

Four fresh stores and separate fixture caller heads are explicitly prepared.
Only three ordinary native/pinned-TLS processes start; the actual round0 leader
stays stopped. The live controller only starts/stops and observes, never creates
or delivers protocol messages. Cold MeshInspection uses setup-retained public
anchors, does not open identities, and refuses configuration mismatches.

Requires the existing exact source-bound V8 build and local reviewed manifests.
Generated key/config/wallet/ledger stores remain private under tmp; reports are
sanitized engineering evidence. All failures remain failures. No old fixture is
opened, rewritten, resumed or refunded. Fixed one-attempt stage bounds below.
"""
from pathlib import Path
import hashlib,json,os,subprocess,time,datetime,signal,sys,socket
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import interstellar_mesh as mesh
from interstellar_mesh_inspection import MeshInspection,config_commitment
import interstellar_transfer as wire
import interstellar_tcp as tcp
from regional_bft_cold_batch import check_retained
from regional_bft_retention import unpack_state
from regional_contact_node import Native
from regional_bft_node import Runtime,FORMAT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
r=Path(__file__).resolve().parents[1];b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';src=r/'tools/regional-ledger'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();j=lambda x:json.dumps(x,separators=(',',':'),ensure_ascii=False).encode()
enc=lambda d,x:('RLD-REGIONAL-FIXTURE-V1:'+d+'\0').encode()+j(x)
hashid=lambda d,x:hashlib.sha256(enc(d,x)).hexdigest()
keys={i:Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(1,15)}
pub=lambda i:keys[i].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
sign=lambda i,raw:keys[i].sign(raw).hex()
approvals=lambda seeds,raw:sorted([dict(key=pub(i),signature=sign(i,raw)) for i in seeds],key=lambda x:x['key'])
focus=json.loads((e/'regional-native-channel-fee-budget-implementation-checks-20261005.json').read_text());assert focus['completed'];before=focus['source_sha256'];assert all(sha(r/p)==v for p,v in before.items())
h=hashlib.sha256(b'RLD-REGIONAL-CANDIDATE-SOURCE-V1\0')
for rel in sorted(before):
 p=r/rel;n=str(p.relative_to(src)).encode();raw=p.read_bytes();h.update(len(n).to_bytes(8,'big')+n+len(raw).to_bytes(8,'big')+raw)
regional=h.hexdigest();core='de74cf78a22e34f558760be0c3cd1ab39e988dfa20eb2722acc23a35fc527d5c';implementation=hashid('implementation',[regional,core]);rules=hashlib.sha256(b'RLD-REGIONAL-CHANNEL-KERNEL-V8\0'+(src/'src/channel_rules.md').read_bytes()).hexdigest();issuance='a0ae7b36b695c787b840d3726fa1fd55e1d5f3874e173346fbf791b7b2ac2153';profile=hashid('native-channel-profile-v1',[(src/'src/channel_profile.md').read_text(),rules,issuance])
exe=src/'target/debug/rld-regional-ledger-candidate';assert exe.exists()
prior_outcome=json.loads((e/'regional-native-startup-inspection-outcome-20261005.json').read_text())
assert sha(exe)==prior_outcome['native_binary_sha256'] and regional==prior_outcome['regional_source_commitment']
for path,digest in prior_outcome['node_implementation_changed_files'].items():assert sha(r/path)==digest
core_manifest=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text())
core_rows=core_manifest['files']
assert len(core_rows)==171 and all(sha(r/row['path'])==row['sha256'] and (r/row['path']).stat().st_size==row['size_bytes'] for row in core_rows)
freeze_path=r/'docs/WHITEPAPER_FREEZE_RECEIPT.json';assert sha(freeze_path)==prior_outcome['authority']['receipt_sha256']
freeze=json.loads(freeze_path.read_text())
for field in ['canonical_markdown','pdf']:assert sha(r.parent/'rldcoin-website'/freeze[field]['path'])==freeze[field]['sha256']


cold_repair=json.loads((e/'regional-missing-leader-cold-config-counterexample-retry1-20261005-checks.json').read_text());assert cold_repair['completed'] and cold_repair['checks']['strict_cold_mismatched_config_refuses_without_write']
for path,digest in cold_repair['source_sha256'].items():assert sha(r/path)==digest

probe_name='regional-native-channel-fee-budget-missing-leader-retry1-20261005'
node_sources={str(p.relative_to(r)):sha(p) for p in sorted((r/'tools').glob('*.py')) if p.is_file()}
stage=dict(format='RLD-CHANNEL-MISSING-LEADER-NATIVE-TLS-STAGE-V1',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),attempt_budget=1,attempts_started=1,preparation_budget_seconds=180,live_stage_budget_seconds=600,stopped_verification_budget_seconds=180,owned_shutdown_grace_seconds=30,hypothesis='With the actual height6 round0 leader unstarted, three ordinary Native nodes on explicitly pinned connected TLS paths create authenticated timeout/view-change evidence and certify the highest accepted q2 challenge exactly once, without live controller protocol construction or delivery.',regional_source_commitment=regional,implementation_identity=implementation,kernel_rules_hash=rules,profile_hash=profile,binary_sha256=sha(exe),source_sha256=before,node_source_sha256=node_sources,controller_sha256=sha(Path(__file__)),full_fault_campaign_budget=0,round_timeout_seconds=60,maximum_height=24,window_blocks=2016,exit='Preparation180, live600 or cold180 boundary; unexpected refusal, process exit or all-three healthy native q2 inclusion in a genuine later round followed by clean shutdown and strict stopped verification. Preserve all state and failures; no restart or unchanged retry.',authority_fixture_public_key=pub(14),fresh_authority_distinct_from_prior_tls_and_failed_missing_leader_fixtures=True,cold_repair_sha256=sha(e/'regional-missing-leader-cold-config-counterexample-retry1-20261005-checks.json'),prior_missing_leader_failed_sha256=sha(e/'regional-native-channel-fee-budget-missing-leader-20261005-checks.json'),cold_mesh_inspection='Strict read-only MeshInspection with externally retained setup public/config anchors; exact configured missing-carrier state is prepared before live freezing.',transport_scope='Ordinary native lifecycle, IPv4 pinned TLS, configured chain edges plus the explicitly pinned 1--3 edge; actual height6 round0 leader process unstarted. No controller envelope bus, no insecure mode/fallback, no external host/physical qualification.')
sp=e/(probe_name+'-stage.json');assert not sp.exists();sp.write_text(json.dumps(stage,indent=2)+'\n')
root=b/'native-channel-fee-budget-missing-leader-retry1-private-20261005';root.mkdir(mode=0o700)
node=root/'earth-0';wdir=root/'witness';wkey=root/'fixture-key-12.json';whead=None
start=time.monotonic();steps=[];failure=None;runtimes=[];runtime_phases=[];processes={};logs=[];shutdown=[];live_observations=[];verification=[];cold_failure=None;missing_before=None;missing=None;healthy=[];phase='preparation';live_started=None;heads_v={};checkpoint=None;setup_certificates=[]
def budget_expired(*_):raise TimeoutError(phase+' budget exhausted')
signal.signal(signal.SIGALRM,budget_expired);signal.alarm(180)
currency=dict(format='RLD-REGIONAL-FIXTURE-V1',fixture_only=True,implementation=implementation,origin='earth',authority=pub(14),cap=str(10**35),block_reward=str(250000*10**24),maturity=2)
raw=enc('currency',list(currency.values()));currency['signature']=sign(14,raw);pin=hashlib.sha256(raw).hexdigest();validators=sorted(pub(i) for i in [2,3,4,5]);admissions=[]
for region in ['earth','proxima','andromeda']:
 a=dict(currency=pin,region=region,rules='RLD-REGIONAL-BFT-VALUE-CHANNELS-FIXTURE-V8',value_rules=profile,validators=validators)
 a['signature']=sign(14,enc('value-channel-admission-v1',list(a.values())));admissions.append(a)
bootstrap=root/'bootstrap.json';bootstrap.write_bytes(j(dict(currency=currency,admissions=admissions)))
def file(name,value):
 p=root/(name+'.json');p.write_bytes(j(value));return str(p)
def call(action,options=[],valid=True):
 global whead
 if action=='mine':
  opts=list(options);commands=json.loads(Path(opts[opts.index('--commands')+1]).read_text()) if '--commands' in opts else []
  return setup_block(commands)
 options=list(options)
 if action in ['channel-witness-seal','channel-witness-recover-seal']:
  options+=['--witness-dir',str(wdir),'--expected-witness-head',whead]
  if action=='channel-witness-seal':options+=['--key-file',str(wkey)]
 if action.startswith('channel-owner-') and action!='channel-owner-combine':
  options += ['--witness-dir',str(wdir)]
  if '--expected-witness-head' not in options: options += ['--expected-witness-head',whead]
  if action in ['channel-owner-init','channel-owner-sign','channel-owner-finish-witness'] and '--witness-key-file' not in options: options += ['--witness-key-file',str(wkey)]
 command=[str(exe),'--dir',str(node),'--authority',pub(14),'--currency',pin,action,*options]
 q=subprocess.run(command,cwd=r,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=max(.01,180-(time.monotonic()-start)))
 steps.append(dict(action=action,exit_code=q.returncode,expected_success=valid))
 assert (q.returncode==0)==valid,(action,q.stderr[:900])
 (root/f'cli-{len(steps):02d}.json').write_text(q.stdout if q.returncode==0 else q.stderr)
 if not valid:return None
 value=json.loads(q.stdout)
 if action=='channel-receipt-accept':
  for n in range(1,4):
   own_head=raw(n,'history-head')['history_head'];opts=options.copy();opts[opts.index('--expected-head')+1]=own_head;raw(n,action,*opts)
 if 'witness_head' in value and (action.startswith('channel-owner-') or action in ['channel-witness-seal','channel-witness-recover-seal']):
  whead=value['witness_head']
  return value.get('owner',value)
 return value
def ordered(value,names):return {n:value[n] for n in names.split() if n in value}
def typed(value,kind):
 names={'Declaration':'format currency region implementation rules authority_signature','Ledger':'coins exports imports minted received channel_state','Coin':'payment created mature dependencies channel_dependencies','Payment':'owner amount','NativeState':'declaration book','Book':'channels reserves','Escrow':'funding opened dependencies channel_dependencies phase','SignedAction':'intent approvals','Intent':'rules currency region nonce valid_through actor previous action','Reservation':'channel coin fee_limit authorization allocated budget','FeeBudget':'format original_amount max_fee spent','Approval':'key signature'}
 out=ordered(value,names[kind])
 children={'Ledger':{'coins':('map','Coin'),'channel_state':('one','NativeState')},'Coin':{'payment':('one','Payment')},'NativeState':{'declaration':('one','Declaration'),'book':('one','Book')},'Book':{'channels':('map','Escrow'),'reserves':('map','Reservation')},'Escrow':{'funding':('one','SignedAction')},'Reservation':{'coin':('one','Coin'),'authorization':('one','SignedAction'),'budget':('one','FeeBudget')},'SignedAction':{'intent':('one','Intent'),'approvals':('vec','Approval')}}
 for key,(mode,child) in children.get(kind,{}).items():
  if key in out:out[key]=typed(out[key],child) if mode=='one' else {k:typed(v,child) for k,v in sorted(out[key].items())} if mode=='map' else [typed(v,child) for v in out[key]]
 if kind=='Intent':
  variant,data=next(iter(out['action'].items()));out['action']={variant:ordered(data,{'Open':'witness inputs parties capacity initial change fee','Reserve':'channel input fee_limit','ReserveBudget':'channel input fee_limit max_fee','Close':'channel state fee_input fee'}[variant])}
  if variant=='Open':out['action'][variant]['change']=[typed(v,'Payment') for v in out['action'][variant]['change']]
 return out

voter_seeds=sorted([2,3,4,5],key=pub)
def raw(n,*options):
 command=[str(exe),'--dir',str(root/f'earth-{n}'),'--authority',pub(14),'--currency',pin,*map(str,options)]
 q=subprocess.run(command,cwd=r,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=max(.01,180-(time.monotonic()-start)))
 steps.append(dict(action=str(options[0]),replica=n,exit_code=q.returncode,expected_success=True))
 (root/f'raw-{len(steps):03d}.json').write_text(q.stdout if q.returncode==0 else q.stderr)
 assert q.returncode==0,(options[0],q.stderr[:900])
 return json.loads(q.stdout)
def bsign(n,request):
 result=raw(n,'bft-sign','--file',file('setup-vote',request),'--signer-dir',root/f'voter-{n}','--key-file',root/f'voter-key-{n}.json','--expected-head',heads_v[n]);heads_v[n]=result['head'];return result['message']
def qc(votes):return raw(0,'bft-quorum','--file',file('setup-qc',sorted(votes,key=lambda v:v['approval']['key'])))
def setup_block(commands):
 global checkpoint
 assert not any('Challenge' in c.get('Channel',{}).get('action',{}).get('intent',{}).get('action',{}) for c in commands),'controller must never inject a Challenge'
 context=raw(0,'bft-context')['context'];snapshot=raw(0,'bft-candidate','--miner',pub(10),'--commands',file('setup-commands',commands))
 leader=context['parent_height']%4
 proposal=bsign(leader,{'Propose':dict(round=0,snapshot=snapshot,timeout=None)})['Proposal']
 prepared=qc([bsign(n,{'Prepare':proposal})['Vote'] for n in [0,1,2]])
 committed=qc([bsign(n,{'Commit':dict(proposal=proposal,prepared=prepared)})['Vote'] for n in [0,1,2]])
 cert=raw(0,'bft-certify','--file',file('setup-certificate-input',dict(proposal=proposal,prepared=prepared,committed=committed)))
 path=file('setup-certificate',cert)
 for n in range(4):checkpoint=raw(n,'finalize','--file',path)['installed_checkpoint']
 setup_certificates.append(cert)
 return cert
try:
 region=call('init',['--bootstrap',str(bootstrap),'--region','earth'])['region']
 for n,seed in enumerate(voter_seeds):
  if n:raw(n,'init','--bootstrap',bootstrap,'--region','earth')
  key=root/f'voter-key-{n}.json';key.write_bytes(j(dict(secret_key=(bytes([seed])*32).hex())));key.chmod(0o600)
  heads_v[n]=raw(n,'bft-init','--signer-dir',root/f'voter-{n}','--key',pub(seed))['head']
 for _ in range(3):call('mine',['--miner',pub(10)])
 status=call('status');ledger=typed(status['ledger'],'Ledger');empty=dict(channels={},reserves={})
 d=dict(format='RLD-REGIONAL-CHANNEL-KERNEL-V8',currency=pin,region=region,implementation=implementation,rules=rules)
 d['authority_signature']=sign(14,enc('channel-kernel-declaration-v1',list(d.values())))
 parties=sorted([pub(10),pub(11)])
 def action(status,data):
  ledger=typed(status['ledger'],'Ledger');book=ledger.get('channel_state',{}).get('book',empty)
  intent=dict(rules=rules,currency=pin,region=region,nonce=status['height'],valid_through=status['height']+10,actor=pub(10),previous=hashid('channel-kernel-latest-head-v1',[d,ledger,book]),action=data)
  seeds=[10,11] if 'Open' in data else [10]
  return {'Channel':dict(declaration=d,action=dict(intent=intent,approvals=approvals(seeds,enc('channel-action-v1',intent))))},hashid('channel-action-v1',intent)
 inputs=[(k,v) for k,v in ledger['coins'].items() if v['payment']['owner']==pub(10) and v['mature']<=status['height']];input,coin=inputs[0]
 opening=dict(witness=pub(12),inputs=[input],parties=parties,capacity='60',initial=['60','0'],change=[dict(owner=pub(10),amount=str(int(coin['payment']['amount'])-61))],fee='1')
 command,channel=action(status,dict(Open=opening));call('mine',['--miner',pub(10),'--commands',file('open',[command])])
 status=call('status');input=next(k for k,v in status['ledger']['coins'].items() if not v.get('channel_dependencies') and v['mature']<=status['height']+1)
 command,_=action(status,dict(ReserveBudget=dict(channel=channel,input=input,fee_limit='3',max_fee=status['ledger']['coins'][input]['payment']['amount'])));call('mine',['--miner',pub(10),'--commands',file('reserve',[command])])
 native=call('history-head')['history_head'];wkey.write_bytes(j(dict(secret_key=(bytes([12])*32).hex())));wkey.chmod(0o600);whead=call('channel-witness-init',['--witness-dir',str(wdir),'--witness',pub(12),'--expected-head',native])['witness_head'];status_before=call('status');bindings={};heads={};owner_dirs={};parts=[]
 for seed in [10,11]:
  keyfile=root/f'fixture-key-{seed}.json';keyfile.write_bytes(j(dict(secret_key=(bytes([seed])*32).hex())));keyfile.chmod(0o600)
  owner_dirs[seed]=str(root/f'owner-{seed}')
  initialized=call('channel-owner-init',['--owner-dir',owner_dirs[seed],'--owner',pub(seed),'--channel',channel,'--expected-head',native]);bindings[seed]=initialized['binding'];heads[seed]=initialized['owner_head']
  request=initialized['initial_request'];req=file(f'initial-{seed}',request)
  prepared=call('channel-owner-prepare',['--owner-dir',owner_dirs[seed],'--file',req,'--expected-owner-head',heads[seed],'--expected-head',native])
  signed=call('channel-owner-sign',['--owner-dir',owner_dirs[seed],'--file',req,'--key-file',str(keyfile),'--review',prepared['review'],'--expected-owner-head',heads[seed],'--expected-head',native]);assert signed['first_signed_this_call'] and not signed['approvals_complete'];heads[seed]=signed['owner_head'];parts.append(signed['partial'])
 prior_draft=call('channel-owner-combine' ,['--file',file('initial-parts',parts),'--expected-head',native]);assert 'witness' not in prior_draft['Initial']
 prior=call('channel-witness-seal',['--file',file('initial-unsealed',prior_draft),'--expected-head',native])['combined']['Initial'];assert prior['witness']['approval']['key']==pub(12)
 # Fixture controller pre-authorizes the old Close while both fixture owner
 # key files exist. Later watch/challenge steps never read or first-sign keys.
 status=call('status')
 fee_input=next(k for k,v in status['ledger']['coins'].items() if v['payment']['owner']==pub(10) and v['mature']<=status['height']+1)
 old_close,_=action(status,dict(Close=dict(channel=channel,state=prior,fee_input=fee_input,fee='1')))
 assert all((root/f'fixture-key-{seed}.json').exists() for seed in [10,11,12])
 new=dict(statement=dict(currency=pin,region=region,channel=channel,sequence=1,payouts=['50','10']),approvals=[])
 expected=dict(currency=pin,region=region,channel=channel,invoice=hashid('fixture-owner-invoice',1),payer=parties[0],recipient=parties[1],amount='10',challenge_fee='3')
 stmt=dict(format='RLD-NATIVE-CHANNEL-RECEIPT-V1',profile=profile,expected=expected,checkpoint=checkpoint,reserve=input,previous_receipt=None,previous_state=hashid('channel-receipt-state-v1',prior['statement']),next_state=hashid('channel-receipt-state-v1',new['statement']))
 unsigned=dict(statement=stmt,prior=prior,next=new,approvals=[]);request={'Payment':unsigned};req=file('payment-request',request);parts=[]
 for seed in [10,11]:
  prepared=call('channel-owner-prepare',['--owner-dir',owner_dirs[seed],'--file',req,'--expected-owner-head',heads[seed],'--expected-head',native]);old=heads[seed]
  signed=call('channel-owner-sign',['--owner-dir',owner_dirs[seed],'--file',req,'--key-file',str(root/f'fixture-key-{seed}.json'),'--review',prepared['review'],'--expected-owner-head',old,'--expected-head',native])
  parts.append(signed['partial']);heads[seed]=signed['owner_head']
  assert call('history-head')['history_head']==native
  keyfile=root/f'fixture-key-{seed}.json';
  if keyfile.exists():keyfile.unlink()
  # Retain witness key until both-owner state seal is durable.
  retry=call('channel-owner-recover',['--owner-dir',owner_dirs[seed],'--file',req,'--review',prepared['review'],'--expected-owner-head',old,'--expected-head',native]);assert retry['partial']==signed['partial'] and retry['owner_head']==heads[seed] and not retry['first_signed_this_call'];assert not keyfile.exists()
 draft=call('channel-owner-combine',['--file',file('payment-parts',parts),'--expected-head',native]);assert 'witness' not in draft['Payment']['next']
 receipt=call('channel-witness-seal',['--file',file('payment-unsealed',draft),'--expected-head',native])['combined']['Payment'];assert receipt['prior']==prior and len(receipt['next']['approvals'])==len(receipt['approvals'])==2
 # Retain witness key only to authorize the second fresh request; delete all three before Close/challenges.
 recovered=call('channel-witness-recover-seal',['--file',file('payment-seal-recovery',draft),'--expected-head',native]);assert recovered['combined']['Payment']==receipt and not recovered['first_sealed_this_call']
 bad=json.loads(json.dumps(receipt));bad['next']['witness']['approval']['signature']='00'
 assert call('history-head')['history_head']==native

 result=call('channel-receipt-accept',['--file',file('combined-receipt',receipt),'--expectation',file('expectation',expected),'--expected-head',native]);assert result['new_fast_payment_accepted'];assert call('status')['ledger']==status_before['ledger'];assert result['history_head']!=native
 call('history-check',['--expected-head',result['history_head']])
 retry=call('channel-receipt-accept',['--file',file('combined-receipt-retry',receipt),'--expectation',file('expectation-retry',expected),'--expected-head',result['history_head']]);assert retry['exact_retry'] and not retry['new_fast_payment_accepted']
 assert call('history-head')['history_head']==result['history_head'] and call('status')['ledger']==status_before['ledger']
 first_receipt=receipt
 first_result=result
 native=first_result['history_head']
 expected2=dict(expected);expected2.update(invoice=hashid('fixture-owner-invoice',2),amount='2')
 new2=dict(statement=dict(currency=pin,region=region,channel=channel,sequence=2,payouts=['48','12']),approvals=[])
 stmt2=dict(format='RLD-NATIVE-CHANNEL-RECEIPT-V1',profile=profile,expected=expected2,checkpoint=checkpoint,reserve=input,previous_receipt=first_result['receipt_id'],previous_state=hashid('channel-receipt-state-v1',first_receipt['next']['statement']),next_state=hashid('channel-receipt-state-v1',new2['statement']))
 unsigned2=dict(statement=stmt2,prior=first_receipt['next'],next=new2,approvals=[])
 req2=file('second-payment-request',{'Payment':unsigned2});second_parts=[]
 # Public fixture seed files are recreated in the SAME still-current original
 # owner journals for a new q2 request, never recovery or a copied-key claim.
 for seed in [10,11]:
  keyfile=root/f'fixture-key-{seed}.json';keyfile.write_bytes(j(dict(secret_key=(bytes([seed])*32).hex())));keyfile.chmod(0o600)
  prepared2=call('channel-owner-prepare',['--owner-dir',owner_dirs[seed],'--file',req2,'--expected-owner-head',heads[seed],'--expected-head',native])
  signed2=call('channel-owner-sign',['--owner-dir',owner_dirs[seed],'--file',req2,'--key-file',str(keyfile),'--review',prepared2['review'],'--expected-owner-head',heads[seed],'--expected-head',native])
  second_parts.append(signed2['partial']);heads[seed]=signed2['owner_head'];keyfile.unlink()
 second_draft=call('channel-owner-combine',['--file',file('second-payment-parts',second_parts),'--expected-head',native])
 receipt=call('channel-witness-seal',['--file',file('second-unsealed',second_draft),'--expected-head',native])['combined']['Payment'];wkey.unlink()
 recovered2=call('channel-witness-recover-seal',['--file',file('second-seal-recovery',second_draft),'--expected-head',native]);assert recovered2['combined']['Payment']==receipt and not recovered2['first_sealed_this_call'] and not wkey.exists()
 result=call('channel-receipt-accept',['--file',file('second-receipt',receipt),'--expectation',file('second-expectation',expected2),'--expected-head',native]);assert result['accepted_sequence']==2
 assert call('status')['ledger']==status_before['ledger']

 assert all(not (root/f'fixture-key-{seed}.json').exists() for seed in [10,11,12])
 call('mine',['--miner',pub(10),'--commands',file('preauthorized-old-close',[old_close])])
 closed=call('status');close_height=closed['height'];assert close_height==6
 context=raw(0,'bft-context')['context'];assert context['parent_height']==close_height
 missing=context['parent_height']%len(voter_seeds);healthy=[n for n in range(4) if n!=missing]
 assert missing==2 and len(healthy)==3 and [pub(seed) for seed in voter_seeds]==validators
 def target_inventory(paths):
  digest=hashlib.sha256()
  for target in paths:
   for p in [target,*sorted(target.rglob('*'))]:
    assert not p.is_symlink(),'private fixture symlink'
    st=p.stat();row=[str(p.relative_to(root)),st.st_mode,st.st_size if p.is_file() else None,st.st_mtime_ns,sha(p) if p.is_file() else None]
    digest.update(j(row))
  return digest.hexdigest()

 ids={};transports={};anchors={}
 for n in range(4):
  state=root/f'mesh-{n}';identity=mesh.initialize(state,pin,region,f'fee-budget-runtime-{n}')
  anchors[n]=dict(public_key=identity['public_key'],node_id=identity['node_id'],network=pin)
  transports[n]=dict(format=mesh.VERSION,state=str(state),network=pin,contacts=[])
  with mesh.Node(transports[n]) as carrier:ids[n]=carrier.id
 configs={}
 for n,seed in enumerate(voter_seeds):
  head_dir=root/f'caller-{n}';head_dir.mkdir(mode=0o700)
  mesh.atomic(head_dir/'head.json',dict(format=FORMAT,binding=dict(currency=pin,region=region,key=pub(seed)),head=heads_v[n],pending=None,outbox=None))
  config=dict(format=FORMAT,state=str(root/f'runtime-{n}'),signer_dir=str(root/f'voter-{n}'),head_file=str(head_dir/'head.json'),key_file=str(root/f'voter-key-{n}.json'),key=pub(seed),miner=pub(10),validators=[dict(key=pub(s),node_id=ids[i]) for i,s in enumerate(voter_seeds)],block_interval=1,round_timeout=60,stop_height=24)
  path=root/f'runtime-config-{n}.json';mesh.atomic(path,config);configs[n]=path

 # Pin literal neighbors and separate retained TLS identities before starting
 # any ordinary native lifecycle. No endpoints/pins come from advertisements.
 ports={};tls={};held=[]
 try:
  for n in range(4):
   tls[n]=tcp.public_tls_identity(transports[n]);assert tls[n]['node_id']==ids[n]
   sock=socket.socket();sock.bind(('127.0.0.1',0));held.append(sock);ports[n]=sock.getsockname()[1]
 finally:
  for sock in held:sock.close()
 for n in range(4):
  transports[n]['contacts']=[dict(peer=ids[m],host='127.0.0.1',port=ports[m],tls_cert_sha256=tls[m]['tls_cert_sha256']) for m in range(4) if abs(m-n)==1 or {m,n}=={1,3}]
  mesh.atomic(root/f'mesh-config-{n}.json',transports[n])
  # Complete explicit transport configuration before freezing even a carrier
  # whose ordinary native/consensus process will never be started.
  with mesh.Node(transports[n]) as prepared:
   assert prepared.id==ids[n] and not prepared.summaries() and not prepared.receipts()
  anchors[n]['config_sha256']=config_commitment(transports[n])
 mesh.atomic(root/'trusted-transport-anchors.json',anchors)
 missing_targets=[root/f'earth-{missing}',root/f'voter-{missing}',root/f'caller-{missing}',root/f'mesh-{missing}']
 missing_before=target_inventory(missing_targets)
 signal.alarm(0)
 runtime_phases.append(dict(phase='fresh-native-channel-q2-and-pinned-tls-config-prepared',elapsed_seconds=round(time.monotonic()-start,3),missing_leader=missing,healthy_voters=healthy,authority_fixture_seed=14))
 print(json.dumps(runtime_phases[-1]),flush=True)
 phase='live';live_started=time.monotonic();signal.alarm(600)
 for n in healthy:
  log=(root/f'ordinary-node-{n}.log').open('ab');logs.append(log)
  command=[str(exe),'--dir',str(root/f'earth-{n}'),'--authority',pub(14),'--currency',pin,'--mesh-config',str(root/f'mesh-config-{n}.json'),'--bft-config',str(configs[n]),'--mesh-listen','127.0.0.1:'+str(ports[n]),'--transport-python',sys.executable,'--interval','0.25']
  processes[n]=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
 accepted=set();startup_observed=set();cursor=0;last_query=0;last_observation={};last_print=0
 while True:
  for n,proc in processes.items():assert proc.poll() is None,('ordinary node exited',n,proc.returncode)
  for n,proc in processes.items():
   try:
    observed=mesh.load(root/f'mesh-{n}/regional-contact-status.json',mesh.MAX_STATE)
    assert observed['process_id']==proc.pid,'status belongs to another process'
    consensus=observed.get('consensus') or {}
    row=dict(replica=n,native_observation_available=observed.get('native_observation_available'),consensus_observation_available=consensus.get('progress_observation_available',True),height=consensus.get('height'),round=consensus.get('round'),errors=observed.get('errors',[])[:4])
    last_observation[n]=row
    if observed.get('native_observation_available') is True and type(consensus.get('height')) is int:startup_observed.add(n)
   except (OSError,ValueError) as ex:
    last_observation[n]=dict(replica=n,observation_available=False,diagnostic=str(ex)[:200])
  now=time.monotonic()
  if len(startup_observed)==3 and now-last_query>=2:
   n=healthy[cursor%3];cursor+=1;last_query=now
   native=Native(exe,root/f'earth-{n}',pub(14),pin)
   try:
    state=native.call('status');book=state['ledger']['channel_state']['book'];closing=book['channels'][channel]['phase']['Closing'];budget=book['reserves'][input]
    assert state['height']<=24 and closing['close_height']==close_height and closing['deadline']==close_height+2016
    if closing['state']==receipt['next']:
     assert state['height']>=close_height+1 and budget['budget']['spent']=='3'
     assert int(budget['coin']['payment']['amount'])+3==int(budget['budget']['original_amount'])
     if n not in accepted:
      accepted.add(n);row=dict(phase='ordinary-native-tls-q2-observed',replica=n,height=state['height'],fee_spent='3',elapsed_live_seconds=round(time.monotonic()-live_started,3));live_observations.append(row);print(json.dumps(row),flush=True)
   except ValueError as ex:
    text=str(ex)
    assert 'would block' in text or 'temporarily unavailable' in text,'unexpected native observation refusal: '+text
    last_observation[n]=dict(replica=n,native_observation_available=False,diagnostic=text[:200])
  if len(accepted)==3:break
  if now-last_print>=30:
   last_print=now;print(json.dumps(dict(phase='ordinary-live-observation',elapsed_live_seconds=round(now-live_started,3),accepted_replicas=sorted(accepted),ordinary_startups_observed=sorted(startup_observed),observations=last_observation)),flush=True)
  time.sleep(.25)
 live_seconds=round(time.monotonic()-live_started,3);signal.alarm(0)
 runtime_phases.append(dict(phase='all-three-ordinary-tls-q2-observed',elapsed_live_seconds=live_seconds));print(json.dumps(runtime_phases[-1]),flush=True)
except Exception as ex:
 failure=type(ex).__name__+': '+str(ex);print(json.dumps(dict(failure=failure,phase=phase)),flush=True)
finally:
 signal.alarm(0)
 cleanup_started=time.monotonic()
 for n,proc in processes.items():
  if proc.poll() is None:proc.terminate()
 cleanup_deadline=cleanup_started+30
 for n,proc in processes.items():
  forced=False
  try:proc.wait(timeout=max(.01,cleanup_deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   forced=True;os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
  shutdown.append(dict(replica=n,exit_code=proc.returncode,forced=forced))
  if forced or proc.returncode!=0:failure=(failure or '')+'; unclean owned node exit '+str(n)
 for log in logs:log.close()
 cleanup_seconds=round(time.monotonic()-cleanup_started,3)
# Strict stopped verification never opens Runtime, reconciles a caller head,
# initializes custody, recovers a response or first-signs. Keep its temporary
# files outside every private target, including runtime directories.
def inventory():
 h=hashlib.sha256()
 for p in sorted(root.rglob('*')):
  if p.is_symlink():raise ValueError('unexpected private fixture symlink')
  st=p.stat();row=[str(p.relative_to(root)),st.st_mode,st.st_size if p.is_file() else None,st.st_mtime_ns,sha(p) if p.is_file() else None]
  h.update(j(row))
 return h.hexdigest()
if missing_before is not None:
 try:
  phase='stopped-verification';signal.alarm(180);cold_started=time.monotonic();before_private=inventory()
  work=b/'native-channel-fee-budget-missing-leader-retry1-cold-private-20261005';work.mkdir(mode=0o700)
  selected_certificates=[]
  for n in range(4):
   native=Native(exe,root/f'earth-{n}',pub(14),pin)
   state=native.call('status');book=state['ledger']['channel_state']['book'];closing=book['channels'][channel]['phase']['Closing'];budget=book['reserves'][input]
   assert state['height']<=24 and closing['close_height']==6 and closing['deadline']==2022
   if n==missing:
    assert state['height']==6 and closing['state']==prior and budget['budget']['spent']=='0'
   elif failure is None:
    assert state['height']>=7 and closing['state']==receipt['next'] and budget['budget']['spent']=='3'
   spent=int(budget['budget']['spent'])

   assert int(budget['coin']['payment']['amount'])+spent==int(budget['budget']['original_amount'])
   head=native.call('history-head')['history_head'];native.call('history-check','--expected-head',head)
   proof=native.call('proof');matching=[]
   for snapshot in proof['snapshots']:
    for block in snapshot['blocks']:
     commands=block['commands']
     if any(c.get('Channel',{}).get('action',{}).get('intent',{}).get('action',{}).get('Challenge',{}).get('state')==receipt['next'] for c in commands):
      matching.append(snapshot)
   if n in healthy and failure is None:
    assert matching
    earliest=min(matching,key=lambda x:x['statement']['height']);assert earliest['statement']['height']==7
    certified_round=earliest['bft']['prepared']['round'];assert certified_round>0
    for qc in [earliest['bft']['prepared'],earliest['bft']['committed']]:
     ordered=[v['approval']['key'] for v in qc['votes']]
     assert len(ordered)==3 and ordered==sorted(pub(voter_seeds[i]) for i in healthy) and qc['round']==certified_round
    selected_certificates.append(hashid('unanimous-checkpoint',earliest['statement']))

   caller=mesh.load(root/f'caller-{n}/head.json',8*1024*1024);status=native.call('bft-status','--signer-dir',root/f'voter-{n}')
   assert status['head']==caller['head'] and status['binding']==caller['binding'] and caller['pending'] is None and caller['outbox'] is None
   complete_envelopes=0;later_rounds=[]
   state_path=root/f'runtime-{n}/state.json'
   if n==missing:
    assert not state_path.parent.exists(),'missing leader Runtime was created'
   elif state_path.exists():
    retained=unpack_state(mesh.load(state_path,32*1024*1024))
    cold=SimpleNamespace(root=work,native=native,region=region,state=retained)
    check_retained(cold);complete_envelopes=len(retained['messages'])
    if failure is None:
     for ident in retained['messages']:
      envelope=wire.decode_json(retained['messages'].payload(ident))
      proposal=envelope['body'].get('Signed',{}).get('Proposal')
      if proposal and proposal['snapshot']['statement']==earliest['statement']:
       assert proposal['round']==certified_round and proposal['round']>0
       timeout=proposal['timeout'];assert timeout['context']==context and timeout['round']+1==certified_round
       ordered=[v['approval']['key'] for v in timeout['votes']]
       assert ordered==sorted(pub(voter_seeds[i]) for i in healthy)
       assert proposal['leader']['key']==validators[(close_height+certified_round)%4]
       later_rounds.append(certified_round)
     assert later_rounds,'authenticated later-round Proposal/TC absent'
   else:
    assert failure is not None,'healthy runtime absent despite live success'

   with MeshInspection(transports[n],**anchors[n]) as node:
    packets=len(node.summaries());receipts_retained=len(node.receipts())
   row=dict(replica=n,height=state['height'],verified_complete_envelopes=complete_envelopes,authenticated_later_rounds=later_rounds,missing_leader=n==missing,fee_spent=budget['budget']['spent'],retained_packets=packets,retained_receipts=receipts_retained,native_head_and_caller_head_verified=True)
   verification.append(row);print(json.dumps(dict(phase='strict-stopped-native-envelope-mesh-caller-check',**row)),flush=True)
  if failure is None:assert len(selected_certificates)==3 and len(set(selected_certificates))==1
  assert target_inventory(missing_targets)==missing_before,'unstarted leader state/head changed'
  assert inventory()==before_private,'stopped verification changed private bytes/metadata'
  assert all(not (root/f'fixture-key-{seed}.json').exists() for seed in [10,11,12])
  cold_seconds=round(time.monotonic()-cold_started,3)
 except Exception as ex:
  cold_failure=type(ex).__name__+': '+str(ex);failure=(failure or '')+'; stopped-check '+cold_failure;print(json.dumps(dict(failure=failure,phase=phase)),flush=True)
 finally:signal.alarm(0)
assert all(sha(r/p)==v for p,v in before.items()) and all(sha(r/p)==v for p,v in node_sources.items())
report=dict(strict_publicly_anchored_readonly_mesh_inspection_used=True,source_core_freeze_preflight_verified=True,report_authority_fixture_public_key=pub(14),format='RLD-CHANNEL-MISSING-LEADER-NATIVE-TLS-CHECKS-V1',completed=failure is None,failure=failure,duration_seconds=round(time.monotonic()-start,3),runtime_phases=runtime_phases,live_observations=live_observations,stopped_verification=verification,shutdown=shutdown,cleanup_seconds=cleanup_seconds,regional_source_commitment=regional,implementation_identity=implementation,kernel_rules_hash=rules,value_profile_rules_hash=profile,core_source_commitment=core,binary_sha256=sha(exe),source_sha256=before,node_source_sha256=node_sources,controller_sha256=sha(Path(__file__)),attempts_used=1,preparation_budget_seconds=180,live_stage_budget_seconds=600,stopped_verification_budget_seconds=180,round_timeout_seconds=60,maximum_height=24,window_blocks=2016,fresh_signed_zero_allocation_fixture=True,public_fixture_seeds_only=True,ordinary_native_node_startup_pinned_tls_explicit_connected_neighbors_verified=failure is None,ordinary_receive_and_runtime_certification_verified=failure is None,controller_live_envelope_delivery=False,controller_live_vote_quorum_certificate_challenge_creation=False,all_owner_witness_key_files_absent_during_live=live_started is not None,missing_leader=missing,healthy_voters=healthy,missing_leader_native_voter_caller_transport_unchanged=missing_before is not None and cold_failure is None and len(verification)==4,authenticated_later_round_three_voter_certificate_verified=failure is None,exactly_once_fee_debit_verified=failure is None,private_file_bytes_inventory_mode_size_mtime_unchanged_by_stopped_verification=cold_failure is None and len(verification)==4,real_process_interruption_qualification=False,full_fault_campaigns_started=0,independent_custody_full_fault_or_complete_protocol_qualified=False)
p=e/(probe_name+'-checks.json');assert not p.exists();p.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['source_sha256','node_source_sha256']}),flush=True);assert failure is None
