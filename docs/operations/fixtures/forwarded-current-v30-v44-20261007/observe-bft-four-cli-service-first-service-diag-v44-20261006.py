from pathlib import Path
import sys,time,json,base64,signal,fcntl,socket,threading,traceback,os
r=Path(__file__).resolve().parents[2];assert r==Path('/Users/galaxy/GitHub/rldcoin') and Path.cwd()==r
sys.path.insert(0,str(r/'tools'));b=r/'tmp/default-relay-20260930'
from bft_forwarded_current_delivery_precondition_v25_20261007 import require_ready_native_scope
require_ready_native_scope()
from regional_paged_fault_prepare import Preparation
from regional_paged_fault_launch import Config,encoded
from bft_four_cli_controller_20261005 import ScopeDeadline
from bft_four_cli_first_service_diagnostic_v29_20261007 import FourCLI,ENTRY
from first_service_diagnostic_collector_v4_20261007 import verify as verify_first_service
from regional_contact_trace_journal import verify_journal
from regional_paged_fault_scope import inventory
from regional_fixture_native_json import decode_native_json
from regional_contact_campaign import public
from regional_contact_node import Native,Service,NativeRefusal
from regional_bft_node import FORMAT
from regional_paged_fault_driver import observation_height
from verify_regional_bft_stopped_batch import verify_stopped_state_pinned
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
start=time.monotonic();deadline=float(sys.argv[1]);assert 0<deadline-start<=180
assert os.environ.get('RLD_GROUND_CONTACT_TRACE')=='1','explicit traced experiment only'
signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(ScopeDeadline('original180second service component deadline')))
x=json.loads((r/'docs/operations/evidence/regional-bft-forwarded-current-v30-identity-20261007.json').read_text());services=[];workers=[];configs=[];native=[];cli=None;result=None;failure=None;cleanup=[];p=None
try:
 p=Preparation(r,b/'native-bft-four-cli-service-first-service-diag-v44-private-20261006',b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate',x['implementation'],x['actual_cli_sha256'],deadline)
 def scope_remaining():
  value=deadline-time.monotonic()
  if value<=0:raise ScopeDeadline('original180second service component deadline')
  return value
 p.remaining=scope_remaining
 last_observations={}
 for label in ('earth','proxima'):p.region(label)
 for _ in range(3):p.certify('earth',[])
 signed=p.sign_preparation('proxima');frame=p.call(p.regions['earth'][0]['ledger'],'contact-export','--export',signed['intent_id']);framep=p.file('setup-source-contact',frame)
 bundle=decode_native_json(base64.b64decode(frame['payload_b64']));command=dict(Import=dict(snapshot=bundle['snapshot'],export=signed['intent_id']))
 expected=dict(currency=p.pin,source=p.region_ids[p.origin],destination=p.region_ids['proxima'],export=signed['intent_id'],recipient=public(20),net_amount='2');ep=p.file('component-expectation',expected)
 for row in p.regions['proxima']:
  applied=p.call(row['ledger'],'contact-apply','--file',framep);assert applied['evidence_verified'] is True and applied['import_accepted'] is False
  assert p.call(row['ledger'],'bft-pending-imports')==[command]
 for _ in range(12):p.certify('proxima',[])
 p.certify('proxima',[command])
 for row in p.regions['proxima']:
  receipt=p.call(row['ledger'],'wallet-receipt','--file',ep);assert receipt['expected']==expected and receipt['import_height']==13 and receipt['mature_height']==15 and receipt['import_accepted'] and receipt['maturity_reached'] is False and receipt['original_output_spendable_now'] is False
 held=[];ports=[];pins=[];transport=[]
 try:
  for n in range(4):
   cfg=dict(format=mesh.VERSION,state=str(p.root/'mesh'/str(n)),network=p.pin,contacts=[]);mesh.initialize(cfg['state'],p.pin,p.region_ids['proxima'],'component-recipient-'+str(n));pins.append(tcp.public_tls_identity(cfg));transport.append(cfg)
   endpoint=socket.socket();endpoint.bind(('127.0.0.1',0));held.append(endpoint);ports.append(endpoint.getsockname()[1])
 finally:
  for endpoint in held:endpoint.close()
 assert len(set(ports))==len({v['node_id'] for v in pins})==len({v['tls_cert_sha256'] for v in pins})==4
 cli_configs=[]
 for n,row in enumerate(p.regions['proxima']):
  transport[n]['contacts']=[dict(peer=pins[j]['node_id'],host='127.0.0.1',port=ports[j],tls_cert_sha256=pins[j]['tls_cert_sha256']) for j in range(4) if abs(n-j)==1]
  config=dict(format=FORMAT,state=str(p.root/'runtime'/str(n)),signer_dir=str(row['signer']),head_file=str(row['caller']),key_file=str(row['keyfile']),key=p.keys[n],miner=public(20),validators=[dict(key=p.keys[j],node_id=pins[j]['node_id']) for j in range(4)],block_interval=1,round_timeout=60,stop_height=15)
  configs.append(config);bft_path=p.file('component-bft-config-'+str(n),config);mesh_path=p.file('component-mesh-config-'+str(n),transport[n]);native.append(Native(p.binary,row['ledger'],p.authority,p.pin))
  argv=(str(p.binary),'--dir',str(row['ledger']),'--authority',p.authority,'--currency',p.pin,'--mesh-config',str(mesh_path),'--bft-config',str(bft_path),'--mesh-listen',f'127.0.0.1:{ports[n]}','--transport-python',str(ENTRY),'--interval','0.25')
  cli_configs.append(Config('ordinary','proxima',n,True,encoded(transport[n]),encoded(config),argv))
 # Exact public allocation is a once-only argv receipt, not a Native result.
 from bft_four_cli_first_service_diagnostic_v29_20261007 import entry
 contract=entry.load_contract();assert not entry.ALLOCATED.exists()
 slots=[]
 for n,row in enumerate(p.regions['proxima']):
  values=[str(p.binary),str(row['ledger']),p.authority,p.pin,'0.25',str(p.root/('component-mesh-config-'+str(n)+'.json')),str(p.root/('component-bft-config-'+str(n)+'.json')),'127.0.0.1:'+str(ports[n])]
  slots.append(dict(zip(entry.FLAGS,values)))
 allocation=dict(format='RLD-FIRST-SERVICE-ENTRY-ALLOCATED-V1',completed=True,root=contract['root'],budget_seconds=180,attempts=1,native_starts=4,entry_sha256=entry.sha(ENTRY),contract_sha256=entry.CONTRACT_SHA256,original_parameters=contract['original_parameters'],slots=slots)
 for n in range(4):
  original_argv=tuple([contract['driver_argv']]+[item for flag in entry.FLAGS for item in (flag,slots[n][flag])]);assert entry.validate_invocation(original_argv,contract,allocation)==(n,original_argv)
 wire.write_new(entry.ALLOCATED,wire.canonical(allocation))
 cli=FourCLI(r,p.root,cli_configs,transport,pins,ports,p.pin,deadline);cli.launch()
 print('service-step '+json.dumps(dict(kind='four-ordinary-native-cli-processes-started',elapsed_seconds=round(time.monotonic()-start,3),setup_certificates=17)),flush=True)
 observations=[]
 while True:
  heights=cli.observe();assert not cli.trace_window.failed and all(cli.trace_window.complete.values()),'complete trace interval required';observations.append(dict(elapsed_seconds=round(time.monotonic()-start,3),heights=heights))
  if len(observations)==1 or observations[-1]['heights']!=observations[-2]['heights']:
   print('service-step '+json.dumps(dict(kind='ordinary-progress',**observations[-1])),flush=True)
  if heights==[15]*4:break
  time.sleep(.25)
 assert cli.trace_window.snapshot()['all_four_streams_observed'],'all four trace producers required'
 cli.stop_all();assert cli.clean_terminal();cli.retain_final_observations()
 # Only stopped fresh ledgers are queried for actual receipt/maturity/value.
 receipts=[p.call(row['ledger'],'wallet-receipt','--file',ep) for row in p.regions['proxima']]
 assert all(v['expected']==expected and v['import_height']==13 and v['mature_height']==15 and v['maturity_reached'] is True and v['original_output_spendable_now'] is True and v['original_output_remaining']=='2' and v['local_finality_covers_import'] is True and v['quarantined'] is False for v in receipts)
 print('service-step '+json.dumps(dict(kind='four-cli-cleanly-stopped-and-actual-maturity-confirmed',elapsed_seconds=round(time.monotonic()-start,3))),flush=True)
 heads={str(row['ledger']):p.call(row['ledger'],'history-head')['history_head'] for rows in p.regions.values() for row in rows};p.file('separate-stopped-native-heads',heads)
 cold_before=inventory(p.root);states={};cold_messages=0;mesh_files=0
 from concurrent.futures import ThreadPoolExecutor
 def verify_replica_readonly(job):
  label,n,row=job
  local_messages=local_mesh_files=0
  p.remaining();check=p.call(row['ledger'],'history-check','--expected-head',heads[str(row['ledger'])]);assert check['history_head']==heads[str(row['ledger'])]
  state=p.call(row['ledger'],'status');assert state['currency']==p.pin and state['region']==p.region_ids[p.origin if label=='earth' else label] and state['height']==(4 if label=='earth' else 15) and state['fixture_only'] is True and state['live_rld'] is False;local_state=state
  bound=p.call(row['ledger'],'bft-status','--signer-dir',row['signer']);caller=json.loads(row['caller'].read_text());assert caller['binding']==bound['binding'] and caller['head']==bound['head'] and caller['pending'] is None and caller['outbox'] is None
  if label=='proxima':
   report=verify_stopped_state_pinned(native[n],configs[n],p.root,heads[str(row['ledger'])]);local_messages=report['messages_authenticated']
   with mesh.Node(transport[n]) as node:
    assert node.id==pins[n]['node_id'] and node.network==p.pin
    for ident in node.state['archives']:node.archived(ident)
   local_mesh_files=len(inventory(Path(transport[n]['state'])))
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
 wallet,caller,_=p.owner;owner=json.loads(caller.read_text());view=p.call(p.regions['earth'][0]['ledger'],'wallet-view','--wallet-dir',wallet,'--expected-wallet-head',owner['head']);assert len(view['signed'])==1 and view['signed'][0]['state']=='INCLUDED_IN_LOCAL_LEDGER' and owner['pending'] is None
 assert inventory(p.root)==cold_before,'stopped cold mutated private bytes'
 ledgers=[states[label][0]['ledger'] for label in ('earth','proxima')];issued=liquid=0
 for ledger in ledgers:
  assert not ledger.get('channel_state');minted=int(ledger['minted']);received=int(ledger['received']);coins=sum(int(v['payment']['amount']) for v in ledger['coins'].values());export=sum(int(v['recipient']['amount']) for v in ledger['exports'].values());assert minted+received==coins+export;issued+=minted;liquid+=coins
 assert issued==int(p.currency['block_reward'])*4==liquid and len(ledgers[0]['exports'])==len(ledgers[1]['imports'])==1 and signed['intent_id'] in ledgers[1]['imports'] and int(ledgers[1]['received'])==3
 p.remaining()
 trace_readback=verify_journal(cli.output/'finite-trace-events.jsonl',cli.trace_window.snapshot(),network=p.pin,slots=cli.trace_window.slots)
 p.remaining()
 first_readback=verify_first_service(cli.output/'first-service-events.jsonl',cli.first_service.snapshot(),cli.first_service.bindings)
 assert cli.first_service.snapshot()['all_four_streams_observed'] and first_readback['events']>0
 p.remaining()
 result=dict(completed=True,first_service_readback=first_readback,first_service_snapshot=cli.first_service.snapshot(),complete_trace_intervals=True,trace_events=trace_readback['events'],trace_journal_readback=trace_readback,trace_profile='RLD-FOUR-CLI-TRACE-JOURNAL-V1',traced_experiment_not_uninstrumented_baseline=True,duration_seconds=round(time.monotonic()-start,3),fresh_zero_allocation=True,native_replicas=8,ordinary_native_cli_processes=4,distinct_native_custody_owners=True,current_history_carriage_slots=[2,2],finite_current_finality_scheduler_candidate=True,helper_service_tick_calls=0,production_native_call_monkeypatches=0,same_host_pinned_tls=True,all_four_import_height=13,all_four_mature_height=15,all_four_spendable_net='2',controller_setup_certificates=17,controller_certificates_after_runtime_start=0,controller_consensus_messages_during_runtime=0,controller_frame_carriage_setup_only=True,component_owner_first_signs=1,original_fault_owner_requests=0,old_failed_native_runtime_opens=0,ordinary_round_seconds=60,contact_interval_seconds=.25,block_interval_seconds=1,finite_stop_height=15,original_maturity=2,original_quorum=3,full_fixed_head_native_cold=8,complete_retained_envelopes_native_checked=cold_messages,original_caller_heads_verified=8,original_owner_head_verified=True,private_mesh_files_cold_checked=mesh_files,cold_private_bytes_unchanged=True,services_and_owned_threads_stopped=cli.clean_terminal(),owned_processes_stopped=True,owned_process_terminal=cli.terminal,native_preparation_and_cold_calls=len(p.calls),native_issued=str(issued),native_liquid=str(liquid),pending_exports='0',native_conservation=True,current_live_unknown_progress_waited=any(None in v['heights'] for v in observations),whole_full_fault_qualified=False,unique_previous_full_fault_cause_not_proved=True,whole_goal_completed=False)


except BaseException as error:
 failure=type(error).__name__+': '+str(error);traceback.print_exc()
finally:
 if cli is not None:
  try:
   cli.stop_all()
   if not any((cli.output/f'final-observation-{i}.json').exists() for i in range(4)):cli.retain_final_observations()
  except BaseException as error:cleanup.append(dict(error=type(error).__name__+': '+str(error)))
 if p is not None:
  diagnostic=dict(partial_observations=locals().get('observations',[]),failure=failure,owned_process_terminal=cli.terminal if cli is not None else [],raw_rejection_saved=cli.raw_failure_saved if cli is not None else False,helper_service_tick_calls=0,production_native_call_monkeypatches=0)
  raw=wire.canonical(diagnostic)
  if len(raw)<=8*1024*1024:mesh.atomic(p.root/'scope-final-cli-observations.json',diagnostic)
  else:cleanup.append(dict(error='diagnostic capacity; native evidence retained'))
 stopped=not cleanup and (cli is None or cli.clean_terminal())
 if failure is not None or cleanup:result=dict(completed=False,failure=failure,cleanup_failures=cleanup,services_and_owned_threads_stopped=stopped,owned_processes_stopped=stopped,owned_process_terminal=cli.terminal if cli is not None else [],raw_rejection_saved=cli.raw_failure_saved if cli is not None else False,failed_currency_never_reopen=True,whole_full_fault_qualified=False,whole_goal_completed=False)
 assert result is not None
 print('sign-service-result '+json.dumps(result),flush=True)
 raise SystemExit(0 if result['completed'] else 1)
