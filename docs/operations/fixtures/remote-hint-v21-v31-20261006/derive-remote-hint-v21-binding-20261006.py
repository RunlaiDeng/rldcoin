from pathlib import Path
import re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'bind-bft-archive-stream-v20-native-v30-v2-20261006.py';new=b/'bind-bft-remote-hint-v21-native-v31-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-hint-pressure-delivery-qualified-v19':'regional-bft-archive-stream-delivery-qualified-v20',
 'regional-bft-hint-pressure-delivery-v19':'regional-bft-archive-stream-delivery-v20',
 'regional-bft-archive-stream-delivery-qualified-v20':'regional-bft-remote-hint-delivery-qualified-v21',
 'regional-bft-archive-stream-delivery-v20':'regional-bft-remote-hint-delivery-v21',
 'observe-bft-current-commit-hint-pressure-delivery-v19':'observe-bft-current-commit-archive-stream-delivery-v20',
 'observe-bft-current-commit-archive-stream-delivery-v20':'observe-bft-current-commit-remote-hint-delivery-v21',
 'regional-bft-current-commit-archive-stream-delivery-v20':'regional-bft-current-commit-remote-hint-delivery-v21',
 'bft-current-commit-archive-stream-delivery-v20':'bft-current-commit-remote-hint-delivery-v21',
 'regional-bft-hint-pressure-v19-identity':'regional-bft-archive-stream-v20-identity',
 'regional-bft-archive-stream-v20-identity':'regional-bft-remote-hint-v21-identity',
 'first_service_diagnostic_entry_contract_v17':'first_service_diagnostic_entry_contract_v18',
 'first_service_diagnostic_entry_contract_v18':'first_service_diagnostic_entry_contract_v19',
 'first_service_diagnostic_entry_v17':'first_service_diagnostic_entry_v18',
 'first_service_diagnostic_entry_v18':'first_service_diagnostic_entry_v19',
 'bft_four_cli_first_service_diagnostic_v14':'bft_four_cli_first_service_diagnostic_v15',
 'bft_four_cli_first_service_diagnostic_v15':'bft_four_cli_first_service_diagnostic_v16',
 'bft_hint_pressure_delivery_precondition_v10':'bft_archive_stream_delivery_precondition_v11',
 'bft_archive_stream_delivery_precondition_v11':'bft_remote_hint_delivery_precondition_v12',
 'regional-bft-hint-pressure-entry-start-allocated-v29':'regional-bft-archive-stream-entry-start-allocated-v30',
 'regional-bft-archive-stream-entry-start-allocated-v30':'regional-bft-remote-hint-entry-start-allocated-v31',
 'regional-bft-four-cli-hint-pressure-v29-decision':'regional-bft-four-cli-archive-stream-v30-decision',
 'regional-bft-four-cli-archive-stream-v30-decision':'regional-bft-four-cli-remote-hint-v31-decision',
 'bind_bft_four_cli_hint_pressure_v29':'bind_bft_four_cli_archive_stream_v30',
 'bind_bft_four_cli_archive_stream_v30':'bind_bft_four_cli_remote_hint_v31',
 'service-first-service-diag-v29':'service-first-service-diag-v30',
 'service-first-service-diag-v30':'service-first-service-diag-v31',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V19':'RLD-CONTACT-TRANSIT-SCHEDULER-V20',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V20':'RLD-CONTACT-TRANSIT-SCHEDULER-V21',
 'regional-bft-archive-stream-v20-v30-source-binding':'regional-bft-remote-hint-v21-v31-source-binding',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda z:m[z[0]],s)
a=s.index('old=json.loads(');z=s.index('static_stage=e/',a)
head='''old=json.loads((e/'regional-bft-archive-stream-v20-identity-20261006.json').read_text());qpath=e/'regional-bft-current-commit-remote-hint-delivery-v21-20261006-checks.json';q=json.loads(qpath.read_text());related_path=e/'regional-bft-current-commit-remote-hint-related-v21-20261006-checks.json';related=json.loads(related_path.read_text());base=json.loads((e/'regional-bft-current-commit-remote-hint-baseline-v20-20261006-checks.json').read_text());assert q['completed'] and related['completed'] and not base['completed'] and base['helper_exit_code']==1
current={p:sha(r/p) for p in old['python_source_sha256']};delta=sorted(p for p,h in current.items() if h!=old['python_source_sha256'][p]);assert delta==['tools/interstellar_mesh.py','tools/regional_bft_node.py','tools/test_interstellar_mesh.py'] and len(current)==192
assert all(sha(r/p)==h for p,h in old['native_source_sha256'].items());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());assert all(sha(r/z['path'])==z['sha256'] for z in core['files']);assert sha(b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate')==old['actual_cli_sha256']
x=copy.deepcopy(old);x.update(profile='RLD-CONTACT-TRANSIT-SCHEDULER-V21',transit_scheduler_profile='RLD-CONTACT-TRANSIT-SCHEDULER-V21',python_source_sha256=current,python_source_commitment=hashlib.sha256(canonical(current)).hexdigest(),source_delta=delta,prior_identity_sha256=sha(e/'regional-bft-archive-stream-v20-identity-20261006.json'));identity=e/'regional-bft-remote-hint-v21-identity-20261006.json'
for name in ['native-bft-four-cli-service-first-service-diag-v30','bft-current-commit-remote-hint-baseline-v20','bft-current-commit-remote-hint-related-v21','bft-current-commit-remote-hint-delivery-v21']:
 p=b/(name+'-stopped-private-inventory-20261006.json');assert p.is_file();x['protected_private_inventory_sha256'][str(p)]=sha(p)
save(identity,x)
def original(p):return subprocess.run(['git','show','e57ec73aa:'+p],cwd=r,capture_output=True,text=True,check=True).stdout
functions=lambda text:{z.name:ast.dump(z,include_attributes=False) for z in ast.walk(ast.parse(text)) if isinstance(z,(ast.FunctionDef,ast.AsyncFunctionDef))}
for path,changed,added in [('tools/interstellar_mesh.py',set(),set()),('tools/regional_bft_node.py',{'broadcast'},set()),('tools/test_interstellar_mesh.py',set(),{'test_new_remote_current_frame_invalidates_complete_broadcast_quiet_inventory','envelope'})]:
 oldfs=functions(original(path));newfs=functions((r/path).read_text());assert set(newfs)-set(oldfs)==added and all(newfs[n]==v for n,v in oldfs.items() if n not in changed)
ast_equal(original('tools/interstellar_mesh.py').replace('RLD-CONTACT-TRANSIT-SCHEDULER-V20','RLD-CONTACT-TRANSIT-SCHEDULER-V21'),(r/'tools/interstellar_mesh.py').read_text());ast_equal(original('tools/interstellar_frame_digest.py'),(r/'tools/interstellar_frame_digest.py').read_text())
expected=original('tools/regional_bft_node.py').replace('and len(rows)<=MAX_MESSAGES and len(recipients)<=mesh.MAX_CONTACTS):',"and len(rows)<=MAX_MESSAGES and len(self.state['messages'])<=MAX_MESSAGES\\n                and len(recipients)<=mesh.MAX_CONTACTS):")
expected=expected.replace("'local_complete_envelope_ids':rows,'recipients':recipients})", """'local_complete_envelope_ids':rows,
                'retained_complete_envelope_ids':[(self.state['messages'].content(i),i)
                                                 for i in sorted(self.state['messages'])],
                'recipients':recipients})""")
ast_equal(expected,(r/'tools/regional_bft_node.py').read_text())
sys.path.insert(0,str(r/'tools'));import test_interstellar_mesh as tests;import interstellar_mesh as mesh
fn=tests.MeshTests.test_current_frame_hint_pressure_ordinary_delivery;providers=set()
def used(code):
 for op in dis.get_instructions(code):
  if op.opname=='LOAD_GLOBAL':providers.add(op.argval);assert op.argval in fn.__globals__ or hasattr(__builtins__,op.argval)
 for c in code.co_consts:
  if isinstance(c,types.CodeType):used(c)
used(fn.__code__)
helper_ground=b/'observe-bft-current-commit-remote-hint-delivery-v21-20261006.py';stage_ground=e/'regional-bft-current-commit-remote-hint-delivery-v21-20261006-stage.json';sg=json.loads(stage_ground.read_text());assert q['helper_sha256']==sha(helper_ground) and q['stage_sha256']==sha(stage_ground)
for p,h in sg['source_sha256'].items():assert sha(Path(p))==h
related_stage=e/'regional-bft-current-commit-remote-hint-related-v21-20261006-stage.json';rs=json.loads(related_stage.read_text());assert related['stage_sha256']==sha(related_stage)
for p,h in rs['source_sha256'].items():assert sha(Path(p))==h
classifier=json.loads((e/'regional-bft-archive-stream-v20-v30-source-binding-20261006-checks.json').read_text());assert classifier['completed'] and classifier['prior_unchanged_Runtime_classification_reused'];assert functions((r/'tools/regional_bft_node.py').read_text())['commit_carriage_frames']==functions(original('tools/regional_bft_node.py'))['commit_carriage_frames']
'''
s=s[:a]+head+s[z:]
s=s.replace("composition='Four involved modules pinned during actual current ordinary delivery; three changed modules and189 unchanged modules compose192. Cold Mesh method tests source-bound with typed hostile seal; default segmentation algorithm exact and six original frame-digest tests current-source passed. Neither data reuse nor serialization grants Native authority.'", "composition='Four modules pinned during current ordinary delivery; three changes are only mesh profile/new complete-ID quiet inventory/new model counter;189 unchanged sources compose192. Original archive/frame encoders and classifiers unchanged, current-related full Native authority methods AST preserved. Transport and model do not grant Native maturity.'")
s=s.replace("e/'regional-bft-archive-stream-related-v20-qualified-20261006-checks.json',e/'regional-bft-current-commit-archive-stream-baseline-v19-20261006-checks.json'", "related_path,e/'regional-bft-current-commit-remote-hint-baseline-v20-20261006-checks.json'")
s=s.replace('archive_path_128_ASCII_and_unsupported_cases_checked=True,current_default_frame_digest_regressions=6,typed_hostile_artifacts_never_followed=True,','prior_unchanged_archive_128_cases_and6digest_tests_reused=True,remote_current_hint_inventory_counter_and_related3_passed=True,original_quiet_time_call_capacity_and_unmodified_inventory_hit_preserved=True,')
compile(s,str(new),'exec');new.write_text(s)
