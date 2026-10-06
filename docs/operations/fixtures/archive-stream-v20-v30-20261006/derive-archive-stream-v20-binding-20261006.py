from pathlib import Path
import re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'bind-bft-hint-pressure-v19-native-v29-20261006.py';new=b/'bind-bft-archive-stream-v20-native-v30-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-import-parent-delivery-qualified-v18':'regional-bft-hint-pressure-delivery-qualified-v19',
 'regional-bft-import-parent-delivery-v18':'regional-bft-hint-pressure-delivery-v19',
 'regional-bft-hint-pressure-delivery-qualified-v19':'regional-bft-archive-stream-delivery-qualified-v20',
 'regional-bft-hint-pressure-delivery-v19':'regional-bft-archive-stream-delivery-v20',
 'observe-bft-current-commit-import-parent-delivery-v18':'observe-bft-current-commit-hint-pressure-delivery-v19',
 'observe-bft-current-commit-hint-pressure-delivery-v19':'observe-bft-current-commit-archive-stream-delivery-v20',
 'regional-bft-current-commit-hint-pressure-delivery-v19':'regional-bft-current-commit-archive-stream-delivery-v20',
 'bft-current-commit-hint-pressure-delivery-v19':'bft-current-commit-archive-stream-delivery-v20',
 'regional-bft-import-parent-v18-identity':'regional-bft-hint-pressure-v19-identity',
 'regional-bft-hint-pressure-v19-identity':'regional-bft-archive-stream-v20-identity',
 'first_service_diagnostic_entry_contract_v16':'first_service_diagnostic_entry_contract_v17',
 'first_service_diagnostic_entry_contract_v17':'first_service_diagnostic_entry_contract_v18',
 'first_service_diagnostic_entry_v16':'first_service_diagnostic_entry_v17',
 'first_service_diagnostic_entry_v17':'first_service_diagnostic_entry_v18',
 'bft_four_cli_first_service_diagnostic_v13':'bft_four_cli_first_service_diagnostic_v14',
 'bft_four_cli_first_service_diagnostic_v14':'bft_four_cli_first_service_diagnostic_v15',
 'bft_import_parent_delivery_precondition_v9':'bft_hint_pressure_delivery_precondition_v10',
 'bft_hint_pressure_delivery_precondition_v10':'bft_archive_stream_delivery_precondition_v11',
 'regional-bft-import-parent-entry-start-allocated-v28':'regional-bft-hint-pressure-entry-start-allocated-v29',
 'regional-bft-hint-pressure-entry-start-allocated-v29':'regional-bft-archive-stream-entry-start-allocated-v30',
 'regional-bft-four-cli-import-parent-v28-decision':'regional-bft-four-cli-hint-pressure-v29-decision',
 'regional-bft-four-cli-hint-pressure-v29-decision':'regional-bft-four-cli-archive-stream-v30-decision',
 'bind_bft_four_cli_import_parent_v28':'bind_bft_four_cli_hint_pressure_v29',
 'bind_bft_four_cli_hint_pressure_v29':'bind_bft_four_cli_archive_stream_v30',
 'service-first-service-diag-v28':'service-first-service-diag-v29',
 'service-first-service-diag-v29':'service-first-service-diag-v30',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V18':'RLD-CONTACT-TRANSIT-SCHEDULER-V19',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V19':'RLD-CONTACT-TRANSIT-SCHEDULER-V20',
 'regional-bft-hint-pressure-v19-v29-source-binding':'regional-bft-archive-stream-v20-v30-source-binding',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda z:m[z[0]],s)
a=s.index('old=json.loads(');z=s.index('static_stage=e/',a)
head='''old=json.loads((e/'regional-bft-hint-pressure-v19-identity-20261006.json').read_text());qpath=e/'regional-bft-current-commit-archive-stream-delivery-v20-20261006-checks.json';q=json.loads(qpath.read_text());related=json.loads((e/'regional-bft-archive-stream-related-v20-qualified-20261006-checks.json').read_text());base=json.loads((e/'regional-bft-current-commit-archive-stream-baseline-v19-20261006-checks.json').read_text());default=json.loads((e/'regional-bft-archive-stream-frame-digest-v20-20261006-checks.json').read_text());assert q['completed'] and related['completed'] and default['completed'] and default['tests_run']==6 and not base['completed']
current={p:sha(r/p) for p in old['python_source_sha256']};delta=sorted(p for p,h in current.items() if h!=old['python_source_sha256'][p]);assert delta==['tools/interstellar_frame_digest.py','tools/interstellar_mesh.py','tools/test_interstellar_mesh.py'] and len(current)==192
assert all(sha(r/p)==h for p,h in old['native_source_sha256'].items());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());assert all(sha(r/z['path'])==z['sha256'] for z in core['files']);assert sha(b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate')==old['actual_cli_sha256']
x=copy.deepcopy(old);x.update(profile='RLD-CONTACT-TRANSIT-SCHEDULER-V20',transit_scheduler_profile='RLD-CONTACT-TRANSIT-SCHEDULER-V20',python_source_sha256=current,python_source_commitment=hashlib.sha256(canonical(current)).hexdigest(),source_delta=delta,prior_identity_sha256=sha(e/'regional-bft-hint-pressure-v19-identity-20261006.json'));identity=e/'regional-bft-archive-stream-v20-identity-20261006.json'
for name in ['native-bft-four-cli-service-first-service-diag-v29','bft-current-commit-archive-stream-baseline-v19','bft-current-commit-archive-stream-related-v20','bft-current-commit-archive-stream-related-v20-v2','bft-current-commit-archive-stream-delivery-v20']:
 p=b/(name+'-stopped-private-inventory-20261006.json');assert p.is_file();x['protected_private_inventory_sha256'][str(p)]=sha(p)
typed=Path(related['typed_inventory']);x['protected_typed_inventory_sha256'][str(typed)]=sha(typed);sys.path.insert(0,str(b));from bind_bft_four_cli_active_b64_scan_20261006 import typed_image
assert typed_image(typed)==json.loads(typed.read_text())['rows'];save(identity,x)
# Replay only exact reviewed source edits against the local predecessor commit.
def original(p):return subprocess.run(['git','show','ef8810e19:'+p],cwd=r,capture_output=True,text=True,check=True).stdout
functions=lambda text:{z.name:ast.dump(z,include_attributes=False) for z in ast.walk(ast.parse(text)) if isinstance(z,(ast.FunctionDef,ast.AsyncFunctionDef))}
for path,changed,added in [('tools/interstellar_mesh.py',{'archived'},set()),('tools/regional_bft_node.py',set(),set()),('tools/test_interstellar_mesh.py',set(),{'test_archive_cold_streamed_bytes_are_exact_and_authentication_stays_required'})]:
 oldfs=functions(original(path));newfs=functions((r/path).read_text());assert set(newfs)-set(oldfs)==added and all(newfs[n]==v for n,v in oldfs.items() if n not in changed)
# Generic segmentation algorithm is byte-identical to the predecessor default
# transit algorithm. Only the explicit extra archive path is new.
oldtree=ast.parse(original('tools/interstellar_frame_digest.py'));newtree=ast.parse((r/'tools/interstellar_frame_digest.py').read_text());of={v.name:v for v in oldtree.body if isinstance(v,ast.FunctionDef)};nf={v.name:v for v in newtree.body if isinstance(v,ast.FunctionDef)};candidate=copy.deepcopy(nf['_commitment']);candidate.name='commitment';candidate.args=copy.deepcopy(of['commitment'].args);candidate.body.insert(0,copy.deepcopy(of['commitment'].body[0]))
for v in ast.walk(candidate):
 if isinstance(v,ast.Name) and v.id=='path':v.id='PATH'
assert ast.dump(candidate,include_attributes=False)==ast.dump(of['commitment'],include_attributes=False)
for n,v in of.items():
 if n!='commitment':assert ast.dump(v,include_attributes=False)==ast.dump(nf[n],include_attributes=False)
assert set(nf)-set(of)=={'_commitment','archive_commitment'}
# Whole mesh differs only in archive exact-byte encoders and profile.
expected=original('tools/interstellar_mesh.py').replace('RLD-CONTACT-TRANSIT-SCHEDULER-V19','RLD-CONTACT-TRANSIT-SCHEDULER-V20').replace('payload==evidence.canonical(frame)','payload==frame_digest.packet_body_bytes(frame)')
oldline="expanded_size=len(evidence.canonical(preview))+len(evidence.canonical(frame['frame']))+8+bool(transit['packet']['body'])"
expected=expected.replace(oldline,"""# The complete frame object was compared to its exact canonical
            # bytes above. Reuse that byte length, including all JSON escapes,
            # by subtracting the same object's empty-string image. No frame
            # encoding or authentication result survives this operation.
            frame_size=len(payload)-len(evidence.canonical(dict(frame,frame='')))+2
            expanded_size=len(evidence.canonical(preview))+frame_size+8+bool(transit['packet']['body'])""")
expected=expected.replace("expanded=evidence.canonical(blob)\\n        require(len(expanded)==body['expanded_size_bytes'] and len(expanded)<=MAX_STATE\\n                and hashlib.sha256(expanded).hexdigest()==body['expanded_sha256'],", "expanded_hash,expanded_size=frame_digest.archive_commitment(blob)\\n        require(expanded_size==body['expanded_size_bytes'] and expanded_size<=MAX_STATE\\n                and expanded_hash==body['expanded_sha256'],")
ast_equal(expected,(r/'tools/interstellar_mesh.py').read_text());ast_equal(original('tools/regional_bft_node.py'),(r/'tools/regional_bft_node.py').read_text())
sys.path.insert(0,str(r/'tools'));import test_interstellar_mesh as tests;import interstellar_mesh as mesh
fn=tests.MeshTests.test_current_frame_hint_pressure_ordinary_delivery;providers=set()
def used(code):
 for op in dis.get_instructions(code):
  if op.opname=='LOAD_GLOBAL':providers.add(op.argval);assert op.argval in fn.__globals__ or hasattr(__builtins__,op.argval)
 for c in code.co_consts:
  if isinstance(c,types.CodeType):used(c)
used(fn.__code__)
helper_ground=b/'observe-bft-current-commit-archive-stream-delivery-v20-20261006.py';stage_ground=e/'regional-bft-current-commit-archive-stream-delivery-v20-20261006-stage.json';sg=json.loads(stage_ground.read_text());assert q['helper_sha256']==sha(helper_ground) and q['stage_sha256']==sha(stage_ground)
for p,h in sg['source_sha256'].items():assert sha(Path(p))==h
for p,h in related['source_sha256'].items():assert sha(Path(p))==h
olddefault=json.loads((e/'regional-bft-archive-stream-frame-digest-v20-20261006-stage.json').read_text());assert default['stage_sha256']==sha(e/'regional-bft-archive-stream-frame-digest-v20-20261006-stage.json')
for p,h in olddefault['source_sha256'].items():assert sha(Path(p))==h
classifier=json.loads((e/'regional-bft-hint-pressure-v19-v29-source-binding-20261006-checks.json').read_text());assert classifier['completed'] and classifier['prior_unchanged_Runtime_classification_reused'] and current['tools/regional_bft_node.py']==old['python_source_sha256']['tools/regional_bft_node.py']
'''
s=s[:a]+head+s[z:]
s=s.replace("composition='3 involved sources pinned during executed ground test; 190 unchanged sources bound to V18 and independently verified now. No source change during test.'", "composition='Four involved modules pinned during actual current ordinary delivery; three changed modules and189 unchanged modules compose192. Cold Mesh method tests source-bound with typed hostile seal; default segmentation algorithm exact and six original frame-digest tests current-source passed. Neither data reuse nor serialization grants Native authority.'")
# Reused old receipt is transport prerequisite only; additionally bind exact archive qualification.
s=s.replace("receipt=e/'regional-bft-archive-stream-delivery-qualified-v20", "receipt=e/'regional-bft-archive-stream-delivery-qualified-v20")
s=s.replace("for name in ['", "for name in ['",1)
s=s.replace("e/'regional-bft-current-commit-hint-pressure-related-v19-20261006-checks.json',e/'regional-bft-current-commit-hint-pressure-baseline-v18-20261006-checks.json'", "e/'regional-bft-archive-stream-related-v20-qualified-20261006-checks.json',e/'regional-bft-current-commit-archive-stream-baseline-v19-20261006-checks.json'")
s=s.replace("primitive_Runtime_frame_classification_calls=0,", "exact_default_segmentation_algorithm_AST_preserved=True,archive_path_128_ASCII_and_unsupported_cases_checked=True,current_default_frame_digest_regressions=6,typed_hostile_artifacts_never_followed=True,primitive_Runtime_frame_classification_calls=0,")
compile(s,str(new),'exec');new.write_text(s)
