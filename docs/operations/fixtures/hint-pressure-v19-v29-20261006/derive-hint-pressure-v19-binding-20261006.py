from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'bind-bft-import-parent-v18-native-v28-20261006.py';new=b/'bind-bft-hint-pressure-v19-native-v29-20261006.py';assert not new.exists();s=old.read_text();m={
 '3dcf9bbce:':'82f57dc71:',
 'regional-bft-empty-proposal-v17-identity':'regional-bft-import-parent-v18-identity',
 'regional-bft-import-parent-v18-identity':'regional-bft-hint-pressure-v19-identity',
 'regional-bft-current-commit-import-parent-delivery-v18':'regional-bft-current-commit-hint-pressure-delivery-v19',
 'bft-current-commit-import-parent-delivery-v18':'bft-current-commit-hint-pressure-delivery-v19',
 'regional-bft-current-commit-import-parent-related-v18':'regional-bft-current-commit-hint-pressure-related-v19',
 'regional-bft-current-commit-import-parent-baseline-v17':'regional-bft-current-commit-hint-pressure-baseline-v18',
 'regional-bft-import-parent-delivery-v18':'regional-bft-hint-pressure-delivery-v19',
 'regional-bft-import-parent-delivery-qualified-v18':'regional-bft-hint-pressure-delivery-qualified-v19',
 'regional-bft-empty-proposal-delivery-qualified-v17':'regional-bft-import-parent-delivery-qualified-v18',
 'regional-bft-empty-proposal-delivery-v17':'regional-bft-import-parent-delivery-v18',
 'observe-bft-current-commit-proposal-delivery-v17':'observe-bft-current-commit-import-parent-delivery-v18',
 'observe-bft-current-commit-import-parent-delivery-v18':'observe-bft-current-commit-hint-pressure-delivery-v19',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V17':'RLD-CONTACT-TRANSIT-SCHEDULER-V18',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V18':'RLD-CONTACT-TRANSIT-SCHEDULER-V19',
 'first_service_diagnostic_entry_contract_v15':'first_service_diagnostic_entry_contract_v16',
 'first_service_diagnostic_entry_contract_v16':'first_service_diagnostic_entry_contract_v17',
 'first_service_diagnostic_entry_v15':'first_service_diagnostic_entry_v16',
 'first_service_diagnostic_entry_v16':'first_service_diagnostic_entry_v17',
 'bft_four_cli_first_service_diagnostic_v12':'bft_four_cli_first_service_diagnostic_v13',
 'bft_four_cli_first_service_diagnostic_v13':'bft_four_cli_first_service_diagnostic_v14',
 'bft_empty_proposal_delivery_precondition_v8':'bft_import_parent_delivery_precondition_v9',
 'bft_import_parent_delivery_precondition_v9':'bft_hint_pressure_delivery_precondition_v10',
 'regional-bft-empty-proposal-entry-start-allocated-v27':'regional-bft-import-parent-entry-start-allocated-v28',
 'regional-bft-import-parent-entry-start-allocated-v28':'regional-bft-hint-pressure-entry-start-allocated-v29',
 'regional-bft-four-cli-empty-proposal-v27-decision':'regional-bft-four-cli-import-parent-v28-decision',
 'regional-bft-four-cli-import-parent-v28-decision':'regional-bft-four-cli-hint-pressure-v29-decision',
 'bind_bft_four_cli_empty_proposal_v27':'bind_bft_four_cli_import_parent_v28',
 'bind_bft_four_cli_import_parent_v28':'bind_bft_four_cli_hint_pressure_v29',
 'service-first-service-diag-v27':'service-first-service-diag-v28',
 'service-first-service-diag-v28':'service-first-service-diag-v29',
 'regional-bft-import-parent-v18-v28-source-binding':'regional-bft-hint-pressure-v19-v29-source-binding',
 'test_prepared_import_parent_proposal_keeps_spare_after_native_current_hint':'test_current_frame_hint_survives_group_position_pressure_in_same_plan',
 'test_prepared_import_parent_proposal_priority_reaches_destination_after_full_retry':'test_current_frame_hint_pressure_ordinary_delivery',
 'bft-current-commit-import-parent-baseline-v17':'bft-current-commit-hint-pressure-baseline-v18',
 'bft-current-commit-import-parent-related-v18':'bft-current-commit-hint-pressure-related-v19',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s)
s=s.replace("delta==['tools/interstellar_mesh.py','tools/regional_bft_node.py','tools/test_interstellar_mesh.py']","delta==['tools/interstellar_mesh.py','tools/test_interstellar_mesh.py']").replace("('tools/interstellar_mesh.py',set(),set())","('tools/interstellar_mesh.py',{'_exchange_plan'},set())").replace("('tools/regional_bft_node.py',{'current_empty_proposal_hint'},set())","('tools/regional_bft_node.py',set(),set())").replace(",'signed_ground_import_parent_proposal'",'')
a=s.index("mesh_now=(r/");z=s.index('# Added Native hint',a)
s=s[:a]+'''mesh_now=(r/'tools/interstellar_mesh.py').read_text();mesh_before=original('tools/interstellar_mesh.py')
anchor='        pending=self.transit_groups(peer) if len(transits)<MAX_PACKET_BATCH else []\\n'
expected=mesh_before.replace(anchor,"""        priority_pair=(first_plan is not None and (self.state['transit_class_steps'][peer]//2)%2==0)
        # Read the primitive hint before group initialization may evict it.
        # A full retry or an already missing hint retains ordinary fallback.
        hint=(carriage_position((self.carriage_position_domain(),'native-commit-spare'))
              if priority_pair else None)
"""+anchor).replace("        if first_plan is not None and (self.state['transit_class_steps'][peer]//2)%2==0:\\n",'        if priority_pair:\\n',1).replace("            hint=carriage_position((self.carriage_position_domain(),'native-commit-spare'))\\n",'',1).replace('RLD-CONTACT-TRANSIT-SCHEDULER-V18','RLD-CONTACT-TRANSIT-SCHEDULER-V19')
ast_equal(mesh_now,expected);ast_equal((r/'tools/regional_bft_node.py').read_text(),original('tools/regional_bft_node.py'))
''' +s[z:]
a=s.index('failed=b/');z=s.index('static_stage=e/',a)
s=s[:a]+'''classifier=json.loads((e/'regional-bft-import-parent-v18-v28-source-binding-20261006-checks.json').read_text());assert classifier['completed'] and classifier['actual_retained_V27_signed_Import_parent_Proposal_exact_frame_classified_without_Native_constructor'] and classifier['actual_full_Proposal_Rust_domain_signature_verified'];assert current['tools/regional_bft_node.py']==old['python_source_sha256']['tools/regional_bft_node.py']
''' +s[z:]
s=s.replace('189 unchanged sources bound to V17','190 unchanged sources bound to V18').replace('primitive_Runtime_frame_classification_calls=1,prior_unchanged_Runtime_classification_reused=False','primitive_Runtime_frame_classification_calls=0,prior_unchanged_Runtime_classification_reused=True')
# Related source changed only by adding the final delivery method afterwards.
a=s.index('static_stage=e/')
s=s[:a]+'''related_stage=json.loads((e/'regional-bft-current-commit-hint-pressure-related-v19-20261006-stage.json').read_text());current_tests=(r/'tools/test_interstellar_mesh.py').read_text();delivery_fn=next(z for z in ast.walk(ast.parse(current_tests)) if isinstance(z,ast.FunctionDef) and z.name=='test_current_frame_hint_pressure_ordinary_delivery');lines=current_tests.splitlines(True);begin=sum(map(len,lines[:delivery_fn.lineno-1]));end=sum(map(len,lines[:delivery_fn.end_lineno]));prior_tests=current_tests[:begin-2]+current_tests[end:];assert hashlib.sha256(prior_tests.encode()).hexdigest()==related_stage['source_sha256'][str(r/'tools/test_interstellar_mesh.py')]
''' +s[a:];compile(s,str(new),'exec');new.write_text(s)
