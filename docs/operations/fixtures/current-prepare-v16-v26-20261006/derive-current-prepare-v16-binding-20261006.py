from pathlib import Path
import re,ast
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'bind-bft-prepared-commit-v15-native-v25-20261006.py';new=b/'bind-bft-current-prepare-v16-native-v26-20261006.py';assert not new.exists();s=old.read_text()
m={
 '61c8bb16a:':'2d9f028b9:',
 'regional-bft-current-commit-v14-identity':'regional-bft-prepared-commit-v15-identity',
 'regional-bft-prepared-commit-v15-identity':'regional-bft-current-prepare-v16-identity',
 'regional-bft-current-commit-delivery-final-v15':'regional-bft-current-commit-prepare-delivery-v16',
 'bft-current-commit-delivery-final-v15':'bft-current-commit-prepare-delivery-v16',
 'regional-bft-current-commit-prepared-related-v15':'regional-bft-current-commit-prepare-related-v16',
 'regional-bft-current-commit-prepared-baseline-v14':'regional-bft-current-commit-prepare-baseline-v15',
 'regional-bft-prepared-commit-delivery-v15':'regional-bft-current-prepare-delivery-v16',
 'regional-bft-prepared-commit-delivery-qualified-v15':'regional-bft-current-prepare-delivery-qualified-v16',
 'regional-bft-current-commit-delivery-qualified-v14':'regional-bft-prepared-commit-delivery-qualified-v15',
 'regional-bft-current-commit-delivery-v14':'regional-bft-prepared-commit-delivery-v15',
 'observe-bft-current-commit-delivery-final-v14':'observe-bft-current-commit-delivery-final-v15',
 'observe-bft-current-commit-delivery-final-v15':'observe-bft-current-commit-prepare-delivery-v16',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V14':'RLD-CONTACT-TRANSIT-SCHEDULER-V15',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V15':'RLD-CONTACT-TRANSIT-SCHEDULER-V16',
 'first_service_diagnostic_entry_contract_v12':'first_service_diagnostic_entry_contract_v13',
 'first_service_diagnostic_entry_contract_v13':'first_service_diagnostic_entry_contract_v14',
 'first_service_diagnostic_entry_v12':'first_service_diagnostic_entry_v13',
 'first_service_diagnostic_entry_v13':'first_service_diagnostic_entry_v14',
 'bft_four_cli_first_service_diagnostic_v9':'bft_four_cli_first_service_diagnostic_v10',
 'bft_four_cli_first_service_diagnostic_v10':'bft_four_cli_first_service_diagnostic_v11',
 'bft_current_commit_delivery_precondition_v5':'bft_prepared_commit_delivery_precondition_v6',
 'bft_prepared_commit_delivery_precondition_v6':'bft_current_prepare_delivery_precondition_v7',
 'regional-bft-current-commit-entry-start-allocated-v24':'regional-bft-prepared-commit-entry-start-allocated-v25',
 'regional-bft-prepared-commit-entry-start-allocated-v25':'regional-bft-current-prepare-entry-start-allocated-v26',
 'regional-bft-four-cli-current-commit-v24-decision':'regional-bft-four-cli-prepared-commit-v25-decision',
 'regional-bft-four-cli-prepared-commit-v25-decision':'regional-bft-four-cli-current-prepare-v26-decision',
 'bind_bft_four_cli_current_commit_v24':'bind_bft_four_cli_prepared_commit_v25',
 'bind_bft_four_cli_prepared_commit_v25':'bind_bft_four_cli_current_prepare_v26',
 'service-first-service-diag-v24':'service-first-service-diag-v25',
 'service-first-service-diag-v25':'service-first-service-diag-v26',
 'regional-bft-prepared-commit-v15-v25-source-binding':'regional-bft-current-prepare-v16-v26-source-binding',
 'test_prepared_unreceipted_commit_keeps_spare_slot_after_full_retry':'test_prepared_prepare_keeps_spare_after_native_current_commit_hint',
 'test_prepared_commit_priority_reaches_destination_after_full_retry':'test_prepared_prepare_priority_reaches_destination_after_full_retry',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s)
s=s.replace("delta==['tools/interstellar_mesh.py','tools/test_interstellar_mesh.py']","delta==['tools/interstellar_mesh.py','tools/regional_bft_node.py','tools/test_interstellar_mesh.py']")
s=s.replace("('tools/interstellar_mesh.py',{'_exchange_plan'},set())","('tools/interstellar_mesh.py',set(),set())").replace("('tools/regional_bft_node.py',set(),set())","('tools/regional_bft_node.py',{'commit_carriage_frames'},set())")
a=s.index('v15=(r/');z=s.index('# Added Native hint',a)
s=s[:a]+"mesh_now=(r/'tools/interstellar_mesh.py').read_text();ast_equal(mesh_now.replace('RLD-CONTACT-TRANSIT-SCHEDULER-V16','RLD-CONTACT-TRANSIT-SCHEDULER-V15'),original('tools/interstellar_mesh.py'))\nnode_now=(r/'tools/regional_bft_node.py').read_text();node_previous=node_now.replace(\"vote.get('phase') not in ('Prepare','Commit')\",\"vote.get('phase')!='Commit'\").replace(\"vote['round'],vote['value'],vote['phase'],key]\",\"vote['round'],vote['value'],'Commit',key]\");ast_equal(node_previous,original('tools/regional_bft_node.py'))\n"+s[z:]
a=s.index('classifier=json.loads(');z=s.index('static_stage=e/',a)
s=s[:a]+"failed=b/'native-bft-four-cli-service-first-service-diag-v25-private-20261006';failed_state=unpack_state(json.loads((failed/'runtime/3/state.json').read_text()));matrix=json.loads((e/'regional-bft-parent13-v25-matrix-20261006-checks.json').read_text());target=next(z for z in matrix['rows'] if z['source']==3 and z['kind']=='Prepare');ident=target['body_id'];body=next(body for i,body,_,_ in failed_state['messages'].bodies() if i==ident);context=body['Signed']['Vote']['context'];keys=tuple(z['key'] for z in json.loads((failed/'component-bft-config-3.json').read_text())['validators']);frames=runtime.commit_carriage_frames(failed_state['messages'],context,keys,context['currency'],context['region']);payload=failed_state['messages'].payload(ident);raw=mesh.evidence.make_frame('regional-bft',context['region'],context['region'],failed_state['messages'].content(ident),payload);exact_frame=mesh.evidence.inspect_frame(raw)[0]['message_id'];assert exact_frame in frames;assert exact_frame=='e60bf700ec274cdb7118924eb245daa2db1423d55872eba05094eb3d98f6f178'\n"+s[z:]
s=s.replace("['native-bft-four-cli-service-first-service-diag-v25','bft-current-commit-prepared-baseline-v14','bft-current-commit-prepared-related-v15','bft-current-commit-delivery-final-v15']", "['native-bft-four-cli-service-first-service-diag-v25','bft-current-commit-prepare-baseline-v15','bft-current-commit-prepare-related-v16','bft-current-commit-prepare-delivery-v16']")
s=s.replace('190 unchanged sources bound to V14','189 unchanged sources bound to V15').replace('actual_retained_V23_signed_Commit_exact_frame_classified_without_Native_constructor=True','actual_retained_V25_signed_Prepare_exact_frame_classified_without_Native_constructor=True').replace('primitive_Runtime_frame_classification_calls=0,prior_unchanged_Runtime_classification_reused=True','primitive_Runtime_frame_classification_calls=1,prior_unchanged_Runtime_classification_reused=False')
compile(s,str(new),'exec');ast.parse(s);new.write_text(s);print('new source-bound entry builder parsed; no Native/fixture calls')
