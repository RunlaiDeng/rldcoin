from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'bind-bft-current-prepare-v16-native-v26-v2-20261006.py';new=b/'bind-bft-empty-proposal-v17-native-v27-20261006.py';assert not new.exists();s=old.read_text();m={
 '2d9f028b9:':'36655c790:',
 'regional-bft-prepared-commit-v15-identity':'regional-bft-current-prepare-v16-identity',
 'regional-bft-current-prepare-v16-identity':'regional-bft-empty-proposal-v17-identity',
 'regional-bft-current-commit-prepare-delivery-v16':'regional-bft-current-commit-proposal-delivery-v17',
 'bft-current-commit-prepare-delivery-v16':'bft-current-commit-proposal-delivery-v17',
 'regional-bft-current-commit-prepare-related-v16':'regional-bft-current-commit-proposal-related-v17',
 'regional-bft-current-commit-prepare-baseline-v15':'regional-bft-current-commit-proposal-baseline-v16',
 'regional-bft-current-prepare-delivery-v16':'regional-bft-empty-proposal-delivery-v17',
 'regional-bft-current-prepare-delivery-qualified-v16':'regional-bft-empty-proposal-delivery-qualified-v17',
 'regional-bft-prepared-commit-delivery-qualified-v15':'regional-bft-current-prepare-delivery-qualified-v16',
 'regional-bft-prepared-commit-delivery-v15':'regional-bft-current-prepare-delivery-v16',
 'observe-bft-current-commit-delivery-final-v15':'observe-bft-current-commit-prepare-delivery-v16',
 'observe-bft-current-commit-prepare-delivery-v16':'observe-bft-current-commit-proposal-delivery-v17',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V15':'RLD-CONTACT-TRANSIT-SCHEDULER-V16',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V16':'RLD-CONTACT-TRANSIT-SCHEDULER-V17',
 'first_service_diagnostic_entry_contract_v13':'first_service_diagnostic_entry_contract_v14',
 'first_service_diagnostic_entry_contract_v14':'first_service_diagnostic_entry_contract_v15',
 'first_service_diagnostic_entry_v13':'first_service_diagnostic_entry_v14',
 'first_service_diagnostic_entry_v14':'first_service_diagnostic_entry_v15',
 'bft_four_cli_first_service_diagnostic_v10':'bft_four_cli_first_service_diagnostic_v11',
 'bft_four_cli_first_service_diagnostic_v11':'bft_four_cli_first_service_diagnostic_v12',
 'bft_prepared_commit_delivery_precondition_v6':'bft_current_prepare_delivery_precondition_v7',
 'bft_current_prepare_delivery_precondition_v7':'bft_empty_proposal_delivery_precondition_v8',
 'regional-bft-prepared-commit-entry-start-allocated-v25':'regional-bft-current-prepare-entry-start-allocated-v26',
 'regional-bft-current-prepare-entry-start-allocated-v26':'regional-bft-empty-proposal-entry-start-allocated-v27',
 'regional-bft-four-cli-prepared-commit-v25-decision':'regional-bft-four-cli-current-prepare-v26-decision',
 'regional-bft-four-cli-current-prepare-v26-decision':'regional-bft-four-cli-empty-proposal-v27-decision',
 'bind_bft_four_cli_prepared_commit_v25':'bind_bft_four_cli_current_prepare_v26',
 'bind_bft_four_cli_current_prepare_v26':'bind_bft_four_cli_empty_proposal_v27',
 'service-first-service-diag-v25':'service-first-service-diag-v26',
 'service-first-service-diag-v26':'service-first-service-diag-v27',
 'regional-bft-current-prepare-v16-v26-source-binding':'regional-bft-empty-proposal-v17-v27-source-binding',
 'test_prepared_prepare_keeps_spare_after_native_current_commit_hint':'test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint',
 'test_prepared_prepare_priority_reaches_destination_after_full_retry':'test_prepared_empty_proposal_priority_reaches_destination_after_full_retry',
 'bft-current-commit-prepare-baseline-v15':'bft-current-commit-proposal-baseline-v16',
 'bft-current-commit-prepare-related-v16':'bft-current-commit-proposal-related-v17',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s)
s=s.replace('deadline=start+59.5','deadline=start+60').replace(" if p.exists():\n  assert p.name=='regional-bft-empty-proposal-v17-identity-20261006.json' and p.read_text()==text;return\n",' assert not p.exists(),str(p)\n').replace("('tools/regional_bft_node.py',{'commit_carriage_frames'},set())","('tools/regional_bft_node.py',{'commit_carriage_frames'},{'current_empty_proposal_hint'})").replace("{'test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint','test_prepared_empty_proposal_priority_reaches_destination_after_full_retry'}","{'test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint','test_prepared_empty_proposal_priority_reaches_destination_after_full_retry','signed_ground_empty_proposal'}")
a=s.index("node_now=(r/");z=s.index('# Added Native hint',a)
s=s[:a]+'''node_now=(r/'tools/regional_bft_node.py').read_text();node_before=original('tools/regional_bft_node.py')
helper=next(z for z in ast.parse(node_now).body if isinstance(z,ast.FunctionDef) and z.name=='current_empty_proposal_hint')
helper_text='\\n'.join(node_now.splitlines()[helper.lineno-1:helper.end_lineno])+'\\n\\n\\n'
node_before=node_before.replace('def commit_carriage_frames(',helper_text+'def commit_carriage_frames(',1)
a=node_before.index("        vote=body.get('Signed',{}).get('Vote',{})");z=node_before.index('            expanded_bytes+=',a)
branch="""        signed=body.get('Signed',{});vote=signed.get('Vote',{});proposal=signed.get('Proposal')
        try:
            if proposal is not None:
                if not current_empty_proposal_hint(proposal,context,keys):continue
            else:
                if vote.get('phase') not in ('Prepare','Commit') or vote.get('context')!=context:continue
                approval=vote['approval'];key=approval['key']
                if key not in keys:continue
                data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\\\\0'+wire.json.dumps(
                    [{k:context[k] for k in fields},vote['round'],vote['value'],vote['phase'],key],
                    separators=(',',':'),ensure_ascii=False).encode()
                mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                    bytes.fromhex(approval['signature']),data)
"""
node_before=node_before[:a]+branch+node_before[z:];node_before=node_before.replace('Exact current Prepare/Commit frames from Native-checked Messages.','Exact current votes and bounded empty proposals from Native-checked Messages.');ast_equal(node_now,node_before)
''' +s[z:]
a=s.index('failed=b/');z=s.index('static_stage=e/',a)
s=s[:a]+'''failed=b/'native-bft-four-cli-service-first-service-diag-v26-private-20261006';failed_state=unpack_state(json.loads((failed/'runtime/2/state.json').read_text()));matrix=json.loads((e/'regional-bft-parent14-v26-matrix-20261006-checks.json').read_text());target=next(z for z in matrix['rows'] if z['source']==2 and z['kind']=='Proposal');ident=target['body_id'];body=next(body for i,body,_,_ in failed_state['messages'].bodies() if i==ident);context=next(body['Signed']['Vote']['context'] for _,body,_,local in failed_state['messages'].bodies() if local and body.get('Signed',{}).get('Vote',{}).get('context',{}).get('parent_height')==14);keys=tuple(z['key'] for z in json.loads((failed/'component-bft-config-2.json').read_text())['validators']);assert runtime.current_empty_proposal_hint(body['Signed']['Proposal'],context,keys);frames=runtime.commit_carriage_frames(failed_state['messages'],context,keys,context['currency'],context['region']);payload=failed_state['messages'].payload(ident);raw=mesh.evidence.make_frame('regional-bft',context['region'],context['region'],failed_state['messages'].content(ident),payload);exact_frame=mesh.evidence.inspect_frame(raw)[0]['message_id'];assert exact_frame in frames
''' +s[z:]
s=s.replace('actual_retained_V25_signed_Prepare_exact_frame_classified_without_Native_constructor=True','actual_retained_V26_signed_empty_Proposal_exact_frame_classified_without_Native_constructor=True,actual_full_Proposal_Rust_domain_signature_verified=True').replace('combined_original60_seconds=round(time.monotonic()-start+.5,6)','combined_original60_seconds=round(time.monotonic()-start,6)');compile(s,str(new),'exec');new.write_text(s)
