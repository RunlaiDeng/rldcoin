from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'bind-bft-empty-proposal-v17-native-v27-20261006.py';new=b/'bind-bft-import-parent-v18-native-v28-20261006.py';assert not new.exists();s=old.read_text();m={
 '36655c790:':'3dcf9bbce:',
 'regional-bft-current-prepare-v16-identity':'regional-bft-empty-proposal-v17-identity',
 'regional-bft-empty-proposal-v17-identity':'regional-bft-import-parent-v18-identity',
 'regional-bft-current-commit-proposal-delivery-v17':'regional-bft-current-commit-import-parent-delivery-v18',
 'bft-current-commit-proposal-delivery-v17':'bft-current-commit-import-parent-delivery-v18',
 'regional-bft-current-commit-proposal-related-v17':'regional-bft-current-commit-import-parent-related-v18',
 'regional-bft-current-commit-proposal-baseline-v16':'regional-bft-current-commit-import-parent-baseline-v17',
 'regional-bft-empty-proposal-delivery-v17':'regional-bft-import-parent-delivery-v18',
 'regional-bft-empty-proposal-delivery-qualified-v17':'regional-bft-import-parent-delivery-qualified-v18',
 'regional-bft-current-prepare-delivery-qualified-v16':'regional-bft-empty-proposal-delivery-qualified-v17',
 'regional-bft-current-prepare-delivery-v16':'regional-bft-empty-proposal-delivery-v17',
 'observe-bft-current-commit-prepare-delivery-v16':'observe-bft-current-commit-proposal-delivery-v17',
 'observe-bft-current-commit-proposal-delivery-v17':'observe-bft-current-commit-import-parent-delivery-v18',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V16':'RLD-CONTACT-TRANSIT-SCHEDULER-V17',
 'RLD-CONTACT-TRANSIT-SCHEDULER-V17':'RLD-CONTACT-TRANSIT-SCHEDULER-V18',
 'first_service_diagnostic_entry_contract_v14':'first_service_diagnostic_entry_contract_v15',
 'first_service_diagnostic_entry_contract_v15':'first_service_diagnostic_entry_contract_v16',
 'first_service_diagnostic_entry_v14':'first_service_diagnostic_entry_v15',
 'first_service_diagnostic_entry_v15':'first_service_diagnostic_entry_v16',
 'bft_four_cli_first_service_diagnostic_v11':'bft_four_cli_first_service_diagnostic_v12',
 'bft_four_cli_first_service_diagnostic_v12':'bft_four_cli_first_service_diagnostic_v13',
 'bft_current_prepare_delivery_precondition_v7':'bft_empty_proposal_delivery_precondition_v8',
 'bft_empty_proposal_delivery_precondition_v8':'bft_import_parent_delivery_precondition_v9',
 'regional-bft-current-prepare-entry-start-allocated-v26':'regional-bft-empty-proposal-entry-start-allocated-v27',
 'regional-bft-empty-proposal-entry-start-allocated-v27':'regional-bft-import-parent-entry-start-allocated-v28',
 'regional-bft-four-cli-current-prepare-v26-decision':'regional-bft-four-cli-empty-proposal-v27-decision',
 'regional-bft-four-cli-empty-proposal-v27-decision':'regional-bft-four-cli-import-parent-v28-decision',
 'bind_bft_four_cli_current_prepare_v26':'bind_bft_four_cli_empty_proposal_v27',
 'bind_bft_four_cli_empty_proposal_v27':'bind_bft_four_cli_import_parent_v28',
 'service-first-service-diag-v26':'service-first-service-diag-v27',
 'service-first-service-diag-v27':'service-first-service-diag-v28',
 'regional-bft-empty-proposal-v17-v27-source-binding':'regional-bft-import-parent-v18-v28-source-binding',
 'test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint':'test_prepared_import_parent_proposal_keeps_spare_after_native_current_hint',
 'test_prepared_empty_proposal_priority_reaches_destination_after_full_retry':'test_prepared_import_parent_proposal_priority_reaches_destination_after_full_retry',
 'bft-current-commit-proposal-baseline-v16':'bft-current-commit-import-parent-baseline-v17',
 'bft-current-commit-proposal-related-v17':'bft-current-commit-import-parent-related-v18',
 'signed_ground_empty_proposal':'signed_ground_import_parent_proposal',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s)
s=s.replace("('tools/regional_bft_node.py',{'commit_carriage_frames'},{'current_empty_proposal_hint'})","('tools/regional_bft_node.py',{'current_empty_proposal_hint'},set())")
a=s.index("node_now=(r/");z=s.index('# Added Native hint',a)
s=s[:a]+'''node_now=(r/'tools/regional_bft_node.py').read_text();node_before=original('tools/regional_bft_node.py')
old_fn=next(z for z in ast.parse(node_before).body if isinstance(z,ast.FunctionDef) and z.name=='current_empty_proposal_hint');new_fn=next(z for z in ast.parse(node_now).body if isinstance(z,ast.FunctionDef) and z.name=='current_empty_proposal_hint')
lines=node_now.splitlines(True);old_text=''.join(node_before.splitlines(True)[old_fn.lineno-1:old_fn.end_lineno]);reversed_node=''.join(lines[:new_fn.lineno-1])+old_text+''.join(lines[new_fn.end_lineno:]);ast_equal(reversed_node,node_before)
# The only changed existing function is the exact bounded parent Import encoding.
expected=old_text.replace('Scheduling only for a Native-checked round-zero empty two-block proposal.','Scheduling only for a Native-checked empty candidate and bounded parent.').replace('    Complex commands, epochs, timeout rounds and other shapes use ordinary','    Only parent Import commands (original maximum 16) have a typed encoding.\\n    Other commands, epochs, timeout rounds and other shapes use ordinary')
a=expected.index("    for block in snapshot['blocks']:");z=expected.index('    encode=lambda value:',a)
expected=expected[:a]+"""    for index,block in enumerate(snapshot['blocks']):
        if (type(block) is not dict or set(block)!={'header','commands'}
                or type(block['commands']) is not list or len(block['commands'])>16
                or index==1 and block['commands']!=[]
                or type(block['header']) is not dict or set(block['header'])!=set(header_fields)):return False
        commands=[]
        for command in block['commands']:
            if (type(command) is not dict or set(command)!={'Import'}
                    or type(command['Import']) is not dict or set(command['Import'])!={'snapshot','export'}):return False
            imp=command['Import'];mesh.hex32(imp['snapshot']);mesh.hex32(imp['export'])
            commands.append({'Import':{'snapshot':imp['snapshot'],'export':imp['export']}})
        h={k:block['header'][k] for k in header_fields};headers.append(h);blocks.append(dict(header=h,commands=commands))
"""+expected[z:]
expected=expected.replace("    parent,child=headers;statement=snapshot['statement']", "    parent,child=headers;statement=snapshot['statement']\\n    if (blocks[0]['commands'] and parent['commands']!=hashlib.sha256(\\n            b'RLD-REGIONAL-FIXTURE-V1:commands\\\\0'+encode(blocks[0]['commands'])).hexdigest()):return False")
ast_equal(expected,'\\n'.join(node_now.splitlines()[new_fn.lineno-1:new_fn.end_lineno]))
''' +s[z:]
a=s.index('failed=b/');z=s.index('static_stage=e/',a)
s=s[:a]+'''failed=b/'native-bft-four-cli-service-first-service-diag-v27-private-20261006';failed_state=unpack_state(json.loads((failed/'runtime/1/state.json').read_text()));matrix=json.loads((e/'regional-bft-parent13-v27-matrix-20261006-checks.json').read_text());target=next(z for z in matrix['rows'] if z['source']==1 and z['kind']=='Proposal');ident=target['body_id'];body=next(body for i,body,_,_ in failed_state['messages'].bodies() if i==ident);context=next(body['Signed']['Vote']['context'] for _,body,_,local in failed_state['messages'].bodies() if local and body.get('Signed',{}).get('Vote',{}).get('context',{}).get('parent_height')==13);keys=tuple(z['key'] for z in json.loads((failed/'component-bft-config-1.json').read_text())['validators']);assert runtime.current_empty_proposal_hint(body['Signed']['Proposal'],context,keys);frames=runtime.commit_carriage_frames(failed_state['messages'],context,keys,context['currency'],context['region']);payload=failed_state['messages'].payload(ident);raw=mesh.evidence.make_frame('regional-bft',context['region'],context['region'],failed_state['messages'].content(ident),payload);exact_frame=mesh.evidence.inspect_frame(raw)[0]['message_id'];assert exact_frame in frames
''' +s[z:]
s=s.replace('189 unchanged sources bound to V16','189 unchanged sources bound to V17').replace('actual_retained_V26_signed_empty_Proposal_exact_frame_classified_without_Native_constructor','actual_retained_V27_signed_Import_parent_Proposal_exact_frame_classified_without_Native_constructor');compile(s,str(new),'exec');new.write_text(s)
