from pathlib import Path
import re
b=Path('tmp/default-relay-20260930');src=b/'bind-current-frame-set-v26-native-v40-20261007.py';dst=b/'bind-input-release-wake-v27-native-v41-20261007.py';assert not dst.exists();s=src.read_text()
mapping={
'29951a88d':'5a387d88f',
'regional-bft-current-copy-v25-identity-20261007.json':'regional-bft-current-frame-set-v26-identity-20261007.json',
'regional-bft-current-frame-set-v26-identity-20261007.json':'regional-bft-input-release-wake-v27-identity-20261007.json',
'current-frame-set-related-v26-v2':'input-release-wake-related-v27',
'combined_current_frame_set_related60_seconds':'combined_original60_seconds',
'current-frame-set-baseline-v25':'input-release-wake-baseline-v26',
'regional-bft-relay-selected-frames-v39-v2-20261007-checks.json':'regional-bft-proposal-exact-refusal-v40-20261007-checks.json',
'RLD-CONTACT-TRANSIT-SCHEDULER-V25':'RLD-CONTACT-TRANSIT-SCHEDULER-V26',
'RLD-CONTACT-TRANSIT-SCHEDULER-V26':'RLD-CONTACT-TRANSIT-SCHEDULER-V27',
'current-frame-set-delivery-v26':'input-release-wake-delivery-v27',
'current-frame-set-delivery-qualified-v26':'input-release-wake-delivery-qualified-v27',
'first_service_diagnostic_entry_contract_v27':'first_service_diagnostic_entry_contract_v28',
'first_service_diagnostic_entry_contract_v28':'first_service_diagnostic_entry_contract_v29',
'first_service_diagnostic_entry_v27':'first_service_diagnostic_entry_v28',
'first_service_diagnostic_entry_v28':'first_service_diagnostic_entry_v29',
'bft_four_cli_first_service_diagnostic_v24':'bft_four_cli_first_service_diagnostic_v25',
'bft_four_cli_first_service_diagnostic_v25':'bft_four_cli_first_service_diagnostic_v26',
'bft_current_copy_delivery_precondition_v20':'bft_current_frame_set_delivery_precondition_v21',
'bft_current_frame_set_delivery_precondition_v21':'bft_input_release_wake_delivery_precondition_v22',
'service-first-service-diag-v39':'service-first-service-diag-v40',
'service-first-service-diag-v40':'service-first-service-diag-v41',
'regional-bft-four-cli-current-copy-v39-decision-allocated':'regional-bft-four-cli-current-frame-set-v40-decision-allocated',
'regional-bft-four-cli-current-frame-set-v40-decision-allocated':'regional-bft-four-cli-input-release-wake-v41-decision-allocated',
'regional-bft-current-copy-entry-start-allocated-v39':'regional-bft-current-frame-set-entry-start-allocated-v40',
'regional-bft-current-frame-set-entry-start-allocated-v40':'regional-bft-input-release-wake-entry-start-allocated-v41',
'bind_bft_four_cli_current_copy_v39':'bind_bft_four_cli_current_frame_set_v40',
'bind_bft_four_cli_current_frame_set_v40':'bind_bft_four_cli_input_release_wake_v41',
'launch-owned-original-v39':'launch-owned-original-v40',
'launch-owned-original-v40':'launch-owned-original-v41',
'regional-bft-four-cli-v39-owned-controller':'regional-bft-four-cli-v40-owned-controller',
'regional-bft-four-cli-v40-owned-controller':'regional-bft-four-cli-v41-owned-controller',
'current-copy-delivery-qualified-v25':'current-frame-set-delivery-qualified-v26',
'current-copy-delivery-v25':'current-frame-set-delivery-v26',
'observe-bft-current-copy-related-v25-20261007.py':'observe-bft-current-frame-set-related-v26-v2-20261007.py',
'observe-bft-current-frame-set-related-v26-v2-20261007.py':'observe-input-release-wake-tcp-related-v27-20261007.py',
'regional-bft-exact-selector-decision-v39':'regional-bft-exact-selector-decision-v40',
'regional-bft-current-copy-v25-v39-source-binding':'regional-bft-current-frame-set-v26-v40-source-binding',
'regional-bft-current-frame-set-v26-v40-source-binding':'regional-bft-input-release-wake-v27-v41-source-binding',
'current-frame-set-v26-v40-20261007':'input-release-wake-v27-v41-20261007',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m.group()],s)
a=s.index("rev=json.loads(");z=s.index("assert all(sha(r/p)==h",a)
s=s[:a]+'''rev=json.loads((b/'input-release-wake-v27-reversal-20261007.json').read_text());text=(r/'tools/interstellar_tcp.py').read_text();a,z=rev['tcp_replacement'];assert text.count(z)==1;assert text.replace(z,a)==original('tools/interstellar_tcp.py')==(b/'tcp-before-input-release-wake-v27-20261007.py').read_text()
assert (r/'tools/interstellar_mesh.py').read_text().replace('RLD-CONTACT-TRANSIT-SCHEDULER-V27','RLD-CONTACT-TRANSIT-SCHEDULER-V26')==original('tools/interstellar_mesh.py')
for path in ('tools/regional_bft_node.py','tools/interstellar_frame_digest.py','tools/test_interstellar_mesh.py'):assert (r/path).read_text()==original(path)
tests_text=(r/'tools/test_interstellar_tcp.py').read_text();assert tests_text.count(rev['tests_addition'])==1 and tests_text.replace(rev['tests_addition'],'',1)==original('tools/test_interstellar_tcp.py')
'''+s[z:]
s=s.replace("assert delta==['tools/interstellar_mesh.py','tools/test_interstellar_mesh.py']","assert delta==['tools/interstellar_mesh.py','tools/interstellar_tcp.py','tools/test_interstellar_tcp.py']").replace("'Ran 9 tests'","'Ran 13 tests'")
s=s.replace("neg['helper_exit_code']==1 and neg['production_sources_freeze_and_old_inventory_unchanged']","neg['exit_code']==1 and neg['source_and_failed_seal_unchanged']")
a=s.index("packets=aq['packets']");z=s.index('\nx=copy.deepcopy(old)',a)
s=s[:a]+"assert len(aq['rows'])==2 and all(not row['custody_any'] and any(v['stage']=='deferred_input_not_queued' and v['failure_stage']=='input_slot_occupied' for v in row['exact_destination_events']) for row in aq['rows']);assert aq['sealed_bytes_unchanged']"+s[z:]
s=s.replace("'input-release-wake-baseline-v26-stopped-inventory-20261007.json',",'').replace('bft-input-release-wake-related-v27-stopped-private-inventory-20261007.json','input-release-wake-related-v27-stopped-private-inventory-20261007.json')
s=s.replace("root=b/'bft-input-release-wake-related-v27-private-20261007'","root=b/'input-release-wake-ordinary-v27-private-20261007'")
s=s.replace('assert json.loads(seal.read_text())[str(root)]==inventory(root)',"assert json.loads(seal.read_text())[str(root)]==inventory(root);tcp_root=b/'input-release-wake-tcp-related-v27-private-20261007';assert json.loads(seal.read_text())[str(tcp_root)]==inventory(tcp_root)")
s=s.replace("b/'current-frame-set-v26-reversal-20261007.json',b/'current-frame-set-v26-test-reversal-v2-20261007.json'","b/'input-release-wake-v27-reversal-20261007.json'")
s=s.replace('old_V39_failed1825_still_FAIL','old_V40_failed1715_still_FAIL')
a=s.index(",live_hypothesis='");z=s.index("\nz['protected_sha256']",a)
s=s[:a]+",live_hypothesis='V40 source2 Proposal to1 was durably prepared and sent twice; exact peer/nonce/packet/frame rows show request authenticated then original pre-open lock refusal and original input slot occupied, no custody. Actual old-input slots2.633490 and1.711887sec later complete; not cryptographic rejection nor unique maturity cause. Fresh actual owned waiting thread model V26 FAIL0.265127: original local lease release did not notify existing input_wake, retains fixed .25 poll. V27 adds only actual release event signal for existing live retained input waiter, no new slot/deadline/auth change;13 related PASS3.346110 incl4real pinnedTLS custody and once final ordinary receipt cold. One fresh original180 tests whether original15mature/full8cold/envelopes/heads/conservation/normalstop complete.',live_exit='First binding/role/auth/atomic/originalcapacity/prefix guard or original180; stop and preserveFAIL; original17setup/13import/15mature/full8Nativecold/every envelope/heads/conservation/normalstop and total<=180 required. No unchanged rerun/oldfixture reopens/new600/deadlineextension.')"+s[z:]
s=s.replace('actual_related9_and_once_final_ordinary_signed_delivery_reused=True','actual_related13_and_once_final_ordinary_signed_delivery_reused=True').replace('all_old_methods_except_exchange_plan_prepare_AST_preserved=True','all_old_methods_except_TCP_release_exact_text_preserved=True').replace('stable_set_frame_rotation_changed_only_current_positions=True','mesh_profile_only_changed=True').replace('whole_source_reversal_equal','whole_source_reversal_equal')
a=s.index(';extra=[');z=s.index('\nfor p in [p for p in paths',a)
s=s[:a]+";extra=[b/'observe-v40-proposal-exact-refusal-20261007.py',b/'observe-v40-exact-input-window-20261007.py',b/'input-release-wake-counter-v26-20261007.py',b/'check-input-release-wake-baseline-v26-20261007.py',b/'check-input-release-wake-related-v27-20261007.py',b/'build-input-release-wake-v27-20261007.py',b/'generate-input-wake-binder-v27-20261007.py']"+s[z:]
a=s.index("(review/'README.md').write_text(");z=s.index('\nprint(',a)
s=s[:a]+"(review/'README.md').write_text('V40 FAIL original180/192.225inclcleanup/1715sealed. Exact Proposal2to1 sent/authenticated twice then original input slot refusal. Fresh actual waiting-thread event counter FAIL0.265127, V27 only notifies existing active live input waiter on actual other lease release. Original.2 acquisition/3connection/2workers/1deferred/allfullauth unchanged.13related PASS3.346110/62sealed incl genuine pinnedTLS custody and once final ordinary receipt cold. All original production methods exceptTCP_release exact, mesh profile only. One fresh original180/full15mature/full8cold/all envelopes/heads/conservation/stop; no600/oldfixture reopening.\\n')"+s[z:]
compile(s,str(dst),'exec');dst.write_text(s);print(dst)
