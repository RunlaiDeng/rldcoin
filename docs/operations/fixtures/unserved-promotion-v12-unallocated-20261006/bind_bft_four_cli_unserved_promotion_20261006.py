"""Unallocated-only V12/V8 derivative with mandatory ordinary-delivery gate."""
from pathlib import Path
PROJECT=Path('/Users/galaxy/GitHub/rldcoin');BASE=PROJECT/'tmp/default-relay-20260930'
OLD_HELPER=BASE/'observe-bft-four-cli-service-first-service-diag-v19-20261006.py'
OLD_CONTROLLER=BASE/'check-bft-four-cli-service-first-service-diag-v19-20261006.py'
NEW_HELPER=BASE/'observe-bft-four-cli-service-first-service-diag-v20-20261006.py'
NEW_CONTROLLER=BASE/'check-bft-four-cli-service-first-service-diag-v20-20261006.py'
DECISION='regional-bft-four-cli-unserved-promotion-decision-unarmed-20261006.json'
GUARD="from bft_unserved_delivery_precondition_v1_20261006 import require_current_delivery\nrequire_current_delivery()\n"
def helper_transformations():
 return [('from regional_paged_fault_prepare import Preparation',GUARD+'from regional_paged_fault_prepare import Preparation'),('bft_four_cli_first_service_diagnostic_v4_20261006','bft_four_cli_first_service_diagnostic_v5_20261006'),('native-bft-four-cli-service-first-service-diag-v19-private-20261006','native-bft-four-cli-service-first-service-diag-v20-private-20261006'),('regional-bft-ordinary-newest-final-identity-20261006.json','regional-bft-unserved-promotion-final-identity-20261006.json')]
def controller_transformations():
 before="""newest_binding=json.loads((e/'regional-bft-ordinary-newest-final-binding-v1-20261006-checks.json').read_text());newest_ground=json.loads((e/'regional-bft-ordinary-newest-ground-v2-20261006-checks.json').read_text())
assert newest_binding['completed'] and newest_binding['result']['whole_V10_mesh_AST_after_only_newest_assignment_and_profile_reversal'] and newest_binding['result']['actual_candidate_AST_matches_qualified120_model_cases'] and newest_binding['result']['python_source_commitment']==x['python_source_commitment'] and newest_binding['result']['original17setup13import15mature_all8cold_caller_owner_conservation_stop_preserved'] and newest_binding['result']['new180_allocated']==0 and newest_binding['result']['new600_allocated']==0
assert newest_ground['completed'] and newest_ground['result']['tests_run']==10 and newest_ground['result']['latest_target_actual_ground_behavior'] and newest_ground['result']['original_pending17gap_other_class_floor_full4_cold_negative_atomic']"""
 after="""promotion_binding=json.loads((e/'regional-bft-unserved-promotion-final-binding-v2-20261006-checks.json').read_text());promotion_ground=json.loads((e/'regional-bft-unserved-promotion-ground-v3-20261006-checks.json').read_text());promotion_entry=json.loads((e/'regional-bft-unserved-promotion-entry-v8-source-binding-20261006-checks.json').read_text())
assert promotion_binding['completed'] and promotion_binding['result']['whole_mesh_AST_reversed_one_assignment_profile'] and promotion_binding['result']['exact_current_branch_matches_qualified48_case_model'] and promotion_binding['result']['python_source_commitment']==x['python_source_commitment'] and promotion_binding['result']['native89_core171_actual_binary_unchanged'] and promotion_binding['result']['new180_allocated']==0 and promotion_binding['result']['new600_allocated']==0
assert promotion_ground['completed'] and promotion_ground['result']['tests_run']==11 and promotion_ground['result']['latest_target_actual_ground_behavior'] and promotion_ground['result']['original_pending17gap_other_class_floor_full4_cold_negative_atomic']
assert promotion_entry['completed'] and promotion_entry['result']['whole_V7_entry_exact_after_only_four_literal_reversal'] and promotion_entry['result']['all_original_parameters_equal'] and promotion_entry['result']['unallocated_V8_main_refuses_before_Mesh_import']"""
 return [('from regional_paged_fault_scope import inventory',GUARD+'from regional_paged_fault_scope import inventory'),(before,after),('service-first-service-diag-v19','service-first-service-diag-v20'),('regional-bft-four-cli-ordinary-newest-decision-unarmed-20261006.json',DECISION),('regional-bft-ordinary-newest-final-identity-20261006.json','regional-bft-unserved-promotion-final-identity-20261006.json'),('bind_bft_four_cli_ordinary_newest_20261006','bind_bft_four_cli_unserved_promotion_20261006'),('regional-bft-ordinary-newest-entry-start-allocated-v19-20261006.json','regional-bft-unserved-promotion-entry-start-allocated-v20-20261006.json'),('RLD-CONTACT-TRANSIT-SCHEDULER-V11','RLD-CONTACT-TRANSIT-SCHEDULER-V12')]
def transform(text,changes):
 for before,after in changes:
  if before not in text:raise ValueError('missing exact unserved-priority binding')
  text=text.replace(before,after)
 return text
def helper_source():return transform(OLD_HELPER.read_text(),helper_transformations())
def controller_source(decision=DECISION):
 if decision!=DECISION:raise ValueError('V20 remains unallocated; ordinary delivery unknown')
 return transform(OLD_CONTROLLER.read_text(),controller_transformations())
def validate(helper,controller,decision=DECISION):
 if helper!=helper_source() or controller!=controller_source(decision):raise ValueError('unreviewed unserved-priority helper/controller')
 compile(helper,str(NEW_HELPER),'exec');compile(controller,str(NEW_CONTROLLER),'exec');return True
