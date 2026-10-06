from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_bounded_readonly_delivery_precondition_v14_20261007', 'bft_selector_observation_delivery_precondition_v19_20261007'), ('bft_four_cli_first_service_diagnostic_v18_20261007', 'bft_four_cli_first_service_diagnostic_v23_20261007'), ('regional-bft-bounded-readonly-v33-identity-20261007.json', 'regional-bft-selector-observation-v38-identity-20261007.json'), ('service-first-service-diag-v33', 'service-first-service-diag-v38')]
CONTROLLER_CHANGES=[('bft_bounded_readonly_delivery_precondition_v14_20261007', 'bft_selector_observation_delivery_precondition_v19_20261007'), ('service-first-service-diag-v33', 'service-first-service-diag-v38'), ('regional-bft-bounded-readonly-v33-identity-20261007.json', 'regional-bft-selector-observation-v38-identity-20261007.json'), ('regional-bft-four-cli-bounded-readonly-v33-decision-allocated-20261007.json', 'regional-bft-four-cli-selector-observation-v38-decision-allocated-20261007.json'), ('regional-bft-bounded-readonly-entry-start-allocated-v33-20261007.json', 'regional-bft-selector-observation-entry-start-allocated-v38-20261007.json'), ('bind_bft_four_cli_bounded_readonly_v33_20261007', 'bind_bft_four_cli_selector_observation_v38_20261007'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V22', 'RLD-CONTACT-TRANSIT-SCHEDULER-V24')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v33-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-selector-observation-v38-decision-allocated-20261007.json'):
 if decision!='regional-bft-four-cli-selector-observation-v38-decision-allocated-20261007.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v33-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
HELPER_CHANGES.append(('first_service_diagnostic_collector_v1_20261006','first_service_diagnostic_collector_v4_20261007'))
