from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_current_prepare_delivery_precondition_v7_20261006', 'bft_empty_proposal_delivery_precondition_v8_20261006'), ('bft_four_cli_first_service_diagnostic_v11_20261006', 'bft_four_cli_first_service_diagnostic_v12_20261006'), ('regional-bft-current-prepare-v16-identity-20261006.json', 'regional-bft-empty-proposal-v17-identity-20261006.json'), ('service-first-service-diag-v26', 'service-first-service-diag-v27')]
CONTROLLER_CHANGES=[('bft_current_prepare_delivery_precondition_v7_20261006', 'bft_empty_proposal_delivery_precondition_v8_20261006'), ('service-first-service-diag-v26', 'service-first-service-diag-v27'), ('regional-bft-current-prepare-v16-identity-20261006.json', 'regional-bft-empty-proposal-v17-identity-20261006.json'), ('regional-bft-four-cli-current-prepare-v26-decision-allocated-20261006.json', 'regional-bft-four-cli-empty-proposal-v27-decision-allocated-20261006.json'), ('regional-bft-current-prepare-entry-start-allocated-v26-20261006.json', 'regional-bft-empty-proposal-entry-start-allocated-v27-20261006.json'), ('bind_bft_four_cli_current_prepare_v26_20261006', 'bind_bft_four_cli_empty_proposal_v27_20261006'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V16', 'RLD-CONTACT-TRANSIT-SCHEDULER-V17')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v26-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-empty-proposal-v27-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-empty-proposal-v27-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v26-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
