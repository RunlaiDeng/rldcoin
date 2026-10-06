from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_empty_proposal_delivery_precondition_v8_20261006', 'bft_import_parent_delivery_precondition_v9_20261006'), ('bft_four_cli_first_service_diagnostic_v12_20261006', 'bft_four_cli_first_service_diagnostic_v13_20261006'), ('regional-bft-empty-proposal-v17-identity-20261006.json', 'regional-bft-import-parent-v18-identity-20261006.json'), ('service-first-service-diag-v27', 'service-first-service-diag-v28')]
CONTROLLER_CHANGES=[('bft_empty_proposal_delivery_precondition_v8_20261006', 'bft_import_parent_delivery_precondition_v9_20261006'), ('service-first-service-diag-v27', 'service-first-service-diag-v28'), ('regional-bft-empty-proposal-v17-identity-20261006.json', 'regional-bft-import-parent-v18-identity-20261006.json'), ('regional-bft-four-cli-empty-proposal-v27-decision-allocated-20261006.json', 'regional-bft-four-cli-import-parent-v28-decision-allocated-20261006.json'), ('regional-bft-empty-proposal-entry-start-allocated-v27-20261006.json', 'regional-bft-import-parent-entry-start-allocated-v28-20261006.json'), ('bind_bft_four_cli_empty_proposal_v27_20261006', 'bind_bft_four_cli_import_parent_v28_20261006'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V17', 'RLD-CONTACT-TRANSIT-SCHEDULER-V18')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v27-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-import-parent-v28-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-import-parent-v28-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v27-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
