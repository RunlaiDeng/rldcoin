from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_current_commit_delivery_precondition_v5_20261006', 'bft_prepared_commit_delivery_precondition_v6_20261006'), ('bft_four_cli_first_service_diagnostic_v9_20261006', 'bft_four_cli_first_service_diagnostic_v10_20261006'), ('regional-bft-current-commit-v14-identity-20261006.json', 'regional-bft-prepared-commit-v15-identity-20261006.json'), ('service-first-service-diag-v24', 'service-first-service-diag-v25')]
CONTROLLER_CHANGES=[('bft_current_commit_delivery_precondition_v5_20261006', 'bft_prepared_commit_delivery_precondition_v6_20261006'), ('service-first-service-diag-v24', 'service-first-service-diag-v25'), ('regional-bft-current-commit-v14-identity-20261006.json', 'regional-bft-prepared-commit-v15-identity-20261006.json'), ('regional-bft-four-cli-current-commit-v24-decision-allocated-20261006.json', 'regional-bft-four-cli-prepared-commit-v25-decision-allocated-20261006.json'), ('regional-bft-current-commit-entry-start-allocated-v24-20261006.json', 'regional-bft-prepared-commit-entry-start-allocated-v25-20261006.json'), ('bind_bft_four_cli_current_commit_v24_20261006', 'bind_bft_four_cli_prepared_commit_v25_20261006'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V14', 'RLD-CONTACT-TRANSIT-SCHEDULER-V15')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v24-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-prepared-commit-v25-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-prepared-commit-v25-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v24-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
