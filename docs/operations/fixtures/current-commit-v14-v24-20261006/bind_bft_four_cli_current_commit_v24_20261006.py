from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_older_spare_delivery_precondition_v4_20261006', 'bft_current_commit_delivery_precondition_v5_20261006'), ('bft_four_cli_first_service_diagnostic_v8_20261006', 'bft_four_cli_first_service_diagnostic_v9_20261006'), ('regional-bft-older-spare-v13-identity-20261006.json', 'regional-bft-current-commit-v14-identity-20261006.json'), ('service-first-service-diag-v23', 'service-first-service-diag-v24')]
CONTROLLER_CHANGES=[('bft_older_spare_delivery_precondition_v4_20261006', 'bft_current_commit_delivery_precondition_v5_20261006'), ('service-first-service-diag-v23', 'service-first-service-diag-v24'), ('regional-bft-older-spare-v13-identity-20261006.json', 'regional-bft-current-commit-v14-identity-20261006.json'), ('regional-bft-four-cli-older-spare-v23-decision-allocated-20261006.json', 'regional-bft-four-cli-current-commit-v24-decision-allocated-20261006.json'), ('regional-bft-older-spare-entry-start-allocated-v23-20261006.json', 'regional-bft-current-commit-entry-start-allocated-v24-20261006.json'), ('bind_bft_four_cli_older_spare_v23_20261006', 'bind_bft_four_cli_current_commit_v24_20261006'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V13', 'RLD-CONTACT-TRANSIT-SCHEDULER-V14')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v23-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-current-commit-v24-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-current-commit-v24-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v23-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
