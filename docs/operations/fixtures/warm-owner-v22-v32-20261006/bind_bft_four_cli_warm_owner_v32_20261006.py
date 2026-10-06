from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_remote_hint_delivery_precondition_v12_20261006', 'bft_warm_owner_delivery_precondition_v13_20261006'), ('bft_four_cli_first_service_diagnostic_v16_20261006', 'bft_four_cli_first_service_diagnostic_v17_20261006'), ('regional-bft-remote-hint-v21-identity-20261006.json', 'regional-bft-warm-owner-v22-identity-20261006.json'), ('service-first-service-diag-v31', 'service-first-service-diag-v32')]
CONTROLLER_CHANGES=[('bft_remote_hint_delivery_precondition_v12_20261006', 'bft_warm_owner_delivery_precondition_v13_20261006'), ('service-first-service-diag-v31', 'service-first-service-diag-v32'), ('regional-bft-remote-hint-v21-identity-20261006.json', 'regional-bft-warm-owner-v22-identity-20261006.json'), ('regional-bft-four-cli-remote-hint-v31-decision-allocated-20261006.json', 'regional-bft-four-cli-warm-owner-v32-decision-allocated-20261006.json'), ('regional-bft-remote-hint-entry-start-allocated-v31-20261006.json', 'regional-bft-warm-owner-entry-start-allocated-v32-20261006.json'), ('bind_bft_four_cli_remote_hint_v31_20261006', 'bind_bft_four_cli_warm_owner_v32_20261006'), ('RLD-CONTACT-TRANSIT-SCHEDULER-V21', 'RLD-CONTACT-TRANSIT-SCHEDULER-V22')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V23 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v31-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-warm-owner-v32-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-warm-owner-v32-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v31-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
