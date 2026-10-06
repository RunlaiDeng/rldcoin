from pathlib import Path
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
HELPER_CHANGES=[('bft_unserved_delivery_precondition_v2_20261006', 'bft_older_spare_delivery_precondition_v3_20261006'), ('bft_four_cli_first_service_diagnostic_v6_20261006', 'bft_four_cli_first_service_diagnostic_v7_20261006'), ('regional-bft-unserved-promotion-final-identity-20261006.json', 'regional-bft-older-spare-v13-identity-20261006.json'), ('native-bft-four-cli-service-first-service-diag-v21-private-20261006', 'native-bft-four-cli-service-first-service-diag-v22-private-20261006')]
CONTROLLER_CHANGES=[('bft_unserved_delivery_precondition_v2_20261006', 'bft_older_spare_delivery_precondition_v3_20261006'), ('service-first-service-diag-v21', 'service-first-service-diag-v22'), ('regional-bft-unserved-promotion-final-identity-20261006.json', 'regional-bft-older-spare-v13-identity-20261006.json'), ('regional-bft-four-cli-unserved-promotion-v21-decision-allocated-20261006.json', 'regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json'), ('regional-bft-unserved-promotion-entry-start-allocated-v21-20261006.json', 'regional-bft-older-spare-entry-start-allocated-v22-20261006.json'), ('bind_bft_four_cli_unserved_promotion_v21_20261006', 'bind_bft_four_cli_older_spare_v22_20261006'), ("promotion_binding['result']['python_source_commitment']==x['python_source_commitment']", "promotion_binding['result']['python_source_commitment']==json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text())['python_source_commitment']"), ('RLD-CONTACT-TRANSIT-SCHEDULER-V12', 'RLD-CONTACT-TRANSIT-SCHEDULER-V13')]
def transform(text,pairs):
 for a,z in pairs:
  if a not in text:raise ValueError('missing original V21 source binding')
  text=text.replace(a,z)
 return text
def helper_source():return transform((BASE/'observe-bft-four-cli-service-first-service-diag-v21-20261006.py').read_text(),HELPER_CHANGES)
def controller_source(decision='regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json'):
 if decision!='regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')
 return transform((BASE/'check-bft-four-cli-service-first-service-diag-v21-allocated-preview-20261006.py').read_text(),CONTROLLER_CHANGES)
