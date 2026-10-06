from pathlib import Path
import json
BASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
T=json.loads((BASE/'bounded-readonly-v33-transformation-20261007.json').read_text())
def change(s):
 for a,z in T['literals'].items():s=s.replace(a,z)
 return s
def helper_source():return change((BASE/'observe-bft-four-cli-service-first-service-diag-v32-20261006.py').read_text()).replace(T['old_cold'],T['new_cold'])
def controller_source(decision='regional-bft-four-cli-bounded-readonly-v33-decision-allocated-20261007.json'):
 assert decision=='regional-bft-four-cli-bounded-readonly-v33-decision-allocated-20261007.json'
 return change((BASE/'check-bft-four-cli-service-first-service-diag-v32-allocated-preview-20261006.py').read_text()).replace(T['old_pins'],T['new_pins'])
