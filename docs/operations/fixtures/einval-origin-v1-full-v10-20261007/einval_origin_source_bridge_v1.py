from pathlib import Path
import hashlib,json

def verify(project, current):
 r=Path(project);assert r==Path('/Users/galaxy/GitHub/rldcoin') and Path.cwd()==r
 b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 bridge=json.loads((e/'regional-einval-origin-v1-source-bridge-20261007.json').read_text());old=json.loads((e/'regional-bft-current-origin-v32-identity-20261007.json').read_text());middle=json.loads((e/'regional-contact-apply-defer-v1-identity-20261007.json').read_text());rev=json.loads((b/'einval-origin-observer-v1-source-reversal-20261007.json').read_text());prior=json.loads((b/'contact-apply-defer-v1-source-reversal-20261007.json').read_text())
 assert bridge['completed'] and bridge['old_source192_commitment']==old['python_source_commitment'] and bridge['new_source192_commitment']==current['python_source_commitment'];assert sha(e/'regional-einval-origin-v1-identity-20261007.json')==bridge['new_identity_sha256'];assert bridge['observer_source_reversal_sha256']==sha(b/'einval-origin-observer-v1-source-reversal-20261007.json')
 assert bridge['intermediate_apply_identity_sha256']==sha(e/'regional-contact-apply-defer-v1-identity-20261007.json');assert bridge['original_component_checks_sha256']==sha(e/'regional-bft-four-cli-service-first-service-diag-v47-20261006-checks.json');assert bridge['fresh_actual_lock_probe_checks_sha256']==sha(e/'regional-contact-apply-native-lock-v1-20261007-checks.json');assert bridge['observer_model_checks_sha256']==sha(e/'regional-einval-origin-final-history-model-v1-20261007.json')
 model=json.loads((e/'regional-einval-origin-final-history-model-v1-20261007.json').read_text());probe=json.loads((e/'regional-contact-apply-native-lock-v1-20261007-checks.json').read_text());assert model['completed'] and model['exit_code']==0 and all(sha(r/p)==h for p,h in model['source_sha256'].items());assert probe['completed'] and probe['exit_code']==0 and probe['duration_seconds']<=60 and probe['result']['fixed_head_native_cold']==8 and probe['result']['held_lock_mutations']==0 and probe['result']['actual_native_apply_calls']==2
 assert set(p for p in middle['python_source_sha256'] if middle['python_source_sha256'][p]!=current['python_source_sha256'][p])==set(rev['edits'])
 for path,rows in rev['edits'].items():
  text=(r/path).read_text()
  for row in reversed(rows):text=text.replace(row['after'],row['before'])
  assert hashlib.sha256(text.encode()).hexdigest()==middle['python_source_sha256'][path]
  if path=='tools/regional_contact_node.py':assert text.replace(prior['after'],prior['before'])==(b/'regional_contact_node-before-apply-defer-v1-20261007.py').read_text()
  if path=='tools/test_regional_bft_receive_deferred.py':assert text.replace('\n'+prior['new_test_class'],'')==(b/'test_regional_bft_receive_deferred-before-apply-defer-v1-20261007.py').read_text()
 assert old['native_source_sha256']==middle['native_source_sha256']==current['native_source_sha256'];assert old['core_source_commitment']==current['core_source_commitment'] and old['actual_cli_sha256']==current['actual_cli_sha256'];assert all(sha(r/p)==h for p,h in current['python_source_sha256'].items())
 return old
