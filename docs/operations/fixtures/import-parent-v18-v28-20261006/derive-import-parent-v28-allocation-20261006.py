from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'allocate-empty-proposal-native-v27-20261006.py';new=b/'allocate-import-parent-native-v28-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-empty-proposal-v17-identity':'regional-bft-import-parent-v18-identity',
 'regional-bft-empty-proposal-v17-v27-source-binding':'regional-bft-import-parent-v18-v28-source-binding',
 'regional-bft-four-cli-current-prepare-v26-decision':'regional-bft-four-cli-empty-proposal-v27-decision',
 'regional-bft-four-cli-empty-proposal-v27-decision':'regional-bft-four-cli-import-parent-v28-decision',
 'first_service_diagnostic_entry_contract_v15':'first_service_diagnostic_entry_contract_v16',
 'first_service_diagnostic_entry_v15':'first_service_diagnostic_entry_v16',
 'service-first-service-diag-v27':'service-first-service-diag-v28',
 'regional-bft-empty-proposal-delivery-qualified-v17':'regional-bft-import-parent-delivery-qualified-v18',
 'empty-proposal-v17-v27-20261006':'import-parent-v18-v28-20261006',
 'bind-bft-empty-proposal-v17-native-v27-20261006.py':'bind-bft-import-parent-v18-native-v28-20261006.py',
 'check-current-empty-proposal-ground':'check-current-import-parent-ground',
 'derive-empty-proposal-v17-binding':'derive-import-parent-v18-binding',
 "'contract_v15'":"'contract_v16'",
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s);s=s.replace('Necessary V17 exact current round-zero empty two-block Proposal classifier is supported by real V16 signed Proposal counterexample','Necessary V18 exact current empty candidate after bounded Import parent is supported by real V17 signed Import-parent Proposal counterexample');s=s.replace('V17 exact current-parent configured round-zero leader signed empty two-block Proposal frames','V18 exact current-parent configured round-zero leader signed empty candidate after empty or bounded Import parent frames');s=s.replace('old_V26_failed1858_still_FAIL=True,','old_V27_failed1822_still_FAIL=True,old_V26_failed1858_still_FAIL=True,');a=s.index('for name in [');z=s.index('out=e/',a);s=s[:a]+"for name in ['regional-bft-four-cli-service-first-service-diag-v27-20261006-checks.json','regional-bft-four-cli-service-first-service-diag-v27-20261006-stage.json','regional-bft-parent13-v27-matrix-20261006-checks.json','regional-bft-import-parent-proposal-edge-v27-20261006-checks.json']:\n p=e/name;z['protected_sha256'][str(p)]=sha(p)\n"+s[z:];compile(s,str(new),'exec');new.write_text(s)
