from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'allocate-current-prepare-native-v26-20261006.py';new=b/'allocate-empty-proposal-native-v27-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-current-prepare-v16-identity':'regional-bft-empty-proposal-v17-identity',
 'regional-bft-current-prepare-v16-v26-source-binding':'regional-bft-empty-proposal-v17-v27-source-binding',
 'regional-bft-four-cli-prepared-commit-v25-decision':'regional-bft-four-cli-current-prepare-v26-decision',
 'regional-bft-four-cli-current-prepare-v26-decision':'regional-bft-four-cli-empty-proposal-v27-decision',
 'first_service_diagnostic_entry_contract_v14':'first_service_diagnostic_entry_contract_v15',
 'first_service_diagnostic_entry_v14':'first_service_diagnostic_entry_v15',
 'service-first-service-diag-v26':'service-first-service-diag-v27',
 'regional-bft-current-prepare-delivery-qualified-v16':'regional-bft-empty-proposal-delivery-qualified-v17',
 'current-prepare-v16-v26-20261006':'empty-proposal-v17-v27-20261006',
 'bind-bft-current-prepare-v16-native-v26-v2-20261006.py':'bind-bft-empty-proposal-v17-native-v27-20261006.py',
 'check-current-prepare-ground':'check-current-empty-proposal-ground',
 'derive-current-prepare-v16-binding':'derive-empty-proposal-v17-binding',
 "'contract_v14'":"'contract_v15'",
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s);s=s.replace('Necessary V16 current exact signed Prepare classifier change is supported by real V15 prepared/unreceipted Prepare counterexample','Necessary V17 exact current round-zero empty two-block Proposal classifier is supported by real V16 signed Proposal counterexample');s=s.replace('V16 exact current-parent configured-key signed Prepare/Commit full-frame hints retain prepared/unreceipted current votes spare service','V17 exact current-parent configured round-zero leader signed empty two-block Proposal frames join unchanged Prepare/Commit hints, preserving spare service');s=s.replace('old_V25_failed1829_still_FAIL=True,','old_V26_failed1858_still_FAIL=True,old_V25_failed1829_still_FAIL=True,');a=s.index('for name in [');z=s.index('out=e/',a);s=s[:a]+"for name in ['regional-bft-four-cli-service-first-service-diag-v26-20261006-checks.json','regional-bft-four-cli-service-first-service-diag-v26-20261006-stage.json','regional-bft-parent14-v26-matrix-20261006-checks.json','regional-bft-proposal-edge-v26-20261006-checks.json']:\n p=e/name;z['protected_sha256'][str(p)]=sha(p)\n"+s[z:];compile(s,str(new),'exec');new.write_text(s)
