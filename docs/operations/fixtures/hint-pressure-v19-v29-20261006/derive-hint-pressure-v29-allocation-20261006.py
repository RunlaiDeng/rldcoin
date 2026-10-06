from pathlib import Path
import re
r=Path.cwd();b=r/'tmp/default-relay-20260930';old=b/'allocate-import-parent-native-v28-20261006.py';new=b/'allocate-hint-pressure-native-v29-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-import-parent-v18-identity':'regional-bft-hint-pressure-v19-identity',
 'regional-bft-import-parent-v18-v28-source-binding':'regional-bft-hint-pressure-v19-v29-source-binding',
 'regional-bft-four-cli-empty-proposal-v27-decision':'regional-bft-four-cli-import-parent-v28-decision',
 'regional-bft-four-cli-import-parent-v28-decision':'regional-bft-four-cli-hint-pressure-v29-decision',
 'first_service_diagnostic_entry_contract_v16':'first_service_diagnostic_entry_contract_v17',
 'first_service_diagnostic_entry_v16':'first_service_diagnostic_entry_v17',
 'service-first-service-diag-v28':'service-first-service-diag-v29',
 'regional-bft-import-parent-delivery-qualified-v18':'regional-bft-hint-pressure-delivery-qualified-v19',
 'import-parent-v18-v28-20261006':'hint-pressure-v19-v29-20261006',
 'bind-bft-import-parent-v18-native-v28-20261006.py':'bind-bft-hint-pressure-v19-native-v29-20261006.py',
 'check-current-import-parent-ground':'check-carriage-hint-pressure-ground',
 'derive-import-parent-v18-binding':'derive-hint-pressure-v19-binding',
 "'contract_v16'":"'contract_v17'",
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s);s=s.replace('Necessary V18 exact current empty candidate after bounded Import parent is supported by real V17 signed Import-parent Proposal counterexample','Necessary V19 lookup-before-group change is supported by real V18 same-plan native hint eviction counterexample');s=s.replace('V18 exact current-parent configured round-zero leader signed empty candidate after empty or bounded Import parent frames join unchanged Prepare/Commit hints, preserving spare service','V19 reads the already valid exact native frame hint before ordinary group initialization evicts it from the unchanged512/4MiB LRU; original miss/fullretry/nonpriority fallback remains, only the current operation retains primitive IDs');s=s.replace('old_V27_failed1822_still_FAIL=True,','old_V28_failed1883_still_FAIL=True,old_V27_failed1822_still_FAIL=True,');a=s.index('for name in [');z=s.index('out=e/',a);s=s[:a]+"for name in ['regional-bft-four-cli-service-first-service-diag-v28-20261006-checks.json','regional-bft-four-cli-service-first-service-diag-v28-20261006-stage.json']:\n p=e/name;z['protected_sha256'][str(p)]=sha(p)\n"+s[z:];compile(s,str(new),'exec');new.write_text(s)
