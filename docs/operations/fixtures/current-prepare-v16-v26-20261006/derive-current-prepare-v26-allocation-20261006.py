from pathlib import Path
import re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'allocate-prepared-commit-native-v25-20261006.py';new=b/'allocate-current-prepare-native-v26-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-prepared-commit-v15-identity':'regional-bft-current-prepare-v16-identity',
 'regional-bft-prepared-commit-v15-v25-source-binding':'regional-bft-current-prepare-v16-v26-source-binding',
 'regional-bft-four-cli-current-commit-v24-decision':'regional-bft-four-cli-prepared-commit-v25-decision',
 'regional-bft-four-cli-prepared-commit-v25-decision':'regional-bft-four-cli-current-prepare-v26-decision',
 'first_service_diagnostic_entry_contract_v13':'first_service_diagnostic_entry_contract_v14',
 'first_service_diagnostic_entry_v13':'first_service_diagnostic_entry_v14',
 'service-first-service-diag-v25':'service-first-service-diag-v26',
 'regional-bft-prepared-commit-delivery-qualified-v15':'regional-bft-current-prepare-delivery-qualified-v16',
 'prepared-commit-v15-v25-20261006':'current-prepare-v16-v26-20261006',
 'bind-bft-prepared-commit-v15-native-v25-20261006.py':'bind-bft-current-prepare-v16-native-v26-v2-20261006.py',
 'check-prepared-commit-ground':'check-current-prepare-ground',
 "'contract_v12'":"'contract_v14'",
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda x:m[x[0]],s)
s=s.replace('Necessary V15 single-generator source change is supported by real V14 prepared/unreceipted signed counterexample','Necessary V16 current exact signed Prepare classifier change is supported by real V15 prepared/unreceipted Prepare counterexample')
s=s.replace('V15 exact current-parent configured-key signed Commit full-frame hints retain prepared/unreceipted Commit spare service','V16 exact current-parent configured-key signed Prepare/Commit full-frame hints retain prepared/unreceipted current votes spare service')
s=s.replace('old_V24_failed1715_still_FAIL=True,','old_V25_failed1829_still_FAIL=True,old_V24_failed1715_still_FAIL=True,')
a=s.index('for name in [');z=s.index('out=e/',a);s=s[:a]+"for name in ['regional-bft-four-cli-service-first-service-diag-v25-20261006-checks.json','regional-bft-four-cli-service-first-service-diag-v25-20261006-stage.json','regional-bft-parent13-v25-matrix-20261006-checks.json','regional-bft-prepare-edge-v25-entry-failure-20261006.json','regional-bft-prepare-edge-v25-v2-20261006-checks.json','regional-bft-prepare-relay-v25-entry-failure-20261006.json','regional-bft-prepare-relay-v25-v2-20261006-checks.json','regional-bft-current-prepare-v16-v26-source-binding-entry-failure-20261006.json']:\n p=e/name;z['protected_sha256'][str(p)]=sha(p)\n"+s[z:]
s=s.replace("b/'check-prepared-commit-binding-once-20261006.py',", "b/'derive-current-prepare-v16-binding-20261006.py',")
compile(s,str(new),'exec');new.write_text(s)
