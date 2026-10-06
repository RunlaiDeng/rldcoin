from pathlib import Path
import re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'allocate-hint-pressure-native-v29-20261006.py';new=b/'allocate-archive-stream-native-v30-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-hint-pressure-v19-identity':'regional-bft-archive-stream-v20-identity',
 'regional-bft-hint-pressure-v19-v29-source-binding':'regional-bft-archive-stream-v20-v30-source-binding',
 'regional-bft-four-cli-import-parent-v28-decision':'regional-bft-four-cli-hint-pressure-v29-decision',
 'regional-bft-four-cli-hint-pressure-v29-decision':'regional-bft-four-cli-archive-stream-v30-decision',
 'first_service_diagnostic_entry_contract_v17':'first_service_diagnostic_entry_contract_v18',
 'first_service_diagnostic_entry_v17':'first_service_diagnostic_entry_v18',
 'service-first-service-diag-v28':'service-first-service-diag-v29',
 'service-first-service-diag-v29':'service-first-service-diag-v30',
 'regional-bft-hint-pressure-delivery-qualified-v19':'regional-bft-archive-stream-delivery-qualified-v20',
 'hint-pressure-v19-v29-20261006':'archive-stream-v20-v30-20261006',
 'contract_v17':'contract_v18',
 'bind-bft-hint-pressure-v19-native-v29-20261006.py':'bind-bft-archive-stream-v20-native-v30-v2-20261006.py',
 'derive-hint-pressure-v19-binding-20261006.py':'derive-archive-stream-v20-binding-20261006.py',
 'check-carriage-hint-pressure-ground-20261006.py':'check-archive-stream-delivery-ground-v20-20261006.py',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda z:m[z[0]],s)
s=s.replace("old_V28_failed1883_still_FAIL=True,","old_V29_failed1818_still_FAIL=True,old_V28_failed1883_still_FAIL=True,")
a=s.index("authorization_scope='");z=s.index("\nz['protected_sha256']",a)
s=s[:a]+"""authorization_scope='Existing user authorization, sole author/same development line. Necessary V20 archive exact-byte streaming repair is supported by original V29 stopped actual Native maturity followed by archive-cold deadline, one bounded read-only profile, real signed fresh archive repeated-encoding counter,6 complete archive and6 default frame-digest checks, and current-source ordinary cold delivery. Original180/one attempt and all original predicates; no new600 or external scope.',live_hypothesis='V20 removes repeated full-frame JSON serialization in each complete archive cold read using byte-identical existing segmented encoding, while actual file bytes/digests, canonical shape, full packet/route/hop/receipt and every Native envelope check remain. This may reduce the identified cold-stage cost after original15 mature; it is not a unique-cause claim. Four ordinary CLI services must complete mature15/all8 complete Nativecold/caller/owner/conservation/normalstop under unchanged180.',live_exit='First source/identity/role/bounds/negative/owned guard failure, complete original15mature/all8 Nativecold/caller/owner/conservation/normalstop, or original180 deadline. Seal any failure; no same-source rerun/extension/oldfailed reopen/new600.')"""+s[z:]
s=s.replace("for p,h in x['protected_private_inventory_sha256'].items():z['protected_sha256'][p]=h","for p,h in x['protected_private_inventory_sha256'].items():z['protected_sha256'][p]=h\nfor p,h in x['protected_typed_inventory_sha256'].items():z['protected_sha256'][p]=h\nfor name in ['regional-bft-archive-cold-boundary-v29-20261006-checks.json','regional-bft-archive-stream-frame-digest-v20-20261006-checks.json','regional-bft-archive-stream-source-precheck-v1-20261006.json','regional-bft-current-commit-archive-stream-related-v20-v3-20261006-checks.json']:\n p=e/name;z['protected_sha256'][str(p)]=sha(p)")
s=s.replace("b/'check-current-commit-relay-order-v14-20261006.py'","b/'observe-v29-archive-cold-boundary-20261006.py',b/'apply-archive-stream-v20-20261006.py',b/'prepare-archive-stream-counter-v19-20261006.py',b/'seal-archive-stream-related-v3-20261006.py',b/'check-archive-stream-frame-digest-v20-20261006.py',b/'derive-archive-stream-v30-allocation-20261006.py'")
compile(s,str(new),'exec');new.write_text(s)
