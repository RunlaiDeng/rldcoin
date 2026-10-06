from pathlib import Path
import re
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';old=b/'allocate-archive-stream-native-v30-20261006.py';new=b/'allocate-remote-hint-native-v31-20261006.py';assert not new.exists();s=old.read_text();m={
 'regional-bft-archive-stream-v20-identity':'regional-bft-remote-hint-v21-identity',
 'regional-bft-archive-stream-v20-v30-source-binding':'regional-bft-remote-hint-v21-v31-source-binding',
 'regional-bft-four-cli-hint-pressure-v29-decision':'regional-bft-four-cli-archive-stream-v30-decision',
 'regional-bft-four-cli-archive-stream-v30-decision':'regional-bft-four-cli-remote-hint-v31-decision',
 'first_service_diagnostic_entry_contract_v18':'first_service_diagnostic_entry_contract_v19',
 'first_service_diagnostic_entry_v18':'first_service_diagnostic_entry_v19',
 'service-first-service-diag-v29':'service-first-service-diag-v30',
 'service-first-service-diag-v30':'service-first-service-diag-v31',
 'regional-bft-archive-stream-delivery-qualified-v20':'regional-bft-remote-hint-delivery-qualified-v21',
 'archive-stream-v20-v30-20261006':'remote-hint-v21-v31-20261006',
 'contract_v18':'contract_v19',
 'bind-bft-archive-stream-v20-native-v30-v2-20261006.py':'bind-bft-remote-hint-v21-native-v31-20261006.py',
 'derive-archive-stream-v20-binding-20261006.py':'derive-remote-hint-v21-binding-20261006.py',
 'check-archive-stream-delivery-ground-v20-20261006.py':'check-remote-hint-quiet-ground-v21-20261006.py',
}
s=re.sub('|'.join(re.escape(k) for k in sorted(m,key=len,reverse=True)),lambda z:m[z[0]],s)
s=s.replace('old_V29_failed1818_still_FAIL=True,','old_V30_failed1713_still_FAIL=True,old_V29_failed1818_still_FAIL=True,')
a=s.index("authorization_scope='");z=s.index("\nz['protected_sha256']",a)
s=s[:a]+"""authorization_scope='Existing user authorization, same sole-author single development line. V21 fixes bounded quiet inventory missing newly Native-checked remote current frames, proven by genuine signed fresh counter FAIL and related3/regression current-source ordinary cold delivery. Actual V30 target packet reached relay1 but was not selected; no unique cause claim. Original180/one attempt/all original predicates, no new600/external scope.',live_hypothesis='V21 binds the existing quiet inventory to all bounded complete retained envelope IDs including remote Native-checked current frames; a new remote frame immediately refreshes current spare hints while unchanged inventory/time/call/capacity behavior and original Native check/sign/locks/quorum/floors/full4 remain. The actual4 ordinary services must reach15mature/all8completeNativecold/all envelopes/caller/owner/conservation/normalstop under original180.',live_exit='First source/identity/role/bounds/negative/owned guard failure, complete original15mature/all8 Nativecold/caller/owner/conservation/normalstop, or original180 deadline. Seal failure; no same-source retry/extension/failedfixture reopen/new600.')"""+s[z:]
s=s.replace("for name in ['regional-bft-archive-cold-boundary-v29-20261006-checks.json'", "for name in ['regional-bft-parent14-v30-matrix-20261006-checks.json','regional-bft-current-hint-byte-budget-v30-20261006-checks.json','regional-bft-exact-commit-edge-v30-v2-20261006-checks.json','regional-bft-exact-relay-commit-v30-20261006-checks.json','regional-bft-archive-cold-boundary-v29-20261006-checks.json'")
s=s.replace("b/'derive-archive-stream-v30-allocation-20261006.py'","b/'derive-remote-hint-v31-allocation-20261006.py',b/'prepare-remote-hint-quiet-counter-v20-20261006.py',b/'apply-remote-hint-quiet-v21-20261006.py',b/'observe-bft-parent14-v30-matrix-20261006.py',b/'observe-v30-current-hint-byte-budget-20261006.py',b/'observe-v30-exact-commit-edge-20261006.py',b/'observe-v30-exact-commit-edge-v2-20261006.py',b/'observe-v30-exact-relay-commit-20261006.py'")
compile(s,str(new),'exec');new.write_text(s)
