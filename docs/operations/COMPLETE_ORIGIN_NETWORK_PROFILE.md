# Complete origin network profile

`RLD-REGIONAL-BFT-COMPLETE-ORIGIN-NETWORK-FIXTURE-V2` is a fresh authority-signed,
no-value receiver contract. Its rules hash binds the normative
`tools/regional-ledger/src/origin_network_profile.md` and the unchanged complete
origin-history V1 contract. No old private state, keys, currency or test value
migrates; current whitepaper requirements remain mandatory.

`RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3` adds complete typed `origins` to ordinary
consensus envelopes. Each receiving Native verifier independently executes every
source certificate from its pinned signed genesis, derives its source dependencies
in this call, then verifies original local evidence and consensus/value bodies.
Existing NETWORK-V2 has no `origins`; V3 and signed receiver V2 require one another.
Complete source histories are not serialized Ledger initializers or latest-state
witnesses. Ordinary envelopes remain within3MiB, whole objects8MiB, source histories
four per envelope and combined active dependencies64. Oversized wire inputs refuse;
opaque multipart carriage is a separate candidate, not an automatic bypass.

`bft-origin-network-observe-conflicts` and `bft-origin-network-sync` require an
independently retained current Native `--expected-head`. Signature-authenticated
incidents persist even if a body's admission fails, including conflicting complete
source histories in one envelope. Bounded route/count/byte admission and independent
conflict authentication precede whole-history shape/value checks: a bad later tail
cannot erase an earlier authentic contradiction. Both certificate sides still
authenticate; forged conflicts do not create incidents. Observation installs no
history or money.
Synchronization re-authenticates the original whole envelope, accepts complete
origin events, and installs local certified heights sequentially. Exact original
certificates already fully executed by current replay need no duplicate append;
every changed later signature or body still authenticates and takes the historical
conflict path. A refused multi-event synchronization can retain authenticated
prefixes or incidents; it is not a single atomic monetary transaction.

Fresh ordinary runtime configuration uses `RLD-REGIONAL-BFT-ORIGIN-NODE-V2` and its
matching separately retained caller-head format. Native current-finality observation
replaces the old bounded proof startup entry only for this explicit configuration.
Runtime reception preserves incidents before full body admission, rechecks each
complete wire at sync, and retains whole origin bytes with existing message/body
identity behavior. Shared byte storage never authenticates a proof. Cold startup
reconstructs the full original envelope and invokes Native verification again.
Existing512-message,64-reference and32MiB combined-state ceilings stay unchanged.

Ordinary source contact export selects the earliest complete finalized local
certificate prefix ending at an existing debited export. Full current Native
replay precedes selection; separately received evidence, contacts and receipts
cannot choose branches or initialize source state. The selected proof must still
execute completely from signed genesis and match the original debit. Missing
foreign dependencies refuse. The existing single-frame payload limit remains3MiB;
no history truncation or multipart substitution is permitted.

`contact-origin-apply` requires the explicit signed receiver profile and an
independently retained current Native `--expected-head`. It authenticates the
complete original canonical frame and admits evidence only; the ordinary BFT
queue supplies Import candidates. Relay acknowledgement is neither Import nor
maturity. Later retries re-authenticate complete bytes without duplicate append.

Import, quorum3-of4, maturity2, fees, permanent consumption, owner/caller custody,
conflict quarantine and source liabilities remain original Native behavior. Evidence
and relay receipts supply no monetary or voting rights. Arbitrary foreign ancestry,
long local histories, source signing custody, target-scale resource/recovery,
post-quantum adoption, independent operators/security, physical routes and mainnet
adoption require separate complete qualification.
