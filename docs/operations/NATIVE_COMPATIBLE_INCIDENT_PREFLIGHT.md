# Negative-only compatible incident preflight candidate

`Conflict::verify` now applies its unchanged bounded region/canonical-order and
structural incompatibility predicates before authenticating both complete
histories. A pair with no conflicting epoch selection, retired-era successor
or mismatched overlapping block header returns an error: it cannot be incident
evidence. This early rejection grants no signature, ledger, custody, freshness
or signing rights. Every potentially incompatible pair still verifies both
complete native histories before returning success.

Ordinary incoming evidence keeps its separate complete authentication before
storage or body deduplication. `stage_evidence` verifies each incoming certified
history, checks actual owner/value evidence and retains authenticated incidents;
unchanged Native commit/replay and durable publication remain mandatory. No
evidence is pruned, no input history/cache initializes a ledger, and no bound,
quorum, epoch/caller-head or timer rule changes. Malformed compatible evidence
must still refuse through ordinary evidence admission without changing ledger
or journal. A structurally conflicting forgery must still fail authentication.

Changed Native implementation requires fresh frozen source, signed no-value
genesis/currency, complete Native/process regressions and a fresh ordinary
payment/cold run. Preserve all failed source/report/private custody. No old
balances or journals migrate. Full fault, physical links, independent custody,
long-history and the final interstellar payment goal remain unqualified.
