# Native BFT proposal opportunity

The ordinary and complete-origin companions delegate proposal-round, leadership
and timeout-certificate selection to Rust. The companion still drives phase
priority, original monotonic waits, Prepare/Commit requests, certificate
installation, lifecycle and transport. Joint-epoch and role-slot workflows keep
their separate explicit paths. A Native refusal never selects a Python fallback
for the migrated profiles. The independent Python policy is test-only.

## Locked input and bounded observation

`bft-proposal-opportunity` takes `--signer-dir`, `--expected-head`, `--state-dir`,
`--expected-state-sha256`, `--expected-key`, `--runtime-format`, `--round` and
`--file`. The private input file contains the complete observed BFT context.
Duplicate fields, unknown fields, noncanonical identifiers and wrong types
refuse. Input and output retain the ordinary 8 MiB bound.

Native opens the ledger for inspection and fully replays the original signer
journal under its lock. The supplied context must equal the current native
currency, region, epoch, finality parent, block, height and state root. The
separately retained caller head, signer identity and current round must match.
Interrupted native publication refuses without recovery or incident
reconciliation. Current signed admission determines the four active identities.

The archive lock covers its exact private retained bytes and supplied whole
SHA256. The existing retention codec and all directory/object/message/reference
bounds remain unchanged. Native reconstructs and fully authenticates each
current-parent Proposal and Timeout envelope before using it, including complete
carried evidence and each later duplicate envelope. Other retained messages
still require the ordinary full cold authentication; this observation does not
replace that check. No archive digest, metadata or decoded ledger grants rights.

## Selection policy

Retained current proposals suppress another proposal for that round. Retained
future proposals take priority over creating a different future proposal. When
none is present, Native chooses the highest later local-leader round with at
least three distinct retained timeout voters for its preceding round, within
the existing 32-round bound. Current durable proposal state still prevents
repeating the same local proposal.

Certificates include all three or four ordered distinct timeout voters. Every
high Prepare QC authenticates, and Native selects the highest compatible QC.
The fourth voter's lock is retained. An exact duplicate never increases the
voter count; conflicting retained timeout messages from one identity refuse
rather than silently discarding a lock according to iteration order.

The typed observation binds the complete context, original round, caller head,
archive bytes and key. It returns proposal presence, selected round, leader,
complete timeout certificate, selected high value and proposal eligibility.
It supplies no clock and does not reset, shorten or rebase the original phase
interval or timeout. The companion reobserves after a serviced wait. Every
subsequent signature still requires independent current native/caller custody
checks and complete proposal execution; a scheduling response cannot first-sign.

## Qualification boundary

The interface changes neither retained disk encoding nor wire encoding. Its
`ledger_changed`, `signing_authority` and `independent_freshness_qualified` flags
are false. It does not complete the native node runtime, communication migration,
sustained BFT liveness, reconfiguration, independent custody, physical routes or
mainnet acceptance. Changed native source requires fresh signed no-value fixtures;
encoding compatibility never authorizes old-value or failed-store migration.
