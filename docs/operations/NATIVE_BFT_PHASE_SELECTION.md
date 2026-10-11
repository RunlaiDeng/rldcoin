# Native BFT phase selection

Ordinary and complete-origin companions delegate current Prepare/Commit,
future Prepare and complete-certificate selection to Rust. Python dispatches
the selected requests, retains the original phase clocks and manages lifecycle
and transport. Joint-epoch and role-slot workflows remain explicit separate
paths. The Origin companion's immediate own Prepare shortcut after its local
proposal remains in the companion; its actual signing still uses Native.
Native refusal never invokes a Python policy fallback for migrated
profiles; the independent Python policy is test-only.

## Input and observation

`bft-phase-action` takes `--signer-dir`, `--expected-head`, `--state-dir`,
`--expected-state-sha256`, `--expected-key`, `--runtime-format`, `--round`,
`--mode` and `--file`. The private canonical JSON input contains `context` and
an ordered list of every retained body identifier. Native requires an exact
permutation of the locked archive's records, refusing omissions, duplicates or
foreign identifiers. This preserves observed message order within a round;
the list supplies no signature or ledger authority. Unknown/duplicate fields,
wrong types and noncanonical identifiers refuse. Input and output remain
bounded by the ordinary 8 MiB limit.

Native inspection fully replays current ledger and signer custody, refuses
interrupted publication, and compares the complete current context, caller head,
identity and round. The archive must match its independently supplied complete
byte digest under the archive lock. Every relevant current-parent Proposal,
Vote and Timeout envelope authenticates separately with complete carried
evidence before selection. Existing retention and directory bounds remain;
other retained records still require full ordinary cold authentication.

## Modes and priority

`start` gives a complete matching Prepare/Commit certificate priority across
all retained rounds, then selects an eligible current Prepare or Commit.
`commit` requests only a current Commit backed by the signer's own Prepare
and a complete three-voter Prepare quorum. `finalize` requests only a complete
certificate, including delayed rounds after local timeout and while keyless.
`committed` restricts that certificate search to the signer's current committed
value. `future` preserves complete-certificate and current-phase priority before
trying later proposals in descending round order, retaining input order within
one round.

Native constructs three distinct ordered Prepare and Commit quorums and
verifies their context, round and value against the complete proposal. An exact
duplicate cannot increase the vote count. Conflicting retained votes from one
identity in the same round and phase refuse instead of replacing a vote by
iteration order. Prepare/Commit scheduling trials run the shared native state
transition on a private clone, with actual parent, incidents, execution, durable
locks and fences retained. No trial is published or signed. A proposal violating
the prepared lock is ineligible; other native failures propagate.

The typed observation binds request bytes, input order, context, mode, key,
caller head and archive digest. It returns `Idle` or one bounded Prepare,
Commit or Finalize action. Following Prepare, same-unit Commit uses another
fresh native observation when the existing profile permits it. Actual signing
and certificate installation independently reopen and verify their current
native/caller custody; a returned request never first-signs or installs value.

## Remaining boundaries

No mode supplies a clock, shortens an interval, rebases expiry or relaxes quorum,
maturity or capacity. Disk and wire formats remain unchanged. Observation flags
declare no ledger change, signing authority or independent freshness. This
interface does not complete the native node lifecycle or communication runtime,
sustained faults, epoch adoption, independent custody, physical routes or mainnet
acceptance. Changed native source requires fresh signed no-value fixtures;
compatible encoding never authorizes migration of old value or failed stores.
