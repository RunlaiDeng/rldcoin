# Native first-carriage candidate planning

The ordinary Node uses `RLD-NATIVE-FIRST-CARRIAGE-V1` for first-carriage ID
planning. `interstellar_carriage_reference.py` retains the complete original
Python method for explicit independent comparison. Native refusal has no Python
planner fallback. This is a migration component; the scoped eligibility bridge,
ordinary service and remaining wallet runtime still need migration.

## Original behavior

Prepared IDs retain their original order and survive while active, including
receipted entries. Pending candidates keep their order after the original
eligibility checks. On first preparation, recent traffic gets at most the
original 32 admission places. Subsequent preparations retain waiting arrivals
and append unseen actual first arrivals in their original order.

The background stream contains sorted active IDs outside known, reserved and
receipted sets. It rotates strictly after the original history cursor and wraps.
Arrival/background selection alternates from the retained next-kind bit. An
exhausted stream can fall back to the other stream; only an actual background
selection advances the history cursor. A full pending queue displaces no waiting
ID. Missing/ineligible/receipted entries, rechecks and original short-circuit
order remain explicit; neither a recent-label eviction nor a plan deletes proof.

The result contains the original pending, prepared, arrivals, observed,
history_after and next_kind fields. Observed IDs are the sorted current active
set. Construction writes no pending state, journal, caller head or receipt.
Ordinary complete preparation still publishes metadata atomically only after
all existing packet, byte, signature and custody checks. A full retry preserves
ordinary admission metadata; publication failure retains the original state.

## Bounded private interface

`RLD-FIRST-CARRIAGE-BYTES-V1` plus a NUL byte prefixes the private input. A
big-endian two-byte active limit and one-byte recent limit precede raw 32-byte
network, node and peer identities. Ordered active, receipted, recent,
first-arrival, pending, prepared and waiting-arrival lists each use a big-endian
two-byte count and complete raw identities. A literal zero/one flag precedes
optional observed-list data. A second zero/one flag precedes the optional
history identity, followed by the literal zero/one next-kind bit.

Limits can only tighten the original 256 active/metadata and 32 recent/pending
ceilings. Every list is bounded and unique; waiting/prepared overlaps refuse.
Checked offsets, every complete field and exact EOF precede eligibility calls.
The private input refuses above 64 KiB; null or oversized C inputs are never
read. No network, ledger, archive, history or durable storage bound changes.

The synchronous callback receives only one scoped 32-byte ID. It stays live
for this invocation, cannot be retained by Rust, and returns exactly zero/one
or refusal. Rust preserves the original lazy check order, including repeat
checks. Its ceiling of 1056 covers 32 pending checks and at most 256 each for
old waiting arrivals, new arrivals, arrival-stream traversal and background
traversal. Inactive/receipted IDs need no callback, as before. Callback failure
returns no partial plan; the bridge restores the original exception type.
No callback or search handle, mutable witness or eligibility result survives
the invocation.

## Authentication and result binding

The ordinary scoped callback performs the existing complete native transit
verification and candidate route search, configured first-hop check and original
total-hop bound. It uses the current crypto provider before and after each call;
changed provider/domain refuses. The Node retains its existing lock and complete
state verification. Callback booleans are caller observations, never a replacement
for authenticated advertisements, complete packets or native ledger execution.
Later selected carriage still independently verifies every complete item.

The common receipt binds every input byte and the current implementation. The
candidate result also binds network/node/peer, exact ordered callback count and
SHA-256 transcript. The transcript begins with the complete codec prefix and
`ELIGIBILITY-V1` plus NUL, then each raw ID and its zero/one result in call order.
The bridge verifies that transcript, every role and original plan shape, retained
prepared/active membership, disjoint waiting sets and checked candidate IDs.
It retains the common bounded unique response decoder and exact buffer release.

Candidate results use the already guarded printable-ASCII/integer canonical
encoding path; other contact operations retain their original encoder. The
entire tree and strict map order must pass before the optimized encoder is used.
The exact original canonical bytes and size bound remain mandatory.

Literal candidate_only is true, ledger_authority and custody_acknowledgment are
false. IDs, callback transcripts and plans create no durable custody, signing,
value, finality, import, maturity or current spendability rights. All actual
native value authorization, publication, receipts and independent freshness
requirements remain separate. Finite same-host checks do not qualify full faults,
load, long history, cryptographic adoption, independent operations, physical
routes or mainnet. Changed native source requires fresh signed no-value fixtures;
failed stores and old candidate value never migrate.
