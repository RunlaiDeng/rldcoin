# Proof scheduling and immutable host observations

## Decision and scope

The active hypothesis was that full historical witness replay under the shared
node mutex can serialize native settlement with departure proving, and that
choosing the first unresolved controller repeatedly can keep a failed controller
ahead of all later controllers. Source inspection established both paths in the
published parent `815a773`. This stage replaces those paths; compilation and
source review are the chosen checks under the owner's instruction not to add
fixtures or run local test suites. No measured latency result follows.

The bounded decision was to separate witness construction and the three proving
classes while preserving exact authenticated inputs, real receipt verification,
terminal exclusion and refusal limits. A build failure selects source repair;
a source dependency on the global mutex selects moving that computation into an
immutable proof context. An unsafe shortcut in authorization is not an allowed
outcome. Exit evidence is final-source compilation plus review of the lock,
publication, retry and resource paths, not a runtime campaign or mainnet launch.

## Immutable view and native history

`Core::proof_context` shares its authenticated state, proof collection and native
history. It has no custody keys, consensus engines, sender, reservation or signing
methods. Snapshot creation records only immutable material and terminal/candidate
IDs under the mutex. History replay, witness generation and receipt checking run
in blocking tasks outside that mutex. Native state publication, final checkpoint
matching and controller authorization still use the ordinary live executor.
A stale observation may produce a valid historical receipt or an obsolete export
candidate; it cannot bypass a later terminal decision, incident or live check.

The process-local history is a persistent 32-way append tree. Its only accepted
append position is the next exact native sequence. At zero height a leaf holds
at most 32 shared complete records; an internal node contains consecutive child
ranges. A full root grows by one level. An append copies at most one bounded
branch per level and a bounded leaf of shared record references. Immutable
snapshots retain their exact old roots. Height lookup uses successive five-bit
indices. The iterator seeks to the requested leaf, retaining right siblings in
reverse traversal order; remaining leaves keep chronological order. The tree is
not deserialized from untrusted disk and grants no authority from a root hash.
Cold startup still rebuilds it through full native event verification.

This change removes whole-history body copying during node-state staging; it
does not put the whole ledger/history on disk, make arbitrary state mutation
incremental, prune permanent decisions or provide a new monetary commitment.

## Proving lanes and bounded admission

Historical-birth, controller and current-native lanes have separate cursors and
failed-target backoff. Each has at most one active job. A FIFO semaphore bounds
total concurrent construction/proving/publication, configured from one to three.
With three permits, a long job in one class does not occupy another class's
permit. This is a scheduling construction, not proof that any expensive job is
feasible. Under one/two permits some classes must wait for available resources.

A failed target does not remain the mandatory first choice. Each lane rotates
eligible targets and retains finite retry metadata only for currently eligible
targets. Backoff is local scheduling state; no timeout changes a monetary map.
Native witnesses retain at most 4096 transitions as required by the real relation;
a more distant target first proves an exact intermediate retained checkpoint.

The workspace is bound to the exact currency/domain/genesis and locked before
use. Its inventory counts every retained regular file, including partial attempts
and diagnostics. An active attempt reserves maximum receipt bytes, a bounded
128-KiB combined log, an attempt marker and their file entries. Actual partial
files may be counted as well as the reservation, so refusal is conservative.
Capacity exhaustion is a proving-service pause; it does not stop opening the
native ledger solely because the proof directory is full. Unsupported writes
refuse before another output obligation is admitted.

A canonical input is published only after complete bytes and directory sync.
The prover writes a unique attempt output. After process success the host checks
canonical receipt encoding, pinned verifier/image and exact journal in a blocking
task, syncs the result, then publishes its canonical name. Cache reads repeat real
verification. The native executor checks again before accepting the result.
Partial/invalid attempts never occupy the canonical result path. They remain
retained across retry, including the corresponding exact input and marker.

Every prover child enters an isolated Unix process group. Attempt timeout or lane
cancellation requests group termination and direct-child termination. The timeout
path waits for actual direct-child completion before permitting another attempt;
it does not treat an expired observation as completed computation. Process signals
are not independently qualified whole-machine failure/custody evidence. Worker
handles are aborted on every service return path, including listener/TLS errors.

## Retained failures and remaining work

An unplanned incompatible old `state.rs` appeared during this stage's format/check
and caused a macro/type compilation failure. Exact bytes and diff were preserved
locally under `tmp/unexpected-state-source-20261020`; the published implementation
was restored. The writer was not established. Subsequent checks must bind to the
actual final source. This is not a protocol regression pass or permission to drop
its existing genesis, fee-policy or quarantine checks.

The whole State and complete native history/receipt data remain in memory.
Historical replay cost, proof generation cost, receipt-vector append copying,
publication/follow-up mutex work, runtime starvation/cancellation behavior, SDK
scratch/RAM limits and independent custody are not qualified by this stage.
Retained workspace saturation still needs operator-provisioned space; a complete
funded, independently replicated archival service remains unfinished. There are
no generated keys, monetary genesis, test fixtures or running network in this work.
