# Role-scoped BFT handoff implementation contract

Ground implementation contract, 2026-10-02. **Native candidate only; ordinary
startup is implemented locally; full lifecycle/fault qualification remains pending.** Revision 33
continues to require four disjoint, historically unused successor keys. This
contract governs a separate changed native candidate. It addresses I7; it does not finish
arbitrary membership, independent custody, I10/I11 or the project goal.

The local native candidate now provides explicit role admission, role-separated
approvals, purpose-bound readiness journals and new voter creation from complete
validated old/readiness custody. `joint-ready-init/status/sign` and
`joint-voter-init` are explicit local CLI operations. Readiness recovery cannot
first-sign. Continuing voters require their actual old journal under its OS lock
and exact caller head; new immutable provenance embeds complete native journals
and the verified transition, never keys. An original voter cannot sign in another
era. Genesis-only empty creation, capacity and historical-key refusal remain.
Every changed-source test uses fresh signed no-value fixtures. Legacy private
stores cannot migrate into this implementation.

The local Python ordinary node now additionally accepts explicit
`RLD-REGIONAL-BFT-NODE-JOINT-ROLES-V1` configuration: a nullable initial local
slot and a bounded configured sequence of increasing selection heights, complete
ordered carrier mappings and nullable per-era local slots. Joining-only and
departing-only carriers need no invented signing identity. Continuing keys keep
their carrier and original custody. Every voting/readiness caller directory is
separate from all native/runtime directories and every other caller directory.

Native previews bind an exact empty journal, complete readiness purpose and
creation observation. The companion durably records that marker before native
creation and advances its independent head before signing or releasing a
response. Native recover-init only fsyncs/promotes an already retained exact
unsigned readiness/empty voter; it cannot create a missing journal or reset a
used voter. Missing/both payload files, altered markers and incomplete targets
refuse unchanged. Old caller heads, votes and fences remain retained per era.
The ordinary V1 profile/configuration retains its disjoint behavior unchanged.

Local actual-native caller tests cover joining-only operation, marker write
failure, lost signed readiness response, altered pending purpose and lost empty
voter creation response with the key removed. These simulated response/file
boundaries do not count as real process SIGKILL/power loss. Frozen ordinary
startup, second-transition, full fault, stopped cold acceptance and remaining
R10 counterexamples are still separate required evidence.

## Current boundary and executable evidence

`EpochStatement.bytes`, the old BFT `EpochApproval` message and the candidate
signer's `Handoff` request use the same V1 statement signing bytes. The carried
approval's Old/New role is checked against distinct membership sets. Relabelling
an old approval as New is rejected because its key is absent from the new set.
Simply removing the disjointness checks would remove that protection.

`JointRecoveryTests.test_v1_role_relabelling_and_overlapping_membership_refuse_without_custody_changes`
uses a fresh V33 native fixture, real persisted old and candidate signatures,
and native network packing. It checks the exact shared signing bytes, valid
role packing, both role substitutions, a partial-overlap statement and an
unknown approval format. Refusals must leave every private fixture file's bytes,
owner, permissions and link count unchanged. Python's byte-conformance check
does not grant native authority or implement an overlap profile.

## R1 — Explicit signed admission and signature roles

Introduce a separately signed admission
`RLD-REGIONAL-BFT-JOINT-ROLES-FIXTURE-V1`, activation marker
`RLD-BFT-JOINT-ROLES-V1` and carried approval format
`RLD-JOINT-EPOCH-APPROVAL-V2`. Existing admissions retain their exact old rules.
V1 cannot silently adopt new signatures, membership or private storage.

The new native activation identity uses the separate
`joint-role-epoch-handoff-v1` domain. Approval signing bytes are exactly native
`encode("joint-epoch-role-approval-v1", &(role, statement))`, where serde encodes
role as `Old` or `New` and the complete typed statement includes the activation
marker, currency, region, number, previous epoch, closing checkpoint/height and
ordered successor keys. There is no unspecified or inferred role. Old fences
sign Old; candidate readiness signs New. Neither signature verifies as the other
role, including when the key belongs to both sets. Native journals must retain
the corresponding request purpose. An outer transport signature cannot repair
an invalid inner approval.

## R2 — Selection, membership and quorum

The actual old four-member set certifies one exact plan in an ordinary block,
under three distinct ordered prepare and commit votes. Each activation requires
three distinct ordered Old approvals from that current set and three distinct
ordered New approvals from the exact selected successor set. A shared signer
needs two different role signatures; one approval cannot satisfy both roles.

Keep four equal members and the existing 16-epoch native bound. Permit zero through
three continuing keys; unordered, duplicate, unchanged sets and keys previously
removed/fenced from an older set refuse. This is partial overlap support, not
arbitrary population, weights, historical-key rejoining or cryptographic
algorithm replacement. Missing approvals leave the selected transition pending.
They do not permit old successors, alternate selection or timeout cancellation.

## R3 — Candidate readiness is separate custody

Each New readiness journal must bind its exact currency, region, key, purpose,
previous epoch and selected next statement ID. It must fully validate the
selected closing history, old certificate, prior epochs and current incidents.
A continuing old key cannot repurpose its old voting journal as this journal.
Separate caller heads and pending/outbox persistence remain mandatory. Recovery
returns only an exact previously retained New response; it cannot first-sign.

## R4 — Preserve old locks

Retain every old vote, prepare-QC lock, view change and exact Old fence in the
original native journal, with its separately retained latest caller head. Never
clear, replace or truncate that journal to make a continuing key eligible in a
new era. An old fenced journal never signs new-era votes. Removing membership
cannot remove historical evidence, source debits, pending exports or imports.

## R5 — Continuing-key creation requires native rollover provenance

At the exact locally installed activation boundary, creation of a separate new
voting journal requires full native validation of the original old journal under
its OS lock and exact external head, its retained Old fence for this statement,
and the separate native New readiness journal under its exact external head.
The installed statement, complete selected closing history and both role
responses must agree. Digest or statement-ID agreement alone cannot transfer
custody or reset a lock.

The new journal's immutable creation record binds the actual new-era observation
and its exact rollover provenance. Native cold replay validates that provenance;
it cannot reinterpret an old directory as a new one. The companion records a
pending initialization observation before native creation and advances its
separate new head before releasing a response. Interrupted creation may recover
only that exact empty journal. Do not overwrite caller state, merge directories
or adopt a different head. Retain every old journal and head.

## R6 — Joining, continuing and departing carriers

Joining-only carriers have no old voting slot. Native membership history must
prove that the key is fresh, and their retained New readiness is still required
at the exact activation boundary. Continuing carriers satisfy R5. Departing
carriers retain old custody and may relay/catch up without a new voting slot.
Configured key/node mappings are explicit; advertisements supply no keys,
endpoints, pins or successor configuration.

Missing local participation, a missing caller head, a stale backup or arrival
after the boundary leaves the carrier read-only. Complete certified ledger
catch-up is separate from authority to create a signer. Keyless carriers never
create a voting directory. The configuration must support a new carrier joining
while the departing carrier still relays, rather than assume one old/new slot
pair on every carrier.

## R7 — Repeated transitions and exact replay

Allow a bounded configured sequence of increasing selection heights and exact
successor sets. Every transition chains from the native-replayed current era;
its old set is the preceding activated set, never genesis or a Python cache.
Keep separate approval/voting directories and external heads per transition.
Check actual activation rather than membership in known evidence. Preserve
duplicate valid closing witnesses and different valid complete quorum variants.
An invalid later tail publishes neither an epoch event, a chain anchor nor value.

## R8 — Carriage and refusal ordering

Every complete envelope, carried role, prior transition, closing certificate and
dependency authenticates before deduplication, synchronization or signing.
Mixed domains/formats, wrong roles, skipped prior eras, altered selections and
wrong local/native caller heads refuse without custody or ledger changes.
Continue to distinguish transport receipt, evidence retention, native inclusion
and spendability. A local expiry never releases included exports.

## R9 — Capacity and source boundaries

Do not increase native logical 8-MiB, 256-block, 64-snapshot, 16-epoch or signer
record limits; retain the existing 3-MiB network, companion and transport archive
limits. Retain incomplete publications and signed evidence. This changed native
source requires a fresh signed no-value fixture genesis/currency. Never migrate
V33/older balances, private journals, caller heads or adopted authorization.

## R10 — Required positive and counterexample checks

Actual native checks must cover 0/1/2/3 overlap, two consecutive transitions,
owner payment before/after each activation, export/dependency replay and cold
reopening from genesis. Reject copied Old signatures in New collections and
vice versa; duplicates and under-quorum sets; changed role/domain/selection;
historically removed keys; skipped/reordered epochs; tampered rollover records;
stale/missing heads; late empty journals; and invalid certified tails. Test each
creation/response/persistence failure boundary with exact retained recovery and
unchanged old custody. Testing signatures in a model is not native admission.

## R11 — Ordinary lifecycle and fault profile

Use normal nodes with joining/continuing/departing carriers and pinned contacts.
Complete a second transition through ordinary consensus and role carriage,
without controller-generated votes, approvals, activation or payment proofs.
Exercise a missing current leader, old/new missing approval, partition, restart,
changed envelope proof, recipient maturity and signing pause. Freeze exact source,
use fresh private roots, preserve failures and separately cold-authenticate the
complete outcome. A resumed stage cannot replace a failed full profile.

## R12 — Qualification remains separate

Independent operations/anti-rollback custody, simultaneous copied-key use,
power loss, arbitrary membership, sustained Byzantine load, long history,
algorithm migration, archival renewal and physical interstellar links remain
open. Ed25519 role separation does not provide forward-secure signatures or
protect a historical quorum after later key compromise.

The primary [Diem epoch-change verifier](https://diem.github.io/diem/src/diem_types/epoch_change.rs.html)
illustrates verification chained from an already trusted epoch. The research
[Asynchronous Reconfiguration with Byzantine Failures](https://arxiv.org/abs/2005.13499)
addresses superseded configurations using forward-secure signatures. Neither
source proves this proposed RLDCOIN rule or transfers independent qualification.
