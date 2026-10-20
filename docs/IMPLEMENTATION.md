# Implementation and unresolved obligations

## Monetary rules implemented in the native relation

The currency descriptor fixes 4,096 roots, 1,000,000 slots per root, a reward of
0.005126953125 RLD per consumed slot, 10^24 atomic precision and the 21-million
lifetime cap. Genesis creates issuance authority and no issued balances. The
bootstrap domain identity and validator identity roster are part of the currency
binding; an arbitrary same-named domain cannot recreate its slot budget.

Amounts use checked integer arithmetic and decimal strings in JSON. Canonical
wire objects use definite CBOR arrays and byte strings. Re-encoding rejects
unknown/trailing fields and noncanonical representations. Typed hashes separate
protocol, currency, object purpose, family, configuration and position.

Mint consumes a current active frontier and binds its grant, slot, home, anchor,
cover, payout and work nonce. Placement detaches exactly 1–256 unconsumed slots
under a stable grant after proportional public work. Disjoint residual segments
keep their grant identity. Installation and returns create a new grant for only
the selected slots. Neither placement nor its controller issues RLD.

Payments consume actual local owners' inputs, conserve each cover, create signed
change, and pay positive service, prior-Mint work-author and archival-reserve
allocations from existing RLD. Source fee policies are authenticated and retained
across handoff. Coupons pin their original source policy, destination policy,
minima, return formulas and resource bounds. Payout labels cannot redirect service
fees to an arbitrary owner. An archival contribution locks a funded contract.

Capability families bind one source, one destination, a finite leaf root and
source/destination sponsorship proofs. Native execution authenticates every leaf
and accepted cover definition. Claimants need no prior RLD balance; sponsors
must fund the actual source/controller and receiving resource contracts.

Preparation commits an immutable controller and coupon delegation before its
historical execution receipt is proved. Native settlement can continue. A
controller has exactly one certified terminal statement, Exported or Canceled.
Cancellation verifies its original owner authorization and direct native birth
certificate without waiting for a recursive cancellation receipt. Source return
is once-only. After Exported, source recovery requires permanent certified
rejection by the named destination; elapsed time never authorizes a refund.
An explicit zero-threshold empty use policy permits public preparation without
weakening actual input-owner checks. For issuance only, the same explicit policy
in the cancellation/recovery template binds that role to the actual claimant at
preparation. It is never a zero-threshold monetary owner. Unused closure still
requires a separately bound close owner and any nonpublic use authorization.

Destination import/installation, rejection, coupon use and source redemptions
remain permanent. Unused or canceled source coupon closure can be proved to the
destination to close its corresponding capacity obligation.

Current material binds the complete ticket, coupon, advertised covers and exact
recipient/service allocations. A prospective export must fit a complete capsule
including conservative proof/QC overhead. Receipt verification is separate from
current ordering signatures. Historical source creation remains fixed while the
source advances.

Covers name immutable finite authority families and cryptographic profiles.
Broadening requires exact signed lifts and preserves unlifted change. Incident
quarantine binds both the authority family and its initial anchor. Exported value
never acquires a new accepting authority merely because a relay advertises it.

## Consensus, proofs and custody

Native positions and terminal controllers have separate PBFT engines. The
supported committee sizes are 3f+1, from 1 to 127; the quorum is 2f+1. A single
operator domain explicitly has f=0 and provides no Byzantine redundancy. The
code verifies ordered distinct membership, phase, view, sequence, statement and
key path, including full late finality certificates. New-view selection preserves
the highest prepared statement. Equivalent proof wrappers do not change the
selected monetary statement. Sending one's own view change stops new old-view
prepare/commit signatures. Independent checked exponential timers prevent native
activity from resetting a controller's timeout forever.

The incompatible prelaunch signature profile is now
`RLD-ED25519-HEIGHT-POOL-PBFT-SUMMARY-2`. View-change votes commit the exact
preprepare vote and prepare quorum. New-view certificates carry those signed
ordering summaries without repeating each monetary payload. The new primary
must recover the selected statement's complete retained material and revalidate
it before proposing; otherwise it waits. Every actual proposal and finality
message still carries and verifies its complete material. A summary grants no
execution authority. Quorum thresholds and the 16-MiB transport bound are
unchanged. Old-profile descriptors are refused; there is no monetary migration.

Authenticated conflicting complete certificates are retained and stop local
signing, including across restart. Individual invalid or stale messages cannot
create a conflict incident. Every historical envelope is authenticated before
deduplication. Local event replay reconstructs execution and consensus state;
stored state roots or hashes are not accepted as authorization by themselves.

Every validator has 65,536 native position keys and an independently generated
65,536-key controller pool. The native key schedule evolves one way; old
controllers keep their original pool keys after native handoff. Public inventory
admission is proved by the real native guest, including distinct keys and root
membership. Identity approvals and PBFT responses have durable one-choice locks.
Private publication failure poisons the in-memory signer before any response can
be returned. Explicit custody recovery reconciles an already retained publication
and creates no new signature.

Custody is Argon2id-derived XChaCha20-Poly1305 encrypted local storage. Passwords
enter a terminal or bounded stdin, never command arguments, environment variables
or HTTP. Independent latest heads and OS locks detect covered rollback and
concurrent opens. Source memory is zeroized where possible. This does not prove
secure erasure on APFS/SSD media, prevent cloning all state and heads, or provide
hardware-backed forward security. Copies of old encrypted vaults can invalidate
erasure assumptions. Those properties require independent custody work.

Only pinned real RISC Zero 3.0.6 succinct receipts are accepted. The host checks
receipt type, exact image, control/verifier parameters and exact journal. Receipt
verification requires a successful unconditional claim. The guest verifies
recursive assumptions; the prover must resolve every assumption before the
final receipt is released. Admission and native execution have distinct journal
purposes even though they share the native image. No development mode or fake
receipt is a supported fallback.

Handoff requires the old authority's authorization, a new quorum's acknowledgment
of the exact prestate and next configuration, and a real admission proof. It is
its own committed batch. Handoff preserves the original limits and executable custody/signature/succession
profiles. Old positions cannot silently continue beyond the
boundary. No operator replacement command copies balances into a new root.

## Transport and resource behavior

Configured HTTPS contacts require TLS 1.3, exact certificate pins, ordinary
certificate validation and signed challenges. Endpoints and pins are never
learned from advertisements. Discovery hints are observations, not permissions.
Each complete carried object is at most 16 MiB, receipts at most 1 MiB, fragments
1 MiB and each exchange at most 16 fragments. Reassembly checks whole length,
whole hash and canonical object identity. Custody acknowledgment follows fsync
of complete bytes and the directory. Partial or corrupted bytes cannot receive
a complete custody acknowledgment. Offline bundles support independently pinned,
signed one-way carriage. None of these receipts establishes ledger settlement.

Public expensive requests have bounded concurrent admission. Native pending
operations use a finite queue; proposal construction validates and bounds the
batch. Local ticking, each neighbor contact and proof generation are independent
workers. Historical birth proofs, controller proofs and ordinary native proofs
receive recurring scheduling turns. Proof inputs/outputs retain stable content
IDs across interruption; failed diagnostics are bounded and retained.

Proving now uses immutable observations of authenticated host state, persistent
native history and receipts. Witness replay and receipt verification execute
outside the live node mutex. Three separately scheduled lanes cover historical
controller births, controller departure relations and current native execution.
Each lane rotates eligible targets and backs off failed targets; a configured
semaphore bounds total concurrent tasks. With fewer than three permits, proving
lanes deliberately share those resources. Publication rechecks the receipt and
its exact retained local checkpoint or controller through the normal executor.
This does not eliminate all publication/follow-up work under the mutex.

The proving workspace has an exclusive process lock and exact currency, domain
and genesis binding. Retained inputs, attempt markers, diagnostics and outputs
count toward a configured byte budget and a 16,384-file bound. Concurrent
attempts reserve output/diagnostic space before launch. Canonical inputs are
published from complete synced temporary files; each retry has a new output
path. Only a real exact image/journal receipt becomes a reusable result.
Failures and interrupted attempts remain retained. A configurable compute
timeout stops the prover attempt, never monetary rights. Capacity exhaustion
pauses proving, not independent native settlement or cancellation. No automatic
proof-history deletion, paid archival qualification or remote prover trust is
introduced. See [the implementation analysis](engineering/PROOF_SCHEDULING.md).

## Disk state material and authenticated queries

A background worker now publishes checkpoint state material plus native
ordered-map witness pages for exact retained checkpoints. State chunks are at most
1 MiB, map leaves at most 128 entries, and manifests at most 256 KiB. Each derived
index is bound to its currency/domain/genesis, shares immutable exact objects and
uses a 2-GiB / 65,536-file local admission budget. Those are cache limits, not
currency history limits or paid archive qualification.

Historical proof input construction can reconstruct complete checkpoint state from disk
without replaying the entire prefix again. Controller birth/cancellation,
returned rejection witnesses and the local state-witness command can use direct
Merkle paths from disk. Every read checks native root/path binding against its
caller-retained checkpoint. Missing or damaged query pages fall back to complete
verified State; missing or damaged complete State falls back to native journal
replay. Damaged data is retained and the issue is exposed in status.
Cold node startup still fully replays the authoritative journal before opening
any derived cache. No serialized state snapshot can initialize or advance a ledger.

`/v1/state-proof` returns a real certified exact-checkpoint inclusion or adjacent
neighbor absence. `rld node state-proof` requires the intended currency descriptor,
checkpoint ID, collection and key, verifies the real receipt/QC and path, and saves
the result. This establishes a historical record, not freshness, an entire wallet
balance, current spendability or permission to import. Query/cancellation witness
construction uses immutable observations outside the global mutex with bounded
concurrent readers. [Storage and proof analysis](engineering/STATE_INDEX.md)
describes the complete-byte and failure paths.

The current executable pins its real native/controller profile to a reviewed
native/proof source fingerprint in `spec/EXECUTABLE_PROFILE.json`. A stale source
binding refuses compilation. Current monetary descriptor reads, drafting and
node initialization/cold replay refuse different program IDs before adopting
state. `rld profile` and actual `rld-prover profile` must match in release evidence.
This revision changes compiled program IDs; no old currency/store/key migration
is authorized. It does not implement general in-place cryptographic upgrades.

## Incremental counted prefix roots

The owner approved the 20 October map-root amendment. Native collections now use
persistent ordered value tables plus immutable counted compressed prefix nodes.
Cloning shares the existing nodes; insert/replace/remove copy the affected paths
and stage both value and commitment roots before publication. Collection tags bind
currency, home and map name. Canonical wire State still carries complete ordered
records; decoding reconstructs both indexes rather than trusting serialized caches.

State.root reads the cached roots of all permanent maps and reconstructs only the
small collection/counter tree. Membership uses the retained key path; absence
still authenticates neighboring ranks or endpoints. Receiving-family commitments
use the same map primitive. Native admission refuses a resulting tree deeper than
64 branches. Derived disk witness pages now split at the same first differing key
bit; native verification checks their complete reconstructed paths and counts.
Old index bindings and old executable descriptors refuse without migration.

This changes root computation and shared in-memory mutation, not the complete
execution witness model. Full monetary invariants, owner/work/fees, issuance slots,
controller exclusion and permanent decision checks remain. See
[the source analysis](engineering/INCREMENTAL_STATE.md). No local fixture, test
suite, payment campaign or measured scalability result is claimed.

## Disk-resident verified native history

Native history records now reside in a private immutable content-addressed index.
The live History retains only its exact root/length/head observation and a shared
bounded byte cache (128 objects / 32 MiB). Full records and 32-way pages are read
on demand. Each append copies the affected disk page path; old observations keep
their exact old roots. The index is built only after ordinary native execution/QC
validation. No persisted index root is loaded as authority: cold startup fully
replays the separately anchored event journal and rebuilds the root.

Proof input replay, controller material, historical certificate checking and API
block paging use checked disk reads. Missing/damaged records are errors, not
absent heights. API block reads run outside the global node mutex. Ordinary new
payments do not scan old commands for wrapper deduplication. Pending rejection
pointers come from journal-verified Reject/Sent events; bounded rotating recovery
rereads exact records. Process-only signer cursors advance only after ordinary
custody reconciliation and reset on restart. They confer no signing permission.

The derived index retains incomplete/orphan objects and refuses new publication
at 1 TiB or 4,194,304 files; these are local storage admission limits, not ledger
truncation. Publication happens before authoritative event append and private root
installation. Failed preparation leaves unadopted objects; an authoritative append
failure retains the old live Core and halts signing. Status exposes conservative
accounted storage and cache use. [The storage analysis](engineering/DISK_HISTORY.md)
records authority, failure behavior and remaining limits. No runtime campaign or
measured memory/latency result is claimed.

## Indexed operation-log execution witnesses

The actual native guest/prover now supports `NativeInput::IndexedExecution` with
`RLD-NATIVE-APPLIED-ACCESS-1`. A certified predecessor binds all state roots, while
an explicit ordered access sequence replaces the complete permanent `applied`
map in the guest input. Each encountered operation verifies exact membership or
absence against the rolling root. Exact retained duplicates advance the access
cursor without executing again; new keys derive their actual successor root from
verified neighbor paths and the actual operation digest. An unused suffix, missing
access, changed digest, stale/mixed root, incorrect count or unsupported path fails.
All other monetary execution and existing invariants remain in the same executor.

An insertion that moves n old leaves below a new fork at path level k is admitted
compactly only when k+n<=64, a conservative bound on every moved path. Unknown
subtree height is never taken from the host. When that bound cannot establish
capacity, the default builder uses the existing full witness under its original
limits. Indexed byte-budget exhaustion also selects full input, which can be
smaller for a short history with many new operations. First-genesis execution
also remains full. Both node proof workers and
CLI witness export select the indexed variant for certified predecessors when
supported. Partial internal state cannot serialize or be issued as complete state.

This removes whole-operation-log materialization from those guest inputs; the
host now retains the complete operation map through its disk adapter; other
collections remain resident. Exact keys/decisions
are not deleted, root algorithms and monetary rules are unchanged, and no achieved
memory/latency result is claimed. [The relation analysis](engineering/INDEXED_NATIVE_WITNESS.md)
records the induction and finite full-witness fallback. The changed actual program
IDs require the new source-bound profile; old descriptors/stores refuse without
migration. No test fixtures, monetary genesis or network were created.

## Disk execution of the permanent operation map

Normal nodes now initialize the applied-operation map on an empty private
`RLD-APPLIED-DISK-1` store after authenticating genesis. Live updates use the exact
native counted prefix hashes and immutable physical objects; a bounded shared
16-MiB / 4,096-object raw cache replaces the resident full table. Every lookup or
access proof checks stored bytes/metadata and exact native membership or absence.
Native roots, child counts and auxiliary physical range/height bindings remain
separate. No root is adopted from a filesystem manifest.

Candidate execution stays in an immutable bounded working layer (8,192 objects /
32 MiB). Queueing, speculative proposals and rejected batches publish no applied
objects. Only complete native execution plus matching QC can seal its reachable
changes before authoritative event append/Core installation. A failure retains
all durably published residue; no failed root grants money or loses an old key.
Historical replay/proof construction seal only already verified native steps.

Verified history format V3 retains each committed record with all six exact sealed
disk-map snapshots. Derived state material V4 stores the remaining collections and
those six commitments, then reconstructs historical state using independently
verified history observations and checks the whole native checkpoint root.
Queries use native disk paths; snapshot publication omits these complete arrays.
Complete snapshot/fallback encoding streams records and fails under existing byte
bounds on I/O/capacity. See [the operation-map analysis](engineering/APPLIED_DISK.md)
for its original stage and the permanent-map section below for current formats.
Native program/source
bindings were rebuilt; old descriptors/derived formats refuse unchanged.

This completes the disk-backed operation-map path, not every native collection.
Physical object/page retention still grows; finite quotas, archival packing and
paid replicated custody remain real operational obligations. No runtime,
crash/power-loss, memory-use or throughput result follows from compilation.

## Disk-resident execution receipts

Verified execution receipts now use an immutable private prefix index over their
native sequence. Core/proof observations retain a root and a shared raw cache
(4,096 objects / 16 MiB), rather than every decoded Certified record. Inserts
copy the affected disk path, not a complete resident receipt vector. Exact birth
and CLI evidence, strict predecessor proof recursion and inclusive successor
rejection recovery retain their original selection rules. Receipt reads verify
complete canonical object bytes and exact retained summaries; I/O/corruption is
an error, never proof absence. Scheduler target selection queries relevant heights
outside the node mutex rather than enumerating all historical certificates.

Only real receipt/QC verification plus exact local native history binding can
publish an indexed receipt. Cold open starts at an empty observation and replays
the independently anchored event journal; a disk root is never adopted. Complete
object/path publication precedes authoritative event append and staged Core
installation. Partial/orphan versions remain and count toward the finite disk
budget. Current-certified and state-proof HTTP reads use immutable observations
outside the node mutex with bounded reader admission. See
[the receipt analysis](engineering/DISK_RECEIPTS.md). This does not implement
packing/rotation or establish measured resource/performance/custody behavior.

## Five permanent native maps on disk

Births, destination decisions, redemptions, source resolutions and consumed funding
now use a generic private append-only native interface and shared immutable disk
paths. Candidate execution retains bounded working changes; post-native/QC sealing
precedes verified-history publication and authoritative append/Core installation.
Every record lookup propagates storage failure; duplicate refusal and canonical
wire construction preserve order/uniqueness without re-enumerating these five
permanent key sets in each batch. Roots and monetary predicates remain unchanged.

The five maps share a separate 16-MiB / 4,096-object raw cache. History V3 retains
six-map sealed observations (including the existing applied map); state material
V4 omits those arrays and reconstructs them only from verified history before
whole-checkpoint validation. Direct historical queries and membership construction
do not enumerate complete maps. Default native proof input now uses exact root-bound accesses for those five
record sets when a certified predecessor exists, with bounded complete fallback.
Scheduling/indexing scans run outside the global mutex. See
[the source analysis](engineering/PERMANENT_MAPS.md). This stage changes actual
program bindings and preserves incompatible old state without migration.

## Indexed permanent-map execution witnesses

NativeInput tag 3 now combines applied accesses with typed birth, destination
decision, redemption, source resolution and consumed-funding accesses. A real
certified predecessor binds all six roots. Empty/nonempty native count openings
are checked even for unread maps; every accessed value or absence is verified at
the current exact root/count/key, and each append computes its successor root.
All supplied accesses must be used. Partial maps refuse complete export or
arbitrary proof issuance. The same native executor still checks monetary rules,
owner/work/fees, issuance, controller exclusion, headers and required QCs.

Ordinary proof input construction records actual five-map accesses during complete
native replay, compares whole headers to verified history and shares one bounded
canonical byte budget with all other input material. It prefers this profile when
a certified predecessor exists; typed material/capture-capacity insufficiency
selects the prior applied-only/full paths under unchanged limits. Other errors
propagate. The real prover and guest execute this input and retain the same native
journal. [The source analysis](engineering/INDEXED_PERMANENT_WITNESS.md) documents
cloned-state tracking and authentication. Proving cost, memory and runtime behavior
remain unmeasured; other collections still need work.

## Material unfinished and unqualified work

The following are real completion boundaries, not fulfilled by source edits:

1. Native execution now shares immutable ordered records and cached counted
   prefix roots, so a single update need not clone every record or rebuild every
   map hash. Other native collections remain resident; native history, the applied map and
   five permanent decision/birth/funding maps now live on disk;
   full invariant scans of the remaining tables, canonical snapshot construction and
   complete guest material for the remaining collections still remain. Native history uses an immutable disk-resident 32-way index, and execution receipts use an immutable disk-resident sequence index. Disk snapshots and witness pages
   serve historical complete material and queries, but snapshot publication still
   materializes complete records and rebuilds pages. A bounded-memory disk
   executor and compact authenticated executable witnesses for all remaining
   collections remain needed. The six-map access path alone does not
   complete that executor. No achieved daily capacity or seconds-scale receipt is established.
2. Native event history now has immutable 64-event/256-MiB maximum storage
   segments and a 128-event hot window. Every 64 append operations can seal one
   eligible segment; a large record may cause fewer than 64 to fit, so this is
   not a strict hot-file count bound under all workloads. Complete frame bytes
   larger than a segment remain loose and block further contiguous sealing;
   maintenance neither skips them nor halts valid native append for that reason.
   Complete frame bytes and the same exact journal commitment remain retained. Cold startup streams
   every segment, checks its source observation and separately retained latest
   head, and replays all native events. Explicit recovery finishes only a fully
   retained, verified seal; damaged originals/residue remain unchanged. This
   reduces loose files; the new disk history removes full-record history residency,
   while other current collections and other Core material remain in memory.
   Contact spools deliberately refuse at finite object/byte limits. A continuously
   operating archival rotation, independently replicated paid custody lifecycle,
   witness availability, disaster recovery and long-history operator product are
   not complete. Evidence is retained on refusal; no timeout drops an obligation.
3. Source/custodian scheduling, invalid-work denial of service, partitions,
   concurrent controllers, cold recovery and succession have not been run through
   a new runtime campaign in this rebuild. A successful compilation does not
   establish these runtime behaviors or their composition.
4. Proof generation for the full Argon2id relation and maximum public inventories
   has not been measured. Feasible proving cost, memory and receipt latency remain
   unresolved operational dependencies even though the real programs compile.
5. Independent security review, cryptographic qualification, secure erasure,
   protected latest-state custody and copied-signer prevention remain open.
6. Signed contact/discovery and offline custody are software carriage mechanisms.
   Physical interstellar routes, long-disconnection operations, key renewal and
   archive succession have not been demonstrated. Light-speed delays remain.
7. A compatible in-place transition to a new proof program, signature suite or
   encoding is not implemented. Existing handoff changes keys/operators within
   the fixed executable profile; it must not be presented as cryptographic
   agility across arbitrary future primitives.
8. There is no launched monetary genesis, deployed validator network, initial
   monetary key ceremony, monetary issuance or migration in this repository.

The whitepaper remains a conditional scientific construction. This implementation
must not be advertised as a complete, independently qualified interstellar
payment network or as having demonstrated world-changing adoption.

## Owner deployment direction, 20 October 2026

After implementation completion, mainnet deployment to
`galaxy@35.200.194.179` is authorized. Current completion boundaries remain open.
Read-only preflight and isolated deployment templates are recorded in
[the mainnet deployment plan](operations/MAINNET_DEPLOYMENT.md). No monetary
genesis, monetary key generation or mainnet start occurred in this stage.
