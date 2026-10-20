# Native permanent decision maps on disk

## Stage and source question

Parent f890e5c stores native history, operation IDs and execution receipts on disk,
but still retains all native birth, destination decision, redemption, source
resolution and consumed-funding records. They are permanent append-only maps.
The active question is whether the same native roots can support ordinary live
execution, historical reconstruction and direct queries without resident copies
of these five collections or new unchecked serialized authority.

The discriminating source chain is Permanent construction/insertion, native
caller migration, candidate isolation, post-QC sealing, verified-history binding
and split-state/query reconstruction. Work is bounded to implementation, source
review and compilation repair followed by the actual full source-bound build.
No fixture, local test suite, payment run or performance acceptance campaign is
introduced. A missing check is repaired; a build cannot qualify runtime behavior.

## Native representation and invariants

The protocol's Permanent<T> has private complete-table and host-storage variants.
It is used only for births, decisions, redemptions, resolutions and used_funding.
The public interface provides checked append, fallible owned lookup, membership
and complete record streams. There is no replacement/remove/indexed assignment.
Sorted wire constructors require distinct increasing actual record keys and exact
equality with each record's direct native key. Full insertion uses the existing
duplicate-refusing Table/Map primitives. Host insertion uses exact native leaf /
counted prefix hashes and duplicate refusal. The guest has no filesystem variant.

Native State retains the same CBOR array positions, complete record arrays,
collection hash tags and top-root construction. Full guest input decoding still
reconstructs all five maps. Per-batch checks no longer allocate five complete key
vectors solely to repeat order/uniqueness: those properties follow from the private
constructors and append transitions. Other monetary invariants, owners, fees,
issuance, controller exclusion, QC and receipt checks remain. Fallible point
lookups replace exact-key scans with the same predicates. The outstanding
controller count explicitly propagates every resolution/redemption read error;
no filter, bool conversion or default converts a failed lookup into absence.

## Disk paths and candidate isolation

One private permanent-index object owner is bound to exact currency/home/genesis.
Each typed leaf/page and historical snapshot also binds its collection tag.
Physical digests bind complete canonical node bytes, typed record, child physical
objects, native subtree hashes/counts, ranges, depth and height. Reads recompute
all summaries and reject changed/mixed contexts. Native inclusion is verified
against the exact root; absence verifies adjacent/end-point native proofs. Missing
or corrupted data is an error, not a zero count or unspent/unresolved record.

The five maps share a raw cache limited to 4,096 objects / 16 MiB, independently
of the applied/history/receipt caches. Each speculative map has its own bounded
8,192-node / 32-MiB immutable working overlay. A native batch has at most 64
operations; each selected map gains at most one record per operation. A path has
at most 64 branches, each node at most 4 KiB, within those overlay limits. The
five-map aggregate working allowance is therefore up to 160 MiB, plus the applied
map's separate allowance and other allocations; this is not a 16-MiB node claim.

Queue/proposal validation publishes no permanent objects. Only after complete
native execution, exact header comparison and QC validation does the staged Core
seal reachable changes in all six disk maps. History publication and authoritative
event/latest-head append follow; only then is the live Core installed. A failure
preserves old live roots and all already published partial/orphan objects. A
failed authoritative append halts signing. Snapshot generation refuses unsealed
working bytes. Historical replay seals only already verified native steps.

## History, material and actual proof inputs

RLD-VERIFIED-HISTORY-INDEX-3 retains each native committed record with a bounded
RLD-NATIVE-DISK-OBSERVATION-1 containing the six exact sealed storage snapshots.
Cold open regenerates them from complete anchored native event replay. Neither
index loads a disk root as ledger authority. One observation is at most 4 KiB;
each typed snapshot retains exact currency/domain/genesis/collection bindings.

RLD-STATE-WITNESS-INDEX-4 omits the six arrays from private cached State material,
retains all their native commitments, and builds witness pages only for the
remaining collections. Historical load requires the storage observations from
independently verified native history, empty material placeholders, complete
invariants and exact whole native checkpoint root. A partial material file alone
cannot authorize a state. Missing derived material may replay the full native
prefix using fresh empty observations under the same private owners.

Historical/current membership and absence for these collections use direct
paths; queries do not enumerate those complete maps. Native/cancellation/CLI
witness membership uses the same direct proofs. Full public State and actual
native proof input still stream complete records for these five maps under the
existing bounded encoders; only the applied map currently has an indexed guest
access tape. This stage does not claim compact guest execution for all maps.
Birth scanning used by scheduling/indexing is a fallible stream outside the node
mutex. Controller HTTP reads capture immutable observations and use bounded
blocking readers outside that mutex.

## Remaining scope

Private object admission remains 1 TiB / 4,194,304 files for the shared owner,
including retained old versions and partial/orphan files. Nothing is pruned on
quota refusal, cancellation or elapsed time. Disk/file amplification, packing,
paid archival replication/rotation, protected latest heads and long-history
operations remain open. Mutable/native mint and other remaining maps, controller
and delivery queues, scans, response buffers and full guest material still have
separate costs. No measured memory, write latency, throughput, proof cost,
crash/power-loss, independent security or physical route result follows.

The native program/source binding changes and is rebuilt/pinned to actual real
guests/prover before the final host build. Old monetary descriptors refuse; this
is not a value/key migration or in-place program upgrade. Preserve incompatible
private directories and old failures. The paper/root algorithm, RLD-only money,
21-million cap, zero allocation and all monetary rights remain unchanged. No
monetary keys/genesis or network are created by this stage.
