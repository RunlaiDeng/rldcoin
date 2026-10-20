# Disk Mint facts and exact slot lookup

## Source question and stage

Parent 80eb5b7 retains every MintRecord in memory. A remembered work-author fact,
new Mint and each batch's active-segment check scan all Mint facts or rebuild a
whole minted-slot set. The question is whether exact event/slot indexes can
preserve the same native decisions without resident history or those scans.

The discriminating chain is complete wire reconstruction, atomic unique event /
slot append, exact active-range query, disk pair publication and verified-history
reconstruction. Work is bounded to implementation, source review and compilation
repair, then the final actual source-bound build/profile comparison. No fixture,
local test suite, proof/payment run or measured capacity campaign is introduced.

## Same native root, private auxiliary index

Mints keeps the native event-keyed root, record hash tags and complete canonical
State array at position 15. It does not add a monetary collection, counter or
accepting authority. The auxiliary key is zero-padded big-endian
(root_u32 <<32)|slot_u32, so its lexical order is exactly (root,slot) order. The
auxiliary value is the event ID. Only the primary Mint event root appears in
State.root, public membership and monetary evidence.

Complete wire constructors validate each fact's root/slot bounds and owner,
require sorted distinct event IDs, and rebuild all auxiliary records from those
same complete facts. Sorted auxiliary construction rejects duplicate global slots.
Private append stages both indexes and rejects either duplicate event or slot;
there is no public replacement/remove API. An unchanged remembered event must
still equal the retained complete record. The host backend also compares each
selected slot record with the complete native-authenticated primary event.

Root<4096 and slot<1,000,000 allow only 12+20 varying bits in the 64-bit auxiliary
key. Its counted prefix tree therefore cannot need more than 32 branch levels;
using the existing 64-branch map primitive imposes no extra height admission on
these keys. The primary event map keeps its original native bound. Auxiliary
roots/counts are private reconstructed observations, never peer assertions of
unspent issuance or a new independent proof suite.

## Equivalent uniqueness and active-range checks

Mint event order/uniqueness and global-slot uniqueness are maintained by complete
constructors and duplicate-refusing atomic append. Native execution no longer
collects every event ID or minted (root,slot) into new vectors/sets per batch.
Mint work checks its exact slot; remembered work-author facts check event equality
then exact slot absence. All failures propagate instead of becoming absence.

The existing active segments retain their bounds and non-overlap checks. For each
active (root,lo,hi), select the greatest retained mint slot <=(root,hi-1). The
interval is empty exactly when no candidate exists, its root differs, or its slot
is below lo. If any mint lies inside the interval, the greatest candidate for that
root cannot be below lo; if none does, the candidate cannot falsely lie inside.
Thus this is the same consumed-active-slot predicate as the original full scan.
Native grant/frontier, exact public work, reward/cap counters, signatures, fees,
controller exclusivity and per-cover conservation remain unchanged.

## Disk engine, lineage and publication

The previous UTXO path engine is now shared as typed_paths. UTXO node/observation
format, native tags and exact bytes remain unchanged. Typed Mint events use
RLD-MINT-EVENT-PATH-1; auxiliary slot records use RLD-MINT-SLOT-PATH-1. Their page
formats and collection tags prevent cross-type/cross-role adoption. Values retain
exact native typed hashes. Node reads check canonical bytes, length/digest,
physical summaries and native membership/absence; returned records validate their
intrinsic type bounds. Missing/corrupted data refuses, never becomes an unused slot.

One private mint-index owner, RLD-MINT-FACTS-DISK-1, binds currency/home/genesis and
shares raw objects/cache across both roots. It opens both empty regardless of
retained files. Complete anchored native/QC event replay reconstructs every pair.
No file/manifest head is adopted. Both counts must agree; a selected auxiliary
entry must resolve through a verified primary event with exactly matching slot.
Read-only historical reconstruction obtains the pair only from the separately
verified immutable native history observation, not a cached State root supplied
by a peer or operator.

Every append produces two staged immutable working roots. Failure to build the
second does not install the first. Core seals both only after complete native,
matching header and QC checks, before verified history and authoritative event /
latest-head publication. Failed partial/orphan publications remain retained; old
live roots are installed only after authoritative append succeeds. Historical
proof preparation seals only already verified native records. No published value,
slot, old root or evidence is pruned on timeout/capacity failure.

The two typed paths share a separate 4,096-object /16-MiB raw cache and 1-TiB /
4,194,304-file admission, including partial/orphan files. Each working root retains
its existing reachable-only 600,000-object /512-MiB encoded-material budget;
other maps keep their separate budgets. Using a conservative 64-fact allowance per operation (current fee lists are
bounded by 32) and 64 operations gives at most 4,096 new remembered facts in a
batch; Mint itself contributes one rather than extra fee facts. Each typed path needs at most 65 nodes and
one value per append, within the existing UTXO path bound. The pair can retain two
working roots; allocations, overlapping versions and concurrent workers add costs.
These are source bounds, not measured maximum RSS or daily-capacity results.

## History, actual guest and limits

History V5 retains eight-map observation V3; the Mint member is a bounded pair of
primary/auxiliary snapshots. State-material V6 omits those arrays and requires
verified history plus complete invariants and the exact whole native checkpoint
root before use. Direct historical Mint queries authenticate primary event paths.
A cache/auxiliary root does not initialize a ledger or authorize signing.

All actual native proof input variants still stream the complete event-sorted
Mint array. The real guest rebuilds its own slot index from every record; it never
accepts the host auxiliary root as proof. Existing indexed inputs remain for the
other seven maps. Compact remote Mint/slot witnesses are still unimplemented;
maximum native input/proving feasibility is unresolved. This stage removes host
Mint residency and per-batch full-Mint scans, not all history processing, active
segment scans, archive amplification or whole-guest material.

Actual native/controller source/program bindings are rebuilt/pinned. Old monetary
descriptors refuse without rewriting currency, values or keys. The paper, native
root algorithm, RLD-only money, 21-million cap, zero allocation, public work and
monetary rights are unchanged. No monetary genesis/keys/network are created.
No runtime selection/proof, throughput/latency/memory, crash/power-loss, independent
security, paid archival lifecycle or physical stellar-route result is claimed.
