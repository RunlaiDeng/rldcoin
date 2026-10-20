# Native-root-exact disk operation map

## Source question and implementation boundary

Parent 203dfe2 can prove operation-map accesses but still retains the entire map
in host memory and serializes it in cached historical State. This stage asks if
normal host execution, current/historical queries and actual indexed proving can
use immutable disk paths without adopting a cached root or reloading that table.
The discriminating observation is the implemented initialization, mutation,
verified-history snapshot and split-state load chain, plus candidate write
isolation. Review these paths and compile final actual guests/prover/host. No
fixture, local test suite, runtime campaign or performance result is introduced.

## Roots and authority

The host-only Storage adapter is initialized only at an independently checked
empty native applied map. AppliedStore.open fixes RLD-APPLIED-DISK-1, currency,
home and genesis; it returns an empty observation, never a disk manifest head.
Core authenticates genesis first. Cold opening fully walks the independently
anchored native event journal and validates ordinary monetary execution and QC
before reconstructing its later roots. Existing private files are data, not a
shortcut around that reconstruction.

Each immutable disk node has a physical byte digest and exact native subtree
hash/count. Physical child references additionally commit first/last keys, depth
and height. On read, recompute the node summary from canonical complete bytes and
compare every field to the caller-retained reference. Leaves bind actual applied
ID/digest. Branches have two nonempty ordered children, the first differing bit,
common prefix, checked child/total counts and height <=64, using unchanged native
hash tags. Auxiliary heights come from this verified mutation lineage and are
bound in physical parent bytes; they are not accepted as proof inputs by the
indexed guest. Native membership/absence generation independently verifies its
computed path under the exact native root.

Frozen roots share one locked private object owner and bounded immutable byte
cache. Insert clones only an observation and its bounded working changes; it
neither replaces/deletes an old key nor mutates an older observation. Complete
wire State still decodes complete sorted memory records. The host adapter never
appears in guest wire input; the actual guest checks the same native roots through
complete or indexed execution. Logical full-state equality compares the same
context/count/native commitment, not storage addresses.

## Candidate isolation and publication

Ordinary validation executes tentative native states before a commit exists.
Persisting every tentative prefix would let repeated uncommitted candidates fill
permanent storage. Inserts therefore retain new canonical nodes only in an
immutable working overlay, at most 8,192 nodes / 32 MiB. A supported 64-operation
batch with paths <=64 creates at most 64*65 nodes, each at most 4 KiB, within that
budget. Overlay reads verify exact bytes and summaries like durable reads. Failed
or discarded working state publishes no applied files and grants no rights.

Only after State.execute_batch and exact matching QC verification does Core seal
reachable working nodes. Seal completes synced immutable object publication and
returns a new observation without working bytes. The verified-history snapshot
refuses an unsealed root. Core stages that snapshot/history and other effects in
its private clone, appends the authoritative native event through the existing
journal/latest-head protocol, then installs the clone. Failed seal or journal
publication never installs the candidate; already written partial/orphan objects
remain. A failed authoritative append retains the old live Core and halts signing.
An orphan object/root is not an event. Historical replay and proof preparation may
seal only records already contained in their verified immutable history view.

Objects use 256 private digest shards, exclusive ownership, complete synced unique
temporary files, directory sync/rename/sync and exact byte comparison when reused.
All retained/partial/orphan files count toward conservative 1-TiB / 4,194,304-file
admission. The raw cache is at most 4,096 objects / 16 MiB, shared across snapshots.
Failed reservations can overcount until verified reopen; status calls them
accounted usage. No new object is admitted beyond those limits; nothing is pruned.
Filesystem capacity can fail earlier. Independent all-state/head rollback and
copied-custody protection remain separate from these byte checks.

## Historical binding and split material

History V2 stores each exact native Committed record with the small applied
snapshot generated after validated execution/seal. That pair's immutable physical
hash enters the process's verified history root. Cold replay regenerates the pair
from native events rather than accepting an on-disk history head. Transport/API
Committed bytes remain unchanged. Historical snapshot decoding is used only from
that authenticated history observation for proof/read reconstruction, never as
an initial live ledger root.

State-index V3 stores the other complete native collections with an empty applied
placeholder and the exact applied commitment in its collection inventory. Its top
root must equal the retained native checkpoint. A load requires the applied
snapshot from the separate verified-history view, checks context and commitment,
then checks complete invariants and State.root against the exact header. A partial
material file alone fails that binding. An altered/mixed snapshot, missing object
or bad digest refuses; it cannot become an empty map. Missing derived material
may fall back to full native replay, with the disk applied map reset only as an
empty local replay observation. Corrupted existing objects are retained/refused;
operator reconstruction preserves all three derived directories and replays the
unchanged authoritative journal/latest head. No old balance/key migration occurs.

Historical applied queries use the adapter's direct paths plus the normal top
membership. Publishing split snapshots does not enumerate the applied map.
Default indexed proof construction clones the frozen disk map and generates exact
accesses; it seals only already committed native step boundaries to avoid retaining
a whole proof span's tentative nodes. Full witness/public State serialization
streams sorted records and propagates I/O errors. Bounded encoding refuses before
emitting oversized material under existing 1-GiB/16-MiB interfaces. Public snapshot
reads capture an immutable State under the node mutex and encode outside it with
a two-reader bound. No read error is silently converted into key absence.

## Scope and remaining obligations

This implements current and historical disk execution for one permanent map,
including actual prover input construction. It is not a 16-MiB full node: other
current collections, decoded records, private history cache, receipts, queues,
working overlays and bounded response/snapshot buffers have separate costs.
Other maps still need disk execution/compact witnesses. Immutable version objects
retain disk and file amplification; finite quotas are not sustained daily-capacity
evidence. Archive packing/rotation, paid replicas and succession remain unfinished.
No measured RAM, write latency, throughput, proof cost, crash/power-loss result or
independent security qualification is claimed. The final actual source/program
binding is recorded separately. New program/derived format bindings refuse old
ones without rewriting them. The paper, map-root construction, RLD-only money,
21-million cap, zero allocation, signatures, fees and complete monetary checks
remain unchanged. No network/genesis/monetary keys are created by this stage.
