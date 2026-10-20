# Authenticated disk state material

## Active hypothesis and bounded decision

The parent `9f607b1` reconstructs historical state from genesis for proof bases
and controller membership witnesses. The active hypothesis is that retained
complete checkpoint state plus directly verifiable map pages can remove that
repeated replay from ordinary historical data access, while preserving full
native authorization and independent cold replay. The discriminating source
observation is whether those callers actually read validated disk material,
rather than merely creating an unused side index. They now do so in historical
state/proof input construction, controller creation, cancellation, rejection
return witnesses, the local membership command and the certified query endpoint.

The implementation/review scope covers index construction, complete-state load,
path construction, fallback, concurrency and exact-checkpoint client validation.
The release-build budget is at most two full compilation attempts with repairs
selected by compiler/source failures. No fixtures or local test suites are added
or run under the owner's instruction. Exit evidence is reviewed integrated code
and compilation bound to exact source; it is not runtime throughput, cold-recovery
campaign, cryptographic qualification or a mainnet-readiness declaration.

## Authority and complete data

The index is process-locked and bound to the currency, domain and genesis. Its
format is `RLD-STATE-WITNESS-INDEX-1`. It lives below the private native store but
is derived data. Native cold startup still replays every authenticated event from
genesis and checks the independently retained latest head before attaching it.
It does not load a ledger from the index. Missing/corrupt/saturated index data
cannot authorize an event, reset a counter, refund value or replace a signer.

Each published checkpoint manifest names its exact full native header, canonical
state byte count/digest, ordered chunk list and the complete native collection
inventory. Complete state chunks are at most 1 MiB. A manifest is at most 256 KiB;
complete state reconstruction remains within the existing 1-GiB witness-record
bound. Chunk sizes and digests, whole state digest, canonical decoding, native
invariants, currency/domain/sequence and the exact checkpoint native state root
are checked before historical state is returned. A handoff checkpoint names the
old signing configuration while its poststate may contain the next configuration;
the authenticated state root binds that next configuration without incorrectly
requiring poststate configuration to equal the old header signing configuration.

The complete canonical State bytes remain available; pages contain only map
entries and cannot substitute for the data needed by a subsequent prover. State
loads into the real native witness relation still need the exact predecessor
execution receipt. Storage hashes are byte-integrity observations, never native
proofs. Checkpoint manifests are published only after every referenced object is
fully written, synced and the object directory synced. Temporary/failed writes
keep unique names. Existing altered objects refuse without overwrite. Partial or
orphaned objects alone do not publish a checkpoint or advance native state.

## Ordered-map page construction and lookup

The protocol exposes its existing collection inventory and pure map/top builders;
no monetary field or root formula is removed. The index computes exactly the
existing native `RLD-MAP-LEAF`, `RLD-MAP-NODE`, `RLD-MAP-EMPTY` and `RLD-MAP-ROOT`
formulas, with the same currency/domain/collection separation. Each collection is
sorted by native entry key. Trees split at the largest power of two strictly
below the current count. A leaf page holds at most 128 entries. Larger subtrees
carry two bounded child references with exact counts and native subtree hashes.
The storage object digest also binds page format, network/collection, bounds and
complete page bytes. The native wrapper binds count and native subtree root.
The top collection tree must equal the caller's exact native checkpoint root.

A rank lookup follows exact child counts. Within a leaf it uses the existing
native membership builder. On return it appends authenticated sibling hashes
bottom up and installs the complete tree's count/index. The existing native
verifier then checks the resulting full membership path. Key-guided search may
use first/last metadata only to select a candidate rank. That metadata is not
independent authority: an inclusion must name the requested key and pass the
native path check. An absence must supply authenticated adjacent ranks or the
exact first/last endpoint and pass `verify_absent`. Wrong routing metadata can
cause refusal/fallback, but cannot prove a false absence of a present key under
an unchanged authenticated ordered-map root and hash assumptions.

## Integration and concurrency

The background indexer takes immutable views under the node mutex, then builds
at most one checkpoint outside that mutex per pass. It examines at most 64
candidate checkpoints per pass, rotating outstanding controller births and the
latest proof base, with recurring current-head priority. Native consensus never
waits for a derived disk publication. Complete object deduplication is by exact
bytes and immutable digest, not by unchecked mutable state. Local admission counts
all retained objects, manifests and partial files under a 2-GiB/65,536-file budget.
Writes reserve conservatively; failed writes may overcount until reopening. A
full derived cache pauses further publication while existing native data remains.

ProofContext checks the caller's retained exact native header before using disk
state or a page query. Missing manifests use normal reference state reconstruction.
Read failures record `state_index_error` and preserve damaged bytes. A failed
page query can fall back to complete root-verified State; failed complete-state
loading falls back to native journal replay. Every full-state fallback still
compares the native root to that header before constructing a query. Cancellation retains the direct birth
QC and original owner authorization, without requiring a departure proof. Its
public draft construction and certified query construction run outside the global
mutex, with at most two concurrent public state readers. Rejection witnesses also
use the same exact-checkpoint path. Live submission/execution still checks current
terminal maps, incidents, authorization and ownership; historical data grants no
current right.

`/v1/state-proof` returns CertifiedQuery: a real certified native checkpoint and
one native membership/absence query. The client requires its independently retained
exact checkpoint ID, currency descriptor, collection and key. It checks the real
pinned execution receipt, QC and all query bindings. It does not call a historical
state root fresh, claim a wallet total from selected outputs, or treat absence as
a refund/import permission. An exact receipt not yet available remains pending.

## Source/executable profile boundary

The actual compiled guest IDs changed with this revision, despite preserving the
native map formulas. The host now embeds a public executable profile plus a
length-prefixed SHA-256 inventory of native/proof Rust sources, dependency locks
and toolchain/build manifests. Node compilation checks that fingerprint. Current
currency reads/drafting and the first initial event before native cold replay
require the embedded proof profile; node genesis initialization does likewise.
A mismatch neither replays native value under the new host rules nor finishes a
pending recovery publication. Old state remains for its matching release.

The profile helper reads metadata from a built real prover; it creates no keys,
proofs, genesis or network. The helper by itself could be pointed at an old binary,
so the final full-source-bound release build must independently compare actual
prover IDs to embedded CLI IDs. Reproducibility on another platform and independent
security remain separate evidence. CI configuration is unchanged. There is no
bypass flag, legacy fallback or claim that a storage/source hash authorizes money.

## Remaining scope

This is integrated disk state material and proof access, not a completed sparse
native executor. Native execution still materializes/clones State, scans current
collections and rebuilds all roots. The current positional sorted-map construction
can shift many pages on insertion; this stage does not establish incremental
update complexity. Background publication also serializes complete state and may
lag or exhaust its finite cache. Historical native records and receipt vectors
still reside in host memory. Complete data can therefore still exceed operating
resources; witness bounds are not an infinite-history guarantee. A bounded-memory
native executor, compact transition witnesses, funded replicated archival custody,
proof cost and latency/capacity qualification remain unfinished. No monetary keys,
genesis, test fixtures or deployed network are created in this stage.
