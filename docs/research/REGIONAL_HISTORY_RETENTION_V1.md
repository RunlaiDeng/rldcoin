# Regional native history retention: implementation obligations

The current native candidate is not a long-history ledger. `MAX_BLOCKS=256`,
`MAX_SNAPSHOTS=64`, `MAX_BYTES=8 MiB`, and 4,096 coin/export/import entries are
explicit refusal boundaries. Every snapshot carries the complete regional block
prefix; incoming export evidence carries verified predecessor/dependency closure.
Raising these numbers alone does not satisfy master-plan I2 or I10.

## Current native groundwork

The published revision-18 prefix candidate reuses an exact predecessor's completely
replayed ledger inside one process, bound to the full currency/admission trust
set. It compares the carried block prefix, authenticates incoming certificates
and epochs, and executes every new block through normal native rules. Cold
verification derives the starting ledgers from genesis; no cached ledger is
deserialized as value authority. Block acceptance validates prospective finality
and the complete new ledger before changing either. A failed tail cannot install
an anchor. Preparing epoch authority changes copies only the registry.

This removes duplicate work within the current bounded representation. It does
not provide durable paged history, compact remote value proofs, rollback roots,
history beyond 256 blocks, or a 200,000-block-era acceptance result. A changed
native implementation requires fresh fixture genesis/currency. Retired, adopted
and earlier candidate records retain their exact original source commitments.

## Required storage and proof boundary

The next native representation must separate immutable durable history from its
bounded active replay state. Each history page needs a domain/version, exact
currency and region, ordered height range, predecessor commitment and canonical
record bytes. A manifest must commit to all retained pages, finality/era proofs,
authenticated incidents and permanent import identity commitments. Restoring
from a manifest alone cannot make an unsigned ledger snapshot trustworthy.

Initial verification must replay from the signed zero-allocation genesis or from
a previously fully verified exact prefix protected by a surviving latest-state
anchor. New checkpoint extensions must bind the predecessor's complete state,
history and import commitments. They may execute only their suffix after exact
parent verification; an unverified sender-supplied balance cannot become that
parent. Full owner consent, source issuance/conservation, local maturity, regional
finality, export debit, import uniqueness and transitive incidents remain native
rules. Legacy unanimous regions cannot silently lower their threshold, and a
new storage dialect does not grant BFT reconfiguration or recovery authority.

Remote proof carriage also needs bounded verified dependency access. Splitting
the same unbounded prefix into transport pages without authenticated closure,
resource admission and native reconstruction is insufficient. Missing pages or
unknown delayed cryptographic/era authority must preserve pending value and
refuse acceptance; a receipt or deadline never releases the source export.

## Durable publication and recovery obligations

1. Write and synchronize immutable payloads before making a manifest/head visible.
   Retain interruption residue; do not treat an unverified orphan as an accepted
   page. A response acknowledging custody requires actual retained bytes and
   synchronized file/directory durability.
2. Protect an exact latest native state observation outside the rollback domain.
   Detect missing history, old manifests, disappearance of import tombstones,
   finality/era regression and vanished authenticated incidents. If every archive
   and anchor can roll back together, independent rollback protection is absent.
3. Restore into a fresh private target with an interruption marker, reconstruct
   value and authority, and compare complete roots before opening it. Never
   overwrite an existing caller head, signer reservation or wallet pending review.
4. Quantify bounded active memory, immutable archive bytes/files, source and
   destination proof work, refusal at disk/capacity limits and complete recovery
   costs. Retention may compress exact bytes; it cannot discard unresolved value,
   signer locks, permanent import identities or required historical authority.

## Acceptance still required

Run an actual native history beyond the first declared 200,000-block issuance era
under the applicable issuance rules, with local payments, delayed original
exports/imports, onward/return value and all I=U+T checks. Recover from separately
retained archives; corrupt, omit, reorder and substitute pages, roots, old heads,
finality/era evidence and import commitments. Exercise interrupted writes,
full storage and stale backups. These faults must not create spendable assets or
refund included exports. A fast empty fixture loop alone does not meet this gate.

Same-host testing is local evidence. Independent archive operators, custody,
security review, power-loss storage assumptions and actual physical routes remain
separate prerequisites. No second host or independent operator is currently
available; continue native implementation without claiming those qualifications.

## Supplemental exact shared evidence storage candidate

The companion now stores immutable canonical bytes for distinct complete
evidence snapshots, indexed by their full byte SHA-256. Each original envelope
retains the ordered reference list (including repeated entries), full body,
value/local flag and original canonical digest/size. Reconstruction returns new
objects; the process holds no mutable trusted proof. Before expansion, exact
encoded size must match and remain at most 3 MiB. The combined storage wrapper
still refuses above 32 MiB and at 512 messages; snapshots are not pruned.

`RLD-REGIONAL-BFT-RETENTION-V2` is supplemental storage, not a signed rule or
proof format. Legacy private state refuses unchanged. Every new envelope is
fully authenticated by Rust before retention, and cold startup/verifiers fully
reconstruct and authenticate every retained envelope. Failed disk persistence
keeps exact already-signed responses in the separate caller-head outbox;
restart recovery cannot first-sign. Missing/substituted/orphan bytes, changed
metadata, expansion overflow and forged certificates refuse.

A byte-only diagnostic round-tripped all 2,259 envelopes in the twelve stopped
revision-18 failed stores, preserving bodies, complete evidence, values and
local flags. Maximum inline state was 33,529,748 bytes; prospective exact shared
state was at most 1,628,727 bytes. Private files were unchanged and were not
migrated. This accounting does not prove native authentication, repair the
failed run, qualify the full fault profile or meet the long-history gates.
Fresh source freezing, lifecycle value/fault runs and stopped-state native
authentication remain separate required evidence.

## Native paged disk candidate

The default native store now prepares typed immutable snapshot, epoch and contact
objects and sixteen-event pages before publishing its compact journal manifest.
Each object binds its full canonical bytes to the storage domain, currency and
local region. Ordered event pages bind exact event offsets, predecessor page
hashes and before/after local heights. The manifest commits the ordered complete
proof set, incident identities and exact reconstructed native journal bytes.
Cold open reconstructs these bytes and performs the existing full native replay;
a self-consistent storage digest cannot validate a forged certificate or balance.

Archive admission counts old tail versions, referenced and unreferenced residue,
and refuses above 4,096 files / 256 MiB. Referenced objects require exact size,
digest, type and scope; unsafe names, symlinks, hardlinks and permissions refuse.
Missing or partial bytes are not repaired automatically. Retained exact objects
are synchronized again before manifest publication. A failed manifest publication
leaves the previous native head and newly written unaccepted objects retained.

The operator can retain `history-head` outside the rollback domain. `history-check`
checks that exact head under the native OS lock and fully replays current native
value/authority; pending incidents require explicit recovery, not reconciliation
inside the pinned check. An old valid manifest can still replay without a surviving
external latest head. This does not qualify independent anti-rollback custody.

This storage phase preserves the logical 8 MiB, 256-block, 64-snapshot and ledger
index bounds. It does not implement long-history execution, compact remote value
proofs, 200,000-block issuance eras or fresh-target archive recovery. Those remain
required above. Old inline private storage is incompatible and remains preserved;
a new implementation requires fresh signed fixture genesis/currency. Passing prior
revision-19 reports cannot certify this changed native source.

Pinned checks also require every authenticated retained incident to appear in the manifest index. An extra unindexed incident refuses before reconciliation; its proof is retained and cannot be hidden by a passing storage head.

## Fresh-target private native history image candidate

The new `RLD-NATIVE-HISTORY-ARCHIVE-V1` implementation addresses bounded ledger
image recovery. It seals under the native lock and a separately retained exact
head; restore authenticates the complete image before target creation and again
after synchronized copying. Inventory digests never replace native signature,
finality, owner/value, permanent import or incident replay. Every retained native
object and damaged-incident residue is carried without pruning. Unknown private
source state, keys, signers, BFT replicas, caller heads, wallet journals, pending
reviews, TLS and transport archives are deliberately outside this ledger image.

Images and restored directories use private files/directories. Fresh targets
only; existing targets are never overwritten or merged. `ARCHIVING` prevents use
of an incomplete image. `RESTORING` prevents all ordinary native entry points
and explicit incident recovery from opening an interrupted target; preserve
that target and select a different fresh path. Unresolved source `journal.next`
also refuses sealing without rewriting evidence. Process-local locks and image
equality checks do not qualify hostile all-state rollback or copied-key custody.

This phase retains the 4096-file / 256-MiB native history capacity, bounded
16-file authenticated incidents and 16-file damaged residue, each at most 8 MiB,
and a combined 4130-file / (520 MiB + 32 byte) image ceiling. Native logical
8-MiB, 256-block and 64-snapshot bounds remain unchanged. It neither extends
history to 200,000 blocks nor restores signer/wallet authority. Power-loss,
independent archives/latest heads, cross-device custody and physical-link gates
remain required. A changed native source needs fresh signed fixture genesis;
revision-20 cycle/fault reports cannot certify it.

The initial ten-test run had nine successes and one incorrect assertion about
the error text for a short forged signature. Preserve that failed log/source.
The corrected test uses a full-length invalid signature, so it exercises native
cryptographic rejection; all ten focused tests and strict all-target checks pass.
Frozen full-source lifecycle and fault-profile results remain separate evidence.

The 4130-file / (520 MiB + 32 byte) ceiling counts retained native payload
(manifest, guard, history, incidents and damaged residue). The separate canonical
archive index is bounded at 8 MiB; locks and filesystem directory metadata are
not included in the reported retained-native byte count. This clarification
does not change native limits or the frozen source used by the running campaign.

## Exact predecessor sharing in native history storage V2

`RLD-NATIVE-HISTORY-MANIFEST-V2` and `RLD-NATIVE-HISTORY-OBJECT-V2`
retain the same complete logical native journal. A first checkpoint is a full
object. A later checkpoint with an exact listed predecessor carries that
predecessor's object digest and byte length, the complete prefix length, the
new blocks and the original complete certificate/era metadata. The signed
statement, consensus serialization, complete snapshot transport and native
value rules are unchanged. The implementation commitment changes, requiring
a fresh signed no-value fixture currency; V1 directories refuse unchanged.

Reconstruction uses only objects already directly listed and reconstructed
earlier in the manifest. It cannot recursively follow references, adopt
orphans, reorder checkpoints or use a future object. Exact object scope,
reference length, predecessor statement, region/currency, prefix height and
new block range are checked. Expanded snapshot bytes must fit the declared
logical journal budget, and the final complete journal commitment must match.
Native signature, BFT/unanimous finality, era, owner, conservation, permanent
import and incident replay still decide validity; self-consistent storage
hashes do not authenticate a forged certificate.

All retained old objects, partial-tail pages and failure residue count against
the original 4096-file/256-MiB archive limit. Logical 8-MiB, 256-block,
64-snapshot and permanent-index bounds remain unchanged. Full expanded memory
state and remote proofs are still bounded and duplicate complete prefixes.
This phase reduces repeated on-disk checkpoint blocks; it does not qualify
200,000-block histories, compact transport proofs, independent archives,
latest-state anti-rollback or stellar cryptographic horizons.

## Native checkpoint-prefix carriage candidate

The contact V2 and BFT network V2 candidate share repeated blocks within one
complete evidence message. Each carried entry includes original certificate/era
metadata and new blocks, plus an optional exact earlier checkpoint statement ID
and prefix length. Reconstruction uses only earlier entries in that same
message, bounds aggregate expanded bytes and complete block counts, and yields
the original complete Evidence. It never consults a warm peer cache or accepts
a checkpoint digest as native authority. Full native authentication/replay still
checks every expanded proof and exact causal/export dependencies.

Full native Evidence/Journal serialization and signed bodies are unchanged.
BFT proposal/finality bodies retain complete snapshots; vote/timeout signatures
and native atomic finality rules are unchanged. Wire envelopes use V2, while
ordinary native proof queries and local consensus still use full Evidence. A
read-only native BFT pack command verifies the complete logical envelope before
packing; incoming/cold checks reconstruct and authenticate before Python uses
the returned full evidence for native sync. Durable submissions are packed by
Rust after typed verification and never debit merely because queued.

Original 3-MiB physical payload, 8-MiB native logical envelope/evidence/journal,
256 blocks, 64 snapshots and permanent-index/archive bounds remain. Compression
may fit more already-admissible logical evidence into the same physical payload;
it does not enlarge the native logical envelope or certify 200,000-block eras.
V1 payloads refuse without fallback; changed implementation needs a fresh signed
no-value fixture currency. Old and test balances never migrate. No compact state
witness, pruning, latest-state anchor or independent/physical qualification is
claimed. Candidate-wide frozen qualification is pending.

## Native state-index proof groundwork (qualification pending)

The candidate native header/checkpoint state root now binds deterministic ordered coin/export/permanent-import trees, exact counts and minted/received counters. Typed leaves, level-bound branches, odd-node padding and empty trees have separate domains. A bounded membership path binds the exact key/value/index; nonmembership proves adjacent authenticated neighbors or an authenticated endpoint, never an unchecked gap. `state-proof`/`state-proof-check` use caller-selected exact checkpoint/collection/key, and the checkpoint must already be fully verified by native replay. A historical coin can be valid in its historical state after being spent; no proof reports current spendability or substitutes for import, incident, maturity, owner consent or value execution. Hashing counters alone does not prove conservation.

This changes consensus state roots and requires fresh signed fixture genesis/currency; prior candidates, private stores and balances do not migrate or qualify it. Full native evidence/history remains mandatory; generation still rebuilds complete bounded maps and is not incremental persistent indexing. The existing 4,096-entry indexes and all logical/storage/transport limits remain unchanged. Native focused/full tests of the first source pass, strict checks identified two retained code issues now corrected; final exact-source process/cycle/fault qualification remains pending. The 4,096-entry synthetic absence sample (2,683 bytes, 24 sibling hashes, complete synthetic state 860,228 bytes) measures map shape only, not actual long-history issuance. Stateful incremental indexes, compact complete dependency/value authority and beyond-era recovery remain required.

## Bounded native stream replay groundwork

`RLD-NATIVE-STREAM-REPLAY-V1` is a separate read-only archive verifier. It starts
with the caller-pinned, fully authenticated fresh fixture genesis and executes
every block through the same owner/value kernel as ordinary native chains.
There is no deserializable cursor or cached-ledger starting point. Its rolling
history retains at most 256 height/tip/history commitments, while the complete
coin/export/permanent-import maps retain their existing 4,096-entry bounds.
Exact local certificate observations are bounded by 64 and require full native
snapshot verification plus the exact replayed prefix. A hash does not confer
finality, import, signing or spendability rights. Invalid tails stage all fallible
checks before changing the ledger, history or anchor.

`history-stream-check --bootstrap GENESIS.json --region earth --file PRIVATE.jsonl
--expected-head EXACT_HEAD` checks a separately retained exact replay head.
Records are tagged Evidence, Block or Finalize; evidence replacement carries a
complete bounded proof set and receives full native verification. A private,
singly linked regular file is required; each complete newline-terminated record
is bounded by 8 MiB and the archive by the existing 256 MiB archive ceiling.
The reader allocates at most one bounded record at a time and never writes to
or adopts a node store. RESTORING targets refuse before the command runs.

The profile explicitly requires an initial unanimous PoW region. Local epoch
handoff and BFT replay refuse rather than lowering admission rules. Ordinary
stores, snapshot construction, BFT, wallets, signers and the 256-block/64-snapshot
limits remain unchanged. Incidents/quarantine are NOT reconciled by this
archive format; its CLI reports that fact. Passing replay is not a recovered
live ledger, a fresh finality certificate, independent latest-state protection
or restored signing custody. All-state/head rollback remains unqualified.
The changed native source requires a new signed no-value genesis/currency and
never migrates older candidates or adopted value.

The initial focused sample replays 1,032 real blocks with 1,024 actual-owner
local payments, a delayed return import of net 59, permanent duplicate-import
refusal and exact cold replay while retaining only 256 observations. This is
bounded replay groundwork, not ordinary-node long-history operation: new
long-range checkpoint authority, incremental durable indexes, real issuance-era
recovery beyond 200,000 blocks, independent archives, cryptographic horizons
and physical/independent qualification remain open. Final frozen whole-native,
process, command-line and new-source lifecycle checks are pending.

## Signed bounded checkpoint segments (local candidate)

`RLD-REGIONAL-SEGMENTED-UNANIMOUS-FIXTURE-V1` is a new explicitly signed
Admission profile, retaining four exact ordered unanimous validator approvals.
It cannot reinterpret a legacy or BFT region, change their thresholds, or
perform local epoch handoff. A snapshot's optional `base` must equal its signed
Statement.previous. Each new segment contains at most 256 complete native blocks;
its first parent/height/anchor must extend that exact already fully verified
certificate. The initial segment executes from the signed zero-allocation genesis.
Later state is copied only from the process's private fully native-executed
predecessor under the exact currency/admission trust binding. It is never decoded
from a ledger cache, supplied by a sender, or authorized by a content hash alone.
Every suffix still checks owner consent, maturity, issuance/conservation, export
finality, permanent imports, command/state roots, work and incident authority.

Ordinary Chain template/accept/install now retain only the bounded unfinalized
segment after this profile's certificate installation. Signed blocks and proofs
remain in the durable native journal; clearing a replay window never deletes
native evidence. Legacy and BFT chains keep their original full-prefix/256-block
behavior. BFT prospective messages refuse a segmented base. Signer journals pin
the preceding exact signed terminal and new segment's first parent/height, with
separate caller heads and existing vote/byte limits. Wallet/recipient queries
read historical blocks from the already fully native-replayed local journal;
absolute historical heights never index the shorter active segment. Incident
comparison uses overlapping absolute heights, avoiding a false conflict between
different compatible segments. Neither ancestry headers nor signatures alone
prove a valid ledger; full native execution remains mandatory.

The ordinary Journal still retains its original total event and 8-MiB limits,
evidence still retains at most 64 snapshots, permanent maps at most 4,096
entries, and the archive all retained objects at most 4,096 files / 256 MiB.
This new finality/remote-value representation breaks the compulsory whole-prefix
certificate dependency; it does not solve the whole persistent journal limit,
BFT long history, incremental durable permanent indexes or 200,000-block-era
recovery. Native stream replay V1 remains a separate read-only legacy-profile
verifier and does not adopt this profile. Complete incident-aware storage,
independent latest-state protection, custody, physical routes and independent
operations remain separate requirements.

## Paged ordinary event journals (new local candidate)

The explicitly admitted segmented unanimous profile now uses
`RLD-NATIVE-HISTORY-PAGED-EVENTS-V1`. A complete 16-event page becomes an
immutable predecessor-linked object; the journal retains its ordered exact
reference and fewer than 16 unsealed events. Manifest and journal commitments
bind this metadata and the exact tail. Open, commit, incident recovery and
ledger-only image verification stream every referenced complete page and run
ordinary native execution from the pinned signed genesis. No serialized ledger
or page hash supplies value, finality, owner or permanent-import authority.

This representation replaces the segmented profile's single complete event
vector. Legacy/BFT journals retain the V2 format, original 336 total-event
admission and full-prefix bounds; either storage/profile mismatch refuses
without conversion. The new page count is bounded by the existing 4,096-file
archive admission. Old partial tails and orphans remain counted within 256 MiB.
Every object, metadata journal, complete evidence and native payload retains
its 8-MiB bound; checkpoint count stays 64 and each active segment stays at most
256 blocks. Complete checkpoint evidence still remains in bounded memory.
This is not an unbounded history, BFT history upgrade, compact remote value
proof or 200,000-block-era implementation. Full cold replay CPU remains
proportional to the retained history, including complete proof verification.

Historical wallet and recipient queries use a fallible page iterator, propagating
read/validation failures instead of treating missing records as absent. A wallet's
signing-height replay advances one ordered block cursor across all retained
reviews. Complete previous blocks and exact Native-certified anchors still
execute normally; a changed tail cannot advance its anchor before verification.
Failed manifest publication retains journal.next and all immutable residue.
Existing external exact-head, incident guard and RESTORING/ARCHIVING policies
remain mandatory; independent latest-state and signing custody are separate.

New native source requires fresh signed zero-allocation no-value fixtures.
Earlier segmented stores and all older value/custody are retained, never
converted or migrated. Initial new-test compiler errors are retained in a
Native-source-only capture. A later finite test reached height 1,028 and cold
opened its ordinary store, but was deliberately stopped during repeated wallet
prefix lookups; it does not count as a completed wallet/value/recovery test.
Its exact Native source and private directory remain retained. Final tests for
the sequential wallet cursor and this source are pending.

## Incremental state-root and record-proof computation candidate

The native V1 ordered state commitment and record-proof dialect are unchanged.
One private process-local witness retains exact typed leaves and Merkle levels.
Every invocation audits the supplied complete ledger and compares every current
record. A leaf is reused only for the exact collection/key/value, and a branch
only for the exact collection/depth/ordered child pair. Counters and counts come
from the current audited ledger. Changed maturity, dependencies, ownership,
export fields or import identities rehash their affected paths. No decoded
witness or hash supplies native value state, authorization or freshness.

A missing/evicted witness reconstructs fully; it is never serialized. Accounting
for retained canonical values, fixed entry overhead and hashes stays at most
8 MiB, independent of original ledger/proof bounds. Optional retention exhaustion
clears the witness and reconstructs the exact original commitment/proof, without
pruning or new acceptance. This accounting is not a measured peak-RSS guarantee;
current/native ledgers and transient preparation remain separate allocations.
`Commitment::from_ledger_uncached` supplies an independent full reconstruction.

## Explicit BFT epoch fencing candidate

Long-lived native history also needs safe authority changes. The separate
`RLD-REGIONAL-BFT-UNANIMOUS-EPOCH-FIXTURE-V1` admission retains ordinary 3-of-4
BFT but enables an explicitly coordinated all-old/all-new activation certificate
at an exact fully native-replayed closing checkpoint. Its old signatures come
from durably fenced original BFT journals; any successor action prevents fencing
that older checkpoint. Fresh candidate approval journals cannot impersonate old
BFT signing locks. An incomplete ceremony retains permanently fenced journals;
there is no cancellation or timeout unsealing. All historic validator keys refuse
reuse, and new BFT journals initialize only at their exact activation boundary.

Native replay retains complete closing history, certificates and epoch proofs.
The change does not increase any snapshot/block/event/index/archive limits,
provide compact complete authority, or qualify the required beyond-200,000-block
history. This all-participant ceremony has no missing-signer or fault-tolerant
membership-change liveness; autonomous configuration changes and independent
custody remain separate obligations. Legacy profiles refuse unchanged. Local
focused checks pass; full frozen checks, actual process and publication are
pending and must remain bound to this changed source's fresh fixture currency.
