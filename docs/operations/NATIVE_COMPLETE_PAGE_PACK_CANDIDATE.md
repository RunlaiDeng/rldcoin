# Complete Native page packing candidate

`tools/regional-ledger/src/retained_pages/packed.rs` is a separate bounded codec
for complete immutable page bytes. Existing flat stream formats, recovery rules,
signed admissions, 16-record pages and file/byte ceilings remain unchanged.
Neither existing stores nor signed profiles adopt this representation automatically.
A container hash is integrity metadata; every original record still requires
Native signature, ledger, signer-lock, finality and permanent-import replay.

A pack contains 1–64 full canonical pages. Each inner page retains its original
format, scope, first record position, exact predecessor hash and all 16 original
records. The pack remains at most 8 MiB. Count and aggregate byte checks precede
encoding; a full page that cannot fit is refused, never truncated or summarized.

The independently selected caller context supplies the complete Native scope,
first record position, previous original page hash and previous pack hash. The
first position is a multiple of 16. Both predecessors are absent only at position
zero. For verification, the caller also supplies an independently retained exact
complete pack reference with SHA-256 and byte length. Incoming bytes cannot choose
any of those anchors. Canonical wire layout is:

```
RLD-NATIVE-COMPLETE-PAGE-PACK-CANDIDATE-V1\0
scope_commitment[32] || first_record[u64 BE]
|| previous_pack[canonical optional hash] || previous_page[canonical optional hash]
|| page_count[u16 BE]
repeated: complete_page_size[u32 BE] || exact_complete_page_bytes
```

An optional hash is one byte `0` for absence, or byte `1` followed by the full
32-byte hash; other encodings refuse. The scope commitment uses the existing
canonical Native hash interface with domain
`complete-page-pack-candidate-scope-v1` and the complete scope. The outer reference
uses SHA-256 over the whole pack. No trailing bytes are permitted.

The decoder verifies the complete outer reference before reading frames, then
checks every typed inner page's canonical encoding, scope, first position,
predecessor and full record count. Only after the whole pack succeeds does it
return an integrity description. Corruption, reordering, skipped pages, wrong
scope/predecessors, counter overflow and capacity excess return no partial result.

Packing addresses representation overhead, not retention funding or authority.
Durable packed manifests, orphan/residue accounting, an authenticated storage
profile, ordinary ledger/signer integration and complete cold Native replay are
still required. Larger file collections cannot bypass the existing 4,096-file /
256-MiB complete archive ceiling. The flat profile's long-history capacity failure
remains a failure; synthetic container records are not signed long-history blocks.

## Immutable private archive interface

`retained_pages/packed/archive.rs` supplies a separate `PackedArchiveCandidate<T>`
with `seal`, `open` and complete ordered `visit` interfaces. It accepts only a
fresh absent target and caller-supplied complete canonical pages. It does not
copy, convert or recover a private Native stream. The same original record-head
function commits each typed record in order from the independently selected
scope's origin. The caller supplies the expected ending head separately.

A seal creates an owned private directory and OS lock, then durably retains an
`ARCHIVING` marker before object publication. Complete packs are written without
replacement and synced before the final canonical `packed.json` manifest. The
marker is removed and the directory synced only after the full manifest and
expected ending head agree. An interruption, missing input or wrong ending head
leaves the marked target and all original residue; ordinary open and another seal
refuse. There is no implicit resume, repair, overwrite or discarded partial tail.

The manifest binds the exact scope, ordered complete pack references, total record
count and record head. Every cold open checks the independent scope/head and
streams all original typed records. A held object rechecks its canonical disk
manifest, all pack references and the complete count/head before successful
completion. Consumers must stage their semantic state until the whole call returns
success. Storage verification alone cannot initialize a Native ledger or signer.

Every retained object, orphan, marker, lock and manifest counts toward the original
4,096-file / 256-MiB complete archive ceiling. Each object and manifest remains at
most 8 MiB. Capacity admission reserves the complete future manifest before
publishing another pack. Unsafe names, symlinks, links, ownership/mode drift,
oversized objects, missing packs and altered manifests refuse; residues cannot be
hidden behind an index. Sealed source data stays immutable under the held lock.

This immutable archive does not implement ordinary incremental appends, signature
custody or an adopted Native profile. It does not establish independent rollback
protection, financial retention reserves, power-loss durability or long-history
value execution. Those requirements remain separate from byte retention and cold
integrity checks.

## Read-only Native inspection

`storage::inspect_packed_native_candidate` independently authenticates the
complete bootstrap against the caller's authority and currency pins, derives
the exact Native stream scope, and executes every complete typed record from
Native genesis. The caller separately supplies both the complete latest storage
head and `PackedNativeBoundaryCandidate`: currency, region, height, finalized
statement, epoch, ledger root and record count. A valid older archive cannot
satisfy a different independently retained latest boundary.

The result is a description of the fully executed state, returned only after the
whole archive and exact ending Native boundary match. It cannot initialize a
Store, ledger, signature lock or caller head. Each certified block, complete
certificate, owner command and evidence/receipt/contact event executes through
the existing Native replay path. A hash-consistent archive with an invalid inner
signature returns no boundary and does not rewrite retained bytes. Cold reads
require the independently pinned complete inputs again.

The bounded body witness resolver supports both original flat streams and this
immutable archive. It can reread an evicted identity only from the exact prefix
already Native-executed in the current invocation; the complete current archive
must still verify. Neither a retained record nor a matching external body hash
can claim that a future record already executed.

This inspection has no Store-side incident proof directory or safety guard. It
refuses nonempty incident-index records rather than treating unauthenticated IDs
as retained proofs. A future ordinary Store integration must authenticate those
complete proofs and account for all external Store files under the same complete
archive ceiling. Incremental appends, signer custody, adopted profiles, permanent
import composition, rollback protection and long-history qualification remain
separate requirements.

## Bounded lossless complete packs

`packed::lossless` provides a separate byte representation of a complete original
canonical pack. Existing archives do not adopt it. Encoding first checks the
complete original typed pack against the caller's scope, offset, predecessors
and independently retained original reference. Every original page byte, full
certificate and command remains recoverable without alteration or omission.

The fixed frame is:

```
RLD-NATIVE-LOSSLESS-COMPLETE-PACK-CANDIDATE-V1\0
codec[1 byte = 1] || original_length[u32 BE] || original_SHA256[32]
|| complete_raw_DEFLATE_stream
```

Codec 1 fixes `miniz_oxide` 0.8.9 at level 6. The caller supplies both complete
encoded and original references independently. The decoder authenticates the
whole encoded object before parsing or allocating an output buffer. It requires
the exact separately retained original length and digest, allocates that fixed
length, and accepts only a completed stream consuming every input byte and
producing exactly that length. A fixed-codec re-encoding must match the complete
compressed stream. Unknown codecs, alternative encodings, trailing bytes,
truncation, excessive expansion and reference mismatches refuse.

Both encoded and decoded complete objects remain at most 8 MiB. The recovered
original digest and complete typed page structure verify before any bytes are
returned. The result supplies exact original bytes and an integrity description,
never ledger state, custody or signing authority. Native execution still begins
at independently pinned genesis and must match the complete latest caller
boundary. A decoded object cannot initialize a ledger from a snapshot.

Lossless representation does not establish a whole-history compression ratio,
CPU/RAM/recovery budget or retention funding. The immutable compressed archive uses its own explicit format and complete
residue accounting. Ordinary appends still require Native integration under the
unchanged 4,096-file / 256-MiB physical archive ceiling. No old private archive is converted or implicitly reinterpreted.
Independent security review, new cryptographic adoption and long-history value
qualification remain separate gates.


## Immutable lossless archive and Native cold inspection

`PackedArchiveCandidate::seal_lossless_candidate` seals only a fresh absent
owned private target. The separate format is
`RLD-NATIVE-IMMUTABLE-LOSSLESS-PACKED-ARCHIVE-CANDIDATE-V1`. Its canonical manifest
retains the complete scope, ordered encoded pack references, aligned
`original_packs` references, complete record count and logical record head.
Each original reference binds the exact bounded decoded pack bytes. The original
page predecessor hashes and every original record commitment remain unchanged;
pack predecessor hashes bind the actual retained encoded objects.

A caller retains `manifest_reference_candidate()` after successful local sealing.
`open_lossless_candidate` requires this independently retained complete manifest
reference as well as the scope and latest logical head. It authenticates the whole
manifest before parsing its references or inflating any retained object. The
original `open` accepts the raw format only and refuses a compressed archive.
The lossless entry likewise refuses the raw format; there is no format sniffing,
automatic conversion or fallback.

`storage::inspect_lossless_packed_native_candidate` separately requires the
complete current manifest reference, storage head and ending Native boundary,
along with authority/currency pins and complete signed bootstrap. It executes all
original records from pinned genesis using the same process-local executed-prefix
resolver. It returns an inspection boundary only after full compressed integrity,
complete Native signature/value replay and the independent ending boundary match.
No result can initialize an ordinary Store, signature lock or caller head.

Sealing durably marks the new target before publishing complete encoded packs
and reserves the complete future manifest before each publication. The marker is
removed only after the independently expected complete logical head matches and
the canonical manifest is durably published. Interruptions, wrong ending heads
and missing input keep all marked residue; another seal and ordinary open refuse.
Every encoded object, original decoded object and manifest remains at most 8 MiB.
All retained physical objects, orphans, locks, markers and manifests count under
the unchanged 4,096-file / 256-MiB ceiling. Reference misalignment, altered bytes,
missing objects and lock conflicts refuse; no records are pruned for compression.

This is immutable read-only retention and inspection. Incremental append,
complete Store-side incident proofs and accounting, signer custody, independent
freshness witnesses, storage funding and long-history value recovery still need
implementation and their own qualification. A peer-selected manifest reference
is not an independently current anchor. Compression does not make those adoption
requirements optional.


## One-pass fresh lossless construction

`LosslessArchiveWriterCandidate::begin` owns an absent private target under its
OS lock and creates the durable `ARCHIVING` marker. `retain_complete_page`
accepts only the next exact canonical original sixteen-record page in the same
scope. It checks the incoming page before publishing a preceding group. A group
contains at most 64 pages; its encoded original-pack size remains at most 8 MiB.
Complete packs are durably retained as generation progresses. This removes the
need to keep the whole history's page bytes or an unbounded raw scratch archive.
Encoding, decoding and compression still use bounded object buffers; 8 MiB is
an object/group bound, not a claim that the entire process uses only 8 MiB RAM.

A failed retain permanently poisons the writer. Dropping it, an interrupted
finish, a capacity refusal or a wrong ending head leaves the marked target and
all durable residue. Neither another writer nor an ordinary open can resume it.
Every physical object and the complete future manifest still count under the
original archive limits. No incomplete records are made authoritative.

`finish(independently_expected_head)` consumes the writer and requires the
producer's separately computed complete ending record head. The producer must
execute Native records itself and retain its own latest Native boundary; a
writer hash never supplies ledger authority. Successful construction emits the
same lossless manifest and object format as the immutable seal entry. Cold opens
still require its separately retained complete manifest reference, scope and
head; Native inspection still replays from independently pinned signed genesis.
This API constructs a fresh immutable archive. It grants no existing-store
append, recovery, signer custody or network adoption rights.


## Complete prefix and atomic continuation

`storage::NativeContinuationCandidate` composes a locked immutable lossless
prefix with a fresh complete-record `Stream` tail. It verifies the prefix from
independently pinned signed genesis before creating the tail. The tail's origin
binds the complete prefix manifest reference, prefix logical head and Native
ending boundary in `native-lossless-prefix-continuation-origin-v1`.
A tail inside the prefix is forbidden. Prefix bytes never change.

`NativePrefixPinsCandidate` and `NativeContinuationPinsCandidate` describe
caller-retained anchors. They have no deserialized Native state. Opening requires
the prefix anchors, tail head, complete ordered record head and full latest
Native boundary. Verification executes prefix then tail from genesis, checking
both the prefix boundary and ending boundary before returning. A tail hash is
not a Native predecessor or an independent freshness witness.

`append_certified` requires exact caller-current anchors and unchanged complete
prefix/tail bytes. It executes the supplied complete certificate through the
existing Native kernel on a staged clone of this process's actually verified
Native execution. That state originates only in full genesis replay and successful
prior durable appends; no decoded cache or peer-selected ledger initializes it. It uses
the original stream's durable pending/page/manifest transaction. Only successful
publication returns new caller anchors. A persistence failure makes the handle
unusable, and pending targets refuse cold open and recreation. Signature or
caller-anchor failures do not publish a partial record or Native boundary.

The two owned directories share one 4,096-file / 256-MiB ceiling, including all
orphans, locks, pending files and complete future transaction payloads. They do
not each receive another allowance. Every retained object remains bounded by
8 MiB. Complete incident proofs, normal Store metadata and signer/caller custody
are not part of this entry; nonempty incident identifiers refuse.

The live handle retains only process-local Native execution. Opening and
inspection still execute the complete source from pinned genesis. Before a live
append, every encoded prefix object's digest and length must match the complete
references already verified in this invocation; the canonical manifest must be
unchanged. Tail structure, bytes and current head verify through the original
stream. A hash check alone cannot create Native state or authenticate new
semantics. All new signatures and carried block commands still execute natively.
The staged Native state and executed-prefix commitment replace the committed
process state only after durable tail publication. Failed semantics or persistence
cannot advance it. This avoids repeating historical Native execution for each new
record while retaining full source byte checks; total I/O still grows with storage.
Continuation rotation, general event interfaces, complete incident integration,
large live-node service costs and ordinary-node/signing/recovery adoption remain
distinct work. No old private archive is converted or resumed.


## Native proposal and public coin interfaces

A continuation handle's `template` checks exact caller-current anchors and all
retained source bytes before constructing an unsigned block through normal Native
execution. Owner signatures, input existence, maturity, balances and fees must
verify before return. Mining and validator signing remain caller responsibilities;
template construction changes neither retained records nor the committed ledger.
The returned BFT context binds the actual current finalized parent, height, block,
state and epoch, rather than a caller-supplied state description.

`snapshot_for_certificate` accepts an actually mined block and complete configured
prepare/commit certificate. It verifies the block, commands, current parent and
every vote, then stages the resulting complete original snapshot through Native
replay. Invalid work, substituted commands, unknown keys, incorrect phases, parent
mismatches and insufficient votes refuse without publication. The caller must
separately invoke `append_certified` for durable acceptance. Construction grants
no signature lock or signer custody.

`coins` returns public coin identifiers, payments and explicit maturity from the
exact actually executed process state. It is not a private wallet reservation
view. Local payment outputs follow the existing local-payment rule; issuance
rewards and fees retain the configured reward maturity. Imported payments require
their separate Native import rules. No caller can select earlier anchors to bypass
these checks. Cold opening still executes every retained original record from
signed genesis and checks independently retained current anchors. These interfaces
do not adopt a new ordinary-node profile or supply signer/recovery authority.


## Fresh authenticated genesis prefix

`NativeContinuationCandidate::create_genesis_prefix` accepts a complete signed
bootstrap and independently supplied authority, currency and region. Native trust,
explicit signed paged profile and actual empty genesis ledger verify before any
target creation. It seals an empty lossless archive whose logical head is the
Native scope origin and returns its complete manifest reference and actual genesis
boundary. Invalid pins, signatures or region selection cannot create a prefix.
The target must be absent under an existing private parent; existing or marked
targets refuse without conversion or recovery.

An empty prefix is valid only when its independently retained boundary exactly
matches Native genesis. Creation and cold opening check that boundary before
executing any tail records, then use the same original atomic append transaction,
complete certificates, reward maturity, capacity and caller-current guards as
nonempty prefixes. A returned genesis boundary cannot initialize state from a
serialized ledger. The caller retains the complete bootstrap and current anchors
separately. This entry is restricted by the authenticated no-value fixture currency;
it neither migrates prior balances nor starts a production network. Ordinary node
lifecycle, signer custody and independent rollback protection remain separate.


## Complete incoming evidence and Native import

`append_evidence` uses the same guarded original atomic tail transaction as local
certificates. The complete bounded incoming sequence must authenticate and execute
on a staged clone of the actual process state before any bytes or new anchors
are published. Missing or reversed predecessors, invalid votes, substituted block
commands and oversized sequences refuse the whole event, including any valid
prefix that preceded the invalid item. The committed ledger and tail remain
unchanged on semantic refusal. Persistence failure poisons the handle and retains
all residue under the existing non-resume rules.

Evidence acceptance changes no local height, balance or maturity. A separate
locally certified Native import must reference the actual verified source export.
The source owner signature, export amount, destination fee, destination admission
and complete predecessor sequence remain authoritative. Imported recipient and
fee coins retain configured import maturity; onward spending preserves their
source dependencies. The existing permanent import tombstone rejects another
import both before and after recipient spending. Current native map capacities
and retention limits remain unchanged.

Cold opening authenticates and replays complete foreign evidence in its original
record order before executing dependent local imports and payments. A destination
receipt, an accepted evidence event or a storage hash grants no value on its own.
This interface does not implement transport, complete incident proofs, ordinary
node lifecycle, signer custody, independent freshness or new cryptographic
adoption. Those interfaces require separate composition and qualification.
