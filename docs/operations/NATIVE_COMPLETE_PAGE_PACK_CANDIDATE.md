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
