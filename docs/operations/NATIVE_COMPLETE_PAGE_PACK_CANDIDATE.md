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
