# SlashEvidenceArchiveObjectV1 and ManifestV1

Status: **FROZEN CODEC CANDIDATE / RUNTIME DISABLED / VALUE_CAP_0**

This specification freezes a bounded, content-addressed transport and recovery
codec for the complete R6.14 slash evidence already retained in authoritative
ledger state. It does not authorize pruning, activate an archive service, prove
availability, change consensus, or make an archive operator authoritative.

## 1. Common envelope

Both structures use this header followed by exactly `field_count` fields:

```text
magic          4 bytes   "RLDA"
codec_version  u16be     1
schema_id      u16be     1 = object, 2 = manifest
field_count    u16be
field          repeated: field_id:u16be, kind:u8, length:u32be, payload
```

Fields are strictly increasing, unique and all required. Unknown fields,
unknown kinds, unknown codec/schema versions, missing fields, trailing bytes,
non-minimal fixed-width values and invalid UTF-8 fail closed. Text is NFC,
non-empty, has no leading/trailing whitespace and obeys its field limit.

Kinds are `1 TEXT`, `2 U8`, `3 U16`, `4 U64`, `5 U128`, `6 HASH32`,
`7 KEY32`, and `8 BYTES`. Integer and fixed-width kinds have lengths 1, 2, 8,
16 and 32 respectively.

Limits are checked from the outer byte length and each field header before a
payload is copied or parsed:

- archive object: at most 1,048,576 bytes;
- canonical evidence: 1 through 524,288 bytes;
- manifest: at most 8,388,608 bytes;
- entries per manifest: 1 through 4,096;
- slash ID and position ID: at most 128 bytes;
- network, Zone and storage profile: at most 128 bytes.

## 2. SlashEvidenceArchiveObjectV1 (`schema_id = 1`)

| ID | field | kind |
|---:|---|---:|
| 1 | schema_version (`1`) | U16 |
| 2 | network_domain | TEXT |
| 3 | zone_id | TEXT |
| 4 | currency_genesis_root | HASH32 |
| 5 | protocol_era | U64 |
| 6 | crypto_era | U64 |
| 7 | slash_id | TEXT |
| 8 | slash_record_hash | HASH32 |
| 9 | evidence_kind (`1` double sign, `2` conflicting checkpoint, `3` invalid state commitment) | U8 |
| 10 | evidence_hash | HASH32 |
| 11 | canonical_evidence_bytes | BYTES |
| 12 | consensus_epoch | U64 |
| 13 | derived_epoch_record_hash | HASH32 |
| 14 | liability_commitment | HASH32 |
| 15 | position_id | TEXT |
| 16 | historical_validator_public_key | KEY32 |
| 17 | historical_validator_key_era | U64 |
| 18 | fault_height | U128 |
| 19 | applied_height | U128 |
| 20 | checkpoint_height | U128 |
| 21 | checkpoint_state_root | HASH32 |
| 22 | checkpoint_certificate_hash | HASH32 |
| 23 | evidence_liability_nullifier | HASH32 |
| 24 | object_length | U64 |
| 25 | object_hash | HASH32 |

`canonical_evidence_bytes` is canonical UTF-8 JSON for the complete
`ConsensusStakeSlashEvidenceV1`: object keys sorted by UTF-8 bytes, no
insignificant whitespace, no duplicate keys, NFC strings, JSON booleans/null
only where the evidence schema permits them, and no terminal newline. Archive
codec verification checks canonical JSON and fixed-shape evidence presence. It
does not independently derive field 10 or field 8 from signatures and the
historical Epoch/liability. Recovery admission must run the complete R6.14
verifier again and require its derived `evidence_hash`, slash-record hash and
all contextual fields to equal the object before the bytes are trusted.

`fault_height <= applied_height <= checkpoint_height` is required. The
nullifier is the existing R6.14 value:

```text
hash_parts(
  "RLD-CONSENSUS-STAKE-SLASH-NULLIFIER-V1",
  lowercase_hex(evidence_hash),
  lowercase_hex(liability_commitment)
)
```

where `hash_parts` prefixes every part with its `u64be` byte length.

`object_length` equals the complete encoded object length. Because its width
and the final hash field width are fixed, it is calculated before hashing.
`object_hash` is:

```text
SHA-256("RLD-SLASH-EVIDENCE-ARCHIVE-OBJECT-V1\0" ||
        exact RLDA bytes from the header through field 24)
```

The header in that preimage declares all 25 fields. Field 25 is then appended.

## 3. SlashEvidenceArchiveManifestV1 (`schema_id = 2`)

| ID | field | kind |
|---:|---|---:|
| 1 | schema_version (`1`) | U16 |
| 2 | archive_generation (nonzero) | U64 |
| 3 | previous_manifest_hash (zero only for generation 1) | HASH32 |
| 4 | first_checkpoint_height | U128 |
| 5 | last_checkpoint_height | U128 |
| 6 | ordered_entries | BYTES |
| 7 | total_object_count | U64 |
| 8 | total_canonical_bytes | U128 |
| 9 | replica_or_erasure_profile | TEXT |
| 10 | crypto_era | U64 |
| 11 | created_at_logical_height | U128 |
| 12 | manifest_length | U64 |
| 13 | manifest_hash | HASH32 |

`ordered_entries` is:

```text
"RLDE" || version:u16be(1) || count:u32be || entries...

entry = checkpoint_height:u128be
        slash_id_length:u16be || slash_id:utf8
        liability_commitment:32
        object_hash:32
        object_length:u64be
        checkpoint_state_root:32
        evidence_liability_nullifier:32
```

Entries are strictly ordered by `(checkpoint_height, slash_id UTF-8 bytes,
liability_commitment bytes)`. Object hashes, slash IDs and nullifiers are each
unique. Counts, total bytes, first/last checkpoint and every entry field must
match the supplied archive objects during recovery verification.

Generation 1 uses the all-zero predecessor. A successor increments generation
by exactly one, names the exact predecessor manifest hash and preserves the
predecessor entry sequence as an exact prefix; it may only append entries.
Changing media/profile or Crypto Era does not permit rewriting that prefix.

`manifest_length` and `manifest_hash` follow the same rule as the object:

```text
SHA-256("RLD-SLASH-EVIDENCE-ARCHIVE-MANIFEST-V1\0" ||
        exact RLDA bytes from the header through field 12)
```

The header declares all 13 fields.

## 4. Explicit non-claims

The codec and its vectors claim only deterministic encoding, bounded decoding,
content identity, object/manifest closure and append-only chain validation.
They do not claim R6.14 semantic re-verification, runtime integration, deployed
replicas, availability, recovery drills, mainnet readiness, dynamic membership,
evidence pruning or a value cap above `VALUE_CAP_0`. Full evidence remains in
authoritative R6.14 ledger/checkpoint/audit state.
