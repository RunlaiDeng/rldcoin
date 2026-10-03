# RLD-WIRE-V1 consensus wire profile (candidate)

Status: **candidate interoperability specification; Rust codec implemented,
runtime adoption partial and explicitly gated**.

This document freezes the first strict byte profile for independent second and
third implementations. It is deliberately narrower than a complete client: it
covers scalar consensus integers, domain context, payment signing messages,
proposal/vote signing messages, commit subjects, and value-risk update subjects.
It does not define networking, storage, state transition execution, validator
selection, signature aggregation, or a complete node.

The codec-only Prepare/Commit/Timeout/ViewChange extension is frozen separately
in [`CONSENSUS-ROUNDS.md`](CONSENSUS-ROUNDS.md) and
`vectors/wire-v1/consensus-rounds.json`. Its runtime, signature, quorum, and
state-machine adoption claims are all false.

Complete offline signed-member evidence for that extension is frozen in
[`CONSENSUS-CERTIFICATES.md`](CONSENSUS-CERTIFICATES.md) and
`vectors/wire-v1/consensus-certificates.json`. It independently verifies strict
Ed25519, historical membership, quorum and highest-QC selection, while keeping
runtime and state-machine adoption claims false.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are normative.

## 1. Runtime/adoption boundary

`rld-core` now contains a strict RLD-WIRE-V1 encoder/decoder and independently
recomputes the complete frozen vector bundle. Non-testnet
`ConsensusProposal`/`ConsensusVote` verification, `ConsensusCommit` identity,
and every `ConsensusCommand`/current `ProductionCommand` commitment are gated
onto this codec; testnet remains on the named legacy path. The API boundary
still accepts JSON, several uncovered object hashes still use hand-built bytes,
and persisted logical heights remain
`u64` (losslessly widened to wire `u128`). Passing these vectors therefore does
not prove that an implementation can join the network, and it does not close
the three-independent-client mainnet gate.

No implementation may claim complete RLD-WIRE-V1 runtime compatibility until
the remaining objects are deliberately migrated and cross-implementation
differential tests pass. The blocking differences are listed in
[`RUST-DIFFERENCES.md`](RUST-DIFFERENCES.md).

## 2. Primitive canonical model

The vector JSON is a diagnostic projection, not the signed wire format.

- Every unsigned integer in vector JSON MUST be a JSON string containing its
  shortest base-10 spelling: `0` or a non-zero ASCII digit followed by ASCII
  digits. A JSON number, sign, whitespace, exponent, decimal point, or leading
  zero is invalid.
- `u8`, `u16`, `u64`, and `u128` are unsigned fixed-width integers encoded in
  network byte order (big-endian) using exactly 1, 2, 8, and 16 bytes.
- `Amount` and every logical height are `u128`. Values outside
  `0..=340282366920938463463374607431768211455` are invalid. Small values still
  occupy all 16 bytes on the wire; those zero octets are fixed-width padding,
  not an alternative integer spelling.
- Hashes and Ed25519 public keys are exactly 32 raw bytes on the wire. Their JSON
  projection is exactly 64 lowercase hexadecimal characters.
- Text is strict UTF-8, MUST already be Unicode NFC, and MUST NOT contain C0 or
  C1 control characters (`U+0000..U+001F`, `U+007F..U+009F`). Normalization is a
  validation step; a decoder MUST NOT silently normalize and accept changed
  bytes.
- `network_domain` is exactly `rldcoin:mainnet:v1` or
  `rldcoin:testnet:v1`.
- A Zone id is lowercase ASCII `zone-` followed by exactly 20 hexadecimal
  characters. This profile carries the id; validating its self-certifying
  derivation against a Zone descriptor remains a state-layer requirement.
- General identifiers use `[A-Za-z0-9][A-Za-z0-9._:/-]*` and the per-field byte
  limit below. Recipients use `rld:<zone-id>:<64-lowercase-hex-key>`.
- The memo is the only unconstrained human text in this version and is limited
  to 512 UTF-8 bytes after the NFC check.
- JSON objects themselves MUST reject duplicate keys. Unknown JSON fields are
  rejected; they are not ignored.

## 3. Envelope and field encoding

Every object has this header:

| Offset | Width | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `RLDW` (`52 4c 44 57`) |
| 4 | 2 | wire version, `0x0001` |
| 6 | 2 | schema id |
| 8 | 2 | number of encoded fields |

Each field immediately follows as:

| Width | Meaning |
| ---: | --- |
| 2 | field id, big-endian |
| 1 | kind code |
| 4 | payload byte length, big-endian |
| variable | payload |

Field ids MUST be strictly increasing. Duplicate ids and reordered ids are
invalid. A decoder MUST consume exactly the declared field count and then reach
end-of-input. Truncation and trailing bytes are invalid. Version 1 treats every
unknown field id as critical and MUST reject it; there is no skippable-extension
range. A future extension therefore needs a new negotiated version or a later
specification that explicitly marks optional extension semantics.

Kind codes are:

| Code | Kind | Payload |
| ---: | --- | --- |
| `01` | TEXT | canonical UTF-8 bytes, no inner length |
| `02` | U8 | exactly 1 byte |
| `03` | U16 | exactly 2 bytes, big-endian |
| `04` | U64 | exactly 8 bytes, big-endian |
| `05` | U128 | exactly 16 bytes, big-endian |
| `06` | HASH32 | exactly 32 bytes |
| `07` | BYTES32 | exactly 32 bytes |
| `08` | HASH32_LIST | u16 count, then that many 32-byte hashes |
| `09` | BYTES | raw bytes; outer field length is authoritative |
| `0a` | BYTES32_LIST | u16 count, then that many 32-byte values |

A `HASH32_LIST` MUST be strictly lexicographically sorted by raw hash bytes and
MUST NOT contain duplicates. The field length must equal `2 + 32 * count`.
`BYTES32_LIST` has the same length and sorting rules but is a distinct kind so
public-key sets cannot be substituted for digest sets.

Required fields MUST occur exactly once. Optional fields are represented only
by omission; explicit null, empty placeholder fields, and presence bitmaps are
not alternatives. When an optional field is present, its ordinary canonical
rules still apply.

## 4. Domain separation and digests

For a signing schema, the exact Ed25519 message is:

```text
ASCII("RLD-SIGNATURE-PREIMAGE-V1") || 00 || canonical_wire
```

For a subject schema, the exact subject-hash preimage is:

```text
ASCII("RLD-SUBJECT-HASH-PREIMAGE-V1") || 00 || canonical_wire
```

The subject/digest is `SHA-256(preimage)`, represented externally as 64
lowercase hex characters. The `RLDW` envelope's schema id supplies the
object-specific part of the domain. Changing the purpose prefix or schema id is
a signature-domain substitution and MUST fail; an implementation MUST NOT retry
under another domain.

Signature bytes and quorum certificates are not fields of their own signing or
subject message. Signature verification is outside the standard-library
verifier in this first release; the verifier checks the complete precomputed
message and SHA-256 digest. Implementations adding Ed25519 verification MUST
verify exactly the bytes above and MUST reject non-canonical public keys or
signatures before state transition processing.

## 5. Schemas

Notation: `id name:kind [R|O]`; `R` is required and `O` is optional. Field order
shown is the only wire order.

### `0001` Amount — subject

`1 value:U128 R`

### `0002` LogicalHeight — subject

`1 value:U128 R`

### `0100` ZoneDomainContext — subject

1. `network_domain:TEXT R` (64 bytes)
2. `zone_id:TEXT R` (64 bytes)
3. `currency_genesis_root:HASH32 R`
4. `protocol_era:U64 R`
5. `crypto_era:U64 R`

### `0201` PaymentRequest — signature

1. `network_domain:TEXT R` (64)
2. `request_id:TEXT R` (identifier, 128)
3. `recipient:TEXT R` (recipient, 160)
4. `recipient_public_key:BYTES32 R`
5. `destination_zone:TEXT R` (Zone, 64)
6. `currency_genesis_root:HASH32 R`
7. `protocol_era:U64 R`
8. `crypto_era:U64 R`
9. `amount:U128 R` (non-zero)
10. `memo:TEXT R` (memo, 512)
11. `expires_at_height:U128 R`
12. `nonce:U64 R`

`recipient` MUST equal
`rld:<destination_zone>:<recipient_public_key-lowercase-hex>`.

### `0202` UniversalPaymentIntent — signature

1. `network_domain:TEXT R` (64)
2. `payment_id:TEXT R` (identifier, 128)
3. `source_zone:TEXT R` (Zone, 64)
4. `destination_zone:TEXT R` (Zone, 64)
5. `currency_genesis_root:HASH32 R`
6. `protocol_era:U64 R`
7. `crypto_era:U64 R`
8. `pricing_epoch:U64 R`
9. `sender_public_key:BYTES32 R`
10. `recipient:TEXT R` (recipient, 160)
11. `coin_id:TEXT R` (identifier, 128)
12. `amount:U128 R` (non-zero)
13. `max_fee:U128 R`
14. `nonce:U64 R`
15. `payment_request_id:TEXT O` (identifier, 128)
16. `payment_request_hash:HASH32 O`
17. `route_quote_id:TEXT O` (identifier, 128)

Fields 15 and 16 MUST be both absent or both present. The hash is the RLD-WIRE-V1
`PaymentRequest` digest from section 4, not a hash of JSON or of a signature.
The recipient Zone MUST equal `destination_zone`.

### `0301` ConsensusProposal — signature

1. `network_domain:TEXT R` (64)
2. `proposal_id:TEXT R` (identifier, 128)
3. `zone_id:TEXT R` (Zone, 64)
4. `currency_genesis_root:HASH32 R`
5. `protocol_era:U64 R`
6. `crypto_era:U64 R`
7. `parent_height:U128 R`
8. `parent_state_root:HASH32 R`
9. `round:U64 R`
10. `proposer_public_key:BYTES32 R`
11. `command_hash:HASH32 R`
12. `expected_height:U128 R`
13. `expected_state_root:HASH32 R`

`expected_height` MUST equal `parent_height + 1`; overflow is invalid. The
command body is not duplicated here. Its separately specified canonical command
hash is the commitment.

### `0302` ConsensusVote — signature

1. `network_domain:TEXT R` (64)
2. `proposal_id:TEXT R` (identifier, 128)
3. `proposal_hash:HASH32 R`
4. `zone_id:TEXT R` (Zone, 64)
5. `currency_genesis_root:HASH32 R`
6. `protocol_era:U64 R`
7. `crypto_era:U64 R`
8. `parent_height:U128 R`
9. `parent_state_root:HASH32 R`
10. `round:U64 R`
11. `expected_state_root:HASH32 R`
12. `voter_public_key:BYTES32 R`

State validation MUST also compare every proposal-bound value with the referenced
proposal. Wire conformance alone cannot establish that relationship.

### `0303` ConsensusCommit — subject

1. `network_domain:TEXT R` (64)
2. `zone_id:TEXT R` (Zone, 64)
3. `currency_genesis_root:HASH32 R`
4. `protocol_era:U64 R`
5. `crypto_era:U64 R`
6. `proposal_hash:HASH32 R`
7. `expected_height:U128 R`
8. `expected_state_root:HASH32 R`
9. `vote_hashes:HASH32_LIST R`

Each vote hash is the RLD-WIRE-V1 `ConsensusVote` digest. The canonical sorted
set makes commit identity independent of arrival order while binding the actual
certificate members. Quorum membership and threshold validation are state-layer
requirements.

### `0401` ValueRiskPolicyUpdate — subject

1. `network_domain:TEXT R` (64)
2. `update_id:TEXT R` (identifier, 128)
3. `zone_id:TEXT R` (Zone, 64)
4. `currency_genesis_root:HASH32 R`
5. `protocol_era:U64 R`
6. `crypto_era:U64 R`
7. `policy_version:U16 R`
8. `previous_policy_sequence:U64 R`
9. `from_cap:U8 R` (`0..3`)
10. `to_cap:U8 R` (`0..3`)
11. `max_single_transfer:U128 R`
12. `max_local_value_total:U128 R`
13. `max_cross_zone_exposure:U128 R`
14. `max_dsc_exposure:U128 R`
15. `safety_case_hash:HASH32 R`
16. `safety_case_valid_until_height:U128 R`
17. `proposed_height:U128 R`
18. `activate_after_height:U128 R`
19. `expires_at_height:U128 R`
20. `nonce:U64 R`

This profile requires `proposed_height < activate_after_height <=
expires_at_height` and `safety_case_valid_until_height >=
activate_after_height`. Policy-specific minimum delays, monotonicity, quorum
membership, and exposure-limit rules remain state-layer checks. The update's
stored `subject_hash` and quorum certificates are derived metadata and are not
recursively included in its subject.

### `0500` CommandCommitment — subject

1. `network_domain:TEXT R` (64)
2. `consensus_tag:U16 R`
3. `production_tag:U16 O`
4. `payload:BYTES R` (maximum 1 MiB)

The complete command tag, value grammar, enum, struct, and field registry is
normatively specified in [`COMMANDS.md`](COMMANDS.md). `production_tag` is
present exactly for consensus tag 7. Only activation tag 6 has an empty
payload. No JSON serialization is part of this subject.

## 6. Context validation is mandatory

Canonical decoding is necessary but insufficient. Before signature or subject
acceptance, a verifier MUST compare the embedded `network_domain`, Zone,
`currency_genesis_root`, `protocol_era`, and `crypto_era` with its trusted local
context. Payment intents MUST additionally validate their destination Zone.
Cross-network, wrong-Zone, wrong-genesis, and wrong-era objects are rejected even
when their bytes and cryptographic signature are otherwise valid.

The context is supplied out of band in the vectors to make this distinction
testable. A decoder MUST NOT fill absent context fields from local state: all
domain fields in these schemas are required and signed/hashed.

## 7. Rejection rules

A conforming decoder fails closed on, at minimum: bad magic/version/schema;
wrong kind or fixed width; missing, duplicate, reordered, or unknown fields;
invalid UTF-8/NFC/control characters; invalid string grammar; non-canonical JSON
numbers or hex; overflow; malformed optional pairs or lists; truncation;
trailing bytes; purpose/schema substitution; and trusted-context mismatch.

There is no permissive compatibility mode in this specification. Legacy objects
must be handled by an explicitly separate protocol/version and must never be
silently reinterpreted as RLD-WIRE-V1.

## 8. Conformance artifacts

The original frozen bundle is
[`vectors/wire-v1/vectors.json`](../../vectors/wire-v1/vectors.json). The
separate adopted command bundle is
[`vectors/wire-v1/commands.json`](../../vectors/wire-v1/commands.json); adding it
does not rewrite the original 31 vectors.
The R6.15 resource reservation is separately frozen in
[`vectors/wire-v1/stake-state-resource-v1.json`](../../vectors/wire-v1/stake-state-resource-v1.json)
and `docs/R6.15_STAKE_STATE_RESOURCE_RESPONSIBILITY_CANDIDATE.md`. R6.17 adopts
tags 18/19 for delayed dual-QC policy governance. R6.18 separately adopts tag 20
and schema `1041` for candidate registration. R6.19 appends tag 21/schema `1042`
for resource-bound position creation and tag 22/schema `1043` for exact legacy
position migration. R6.20 appends tag 23/schema `1044` for exact legacy-candidate
migration and tag 24/schema `1045` for resource-bound derivation-v2 Epoch
retention; all derive usage internally and reuse the `1039` sponsor envelope
plus `103e..1040` V2 accounting records. R6.21A appends tag 25/schema `1046`
for exact append-only bond renewal and schema `1047` for its immutable history
segment; usage is internal and each segment consumes a fresh sponsor Coin and
authorization. Unbond, slash-evidence and settlement resource schemas remain
non-routable.
The separate `vectors/stake-resource-accounting-v1/vectors.json` corpus covers
the engine and independently frozen candidate, position, migration, Epoch and
renewal persistent footprints.
Each case is addressed by SHA-256 of its canonical JSON body, and the bundle
payload has its own SHA-256 address. The standard-library verifier checks the
addresses, exact bytes, preimages, digests, accept cases, and expected rejection
codes. See [`tools/independent-verifier/README.md`](../../tools/independent-verifier/README.md)
for the CI command and audit boundary.
