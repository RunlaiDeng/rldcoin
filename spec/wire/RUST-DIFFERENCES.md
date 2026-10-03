# Rust runtime versus RLD-WIRE-V1

Status updated after the first Rust codec slice. This is a migration/blocker
register, not a compatibility promise.

Implemented: the strict Rust TLV codec passes all 31 original frozen vectors
without calling Python; non-testnet proposal/vote verification, commit identity,
and all current consensus/production command commitments use RLD-WIRE-V1 with
exact-record-only legacy reads. The separate command bundle covers all 7
consensus and 30 production tags. Testnet remains legacy.

The separate `consensus-rounds.json` bundle adds 43 codec-only vectors for
`ConsensusValidatorSet`, `TimeoutVote/Certificate`, independent
`PrepareVote/Certificate`, independent `CommitVote/Certificate`, and
`ViewChangeProposal`. Rust and the standard-library Python verifier agree on
the bytes and object-local rejection rules. No node, signer, witness, WAL, or
network route consumes these new schemas, and all non-zero-round runtime guards
remain active.

The separate `consensus-certificates.json` bundle adds 24 offline evidence
cases. A Go standard-library implementation independently verifies strict pure
Ed25519, historical sets, exact evidence closure, locally computed quorum,
Prepare-to-Commit linkage and highest-QC selection; Rust independently
recomputes all accepted closures and the non-canonical scalar rejection. This
does not alter the runtime guard or supply persistent consensus state.

## Mainnet blockers

| Area | Current Rust behavior | RLD-WIRE-V1 requirement | Disposition |
| --- | --- | --- | --- |
| Explicit network domain | Rust structs still do not store the field. The new non-testnet proposal/vote/commit adapters require the trusted Zone descriptor's network domain and place it in the signed/hashed wire bytes. Payment and value-risk runtime paths remain legacy. | Every covered object carries the exact network domain in its signed/hashed bytes. | **PARTIAL.** Consensus slice complete; payment/value-risk adoption remains a **BLOCKER**. No fallback occurs after V1 verification starts. |
| Logical height width | Proposal, vote, payment expiry, policy windows, ledger height, and related checks use `u64`. | Every logical height is fixed-width big-endian `u128`. | **BLOCKER.** Requires a state/schema migration and overflow review, not only a serializer change. |
| Wire framing | A strict `rld-core::wire` implementation now exists. Named legacy methods remain for testnet/history; non-testnet proposal/vote/commit use V1. Payments and value risk are not switched. | One versioned `RLDW` TLV envelope, strict field ids/types/order, and a purpose prefix. | **PARTIAL.** Remaining runtime objects are a **BLOCKER**. Legacy signatures cannot be accepted as V1. |
| API JSON strictness | Consensus-facing structs do not use `deny_unknown_fields`; several domain fields have `serde(default)` and can deserialize as empty/zero. | Unknown fields fail; all domain fields are required; duplicate keys and non-canonical number/hex projections fail. | **BLOCKER.** Strict input validation is required before hashing or state execution. |
| Unicode canonicality | `put_string` signs Rust UTF-8 bytes as supplied; no NFC/control-character validation is applied. | Strict UTF-8, already-NFC text, no C0/C1 controls, exact byte limits. | **BLOCKER.** Reject, do not normalize after signing. |
| Command commitment | Named `command_hash()` remains the legacy/testnet algorithm. Non-testnet proposal construction and verification use schema `0500` plus the explicit `RLDP` registry for all 7 consensus and 30 production tags. Unknown structs, fields, enums, maps, tuples, signed numbers, and floats fail closed. | `command_hash` is the schema-0500 subject digest over the separately frozen command body. JSON/Debug/layout/map order are forbidden. | **IMPLEMENTED FOR CURRENT VARIANTS.** Rust matches every independent accept vector; mixed legacy/V1, 3-of-4 economic commit, WAL/restart, and replay tests pass. A newly added command/field remains a blocker until the registry and vectors change together. |
| Commit identity | `commit_hash` remains the named legacy/testnet function. Non-testnet ledger insertion and replay identity use `wire_v1_commit_hash`, which binds the sorted unique vote-hash set. Exact matching historical records may be read under a legacy key but new records never fall back. | Commit subject binds network/Zone/currency/eras, proposal hash, height/root, and the sorted unique vote-hash set. | **FIRST SLICE IMPLEMENTED.** Persisted mixed-version migration and a second implementation remain blockers. |
| QC attestation message | `QuorumCertificate::verify` verifies Ed25519 over the ASCII bytes of a lowercase-hex `subject_hash`. | This candidate freezes subject preimages/digests but has not yet frozen a complete QC wire/attestation schema. | **BLOCKER.** Freeze QC membership, threshold, signature message, and vectors before production adoption. Do not silently treat ASCII hex and raw digest bytes as interchangeable. |
| Multi-round BFT codec | The strict codec knows the eight schemas in `CONSENSUS-ROUNDS.md`, and the offline evidence profile verifies signed members, historical membership, quorum and highest QC. Runtime still implements the legacy one-stage round-zero path and rejects non-zero rounds. Experimental `view_change.rs` uses different custom bytes and a different validator-set hash. | Prepare and Commit are separate domains; TC preserves each TimeoutVote HighQC report; all messages bind the committed historical set and parent instance. | **OFFLINE EVIDENCE ONLY / BLOCKER.** Do not connect the experimental kernel, delete a round guard, or treat legacy votes/commits as HighQC/CommitQC. Persistent node/signer/witness state, recovery, state-machine refinement and atomic activation are still missing. |
| Value-risk subject | A typed `wire_v1_subject_hash` adapter matches the frozen vector, but runtime `compute_subject_hash` remains legacy. Existing `VALUE_CAP_0` updates require an empty safety-case string while schema `0401` requires `HASH32`; QC attestations also still sign ASCII hex. | Schema `0401` uses the common strict envelope, explicit network domain, u128 heights, canonical strings, and the subject-purpose prefix. | **BLOCKER.** Resolve the empty-sentinel and QC schema conflicts explicitly; do not map empty to zero hash or silently fall back. |

## Exact legacy behavior observed

- `Amount` is a Rust `u128`; its JSON representation is a decimal string, and
  its parser already rejects leading zeros and values above u128. This is useful
  agreement at the data-model boundary, but current signing layouts insert the
  raw 16-byte amount without the RLD-WIRE-V1 field framing.
- `hash_bytes` is SHA-256 over raw input. `hash_parts` instead prefixes every
  part with an eight-byte big-endian length and returns lowercase hex.
- `PaymentRequest::signing_bytes` starts with `RLD-PAYMENT-REQUEST-V2`, then
  concatenates u32-length-prefixed strings and raw big-endian integers.
- `UniversalPaymentIntent::signing_bytes` starts with `RLD-PAYMENT-V2`.
  Request and route bindings are appended conditionally as labeled strings. An
  embedded `payment_request` is not itself encoded; its signed commitment is
  appended only through the optional request-id branch.
- `ConsensusProposal::signing_bytes` and `ConsensusVote::signing_bytes` start
  with `RLD-CONSENSUS-PROPOSAL-V2` and `RLD-CONSENSUS-VOTE-V2` respectively.
  Both use u64 heights and omit an explicit network domain.
- `ConsensusProposal::proposal_hash` is `hash_parts(signing_bytes,
  signature_ascii_hex)`, so signature representation is part of proposal
  identity. RLD-WIRE-V1's proposal digest identifies the canonical signing
  message; a later certificate specification must separately freeze whether and
  how signatures contribute to a certified-object id.
- `ValueRiskPolicyUpdate::compute_subject_hash` begins with
  `RLD-VALUE-RISK-POLICY-UPDATE-V1` inside `hash_parts`; quorum attestations sign
  the resulting lowercase-hex text bytes.

## Required migration sequence

1. Add independently verified Ed25519 member evidence and historical-set quorum
   vectors for the codec schemas frozen in `CONSENSUS-ROUNDS.md`; command payload
   schemas are already frozen in `COMMANDS.md`.
2. Add a deliberately versioned Rust codec without changing legacy decoding in
   place. Legacy and RLD-WIRE-V1 messages must have distinct negotiation and
   storage identities.
3. Migrate logical heights and persisted state from u64 to u128 with boundary,
   snapshot, WAL, and restart tests.
4. Require explicit network/Zone/currency/era context and strict JSON ingress;
   remove defaulting for consensus-domain fields in the new protocol version.
5. Run Rust-to-Python differential tests over all accepted and rejected vectors,
   then repeat with a genuinely independent second implementation.
6. Only after replay/migration and mixed-version safety tests may a network
   activation height be selected.

Until every blocker above is resolved, the correct status is: **candidate wire
specification and first Rust consensus slice available; runtime migration
incomplete; independent complete-client gate still open**.
