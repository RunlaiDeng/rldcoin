# RLD-WIRE-V1 Prepare/Commit/Timeout/ViewChange profile

Status: **candidate codec freeze; runtime disabled; this bundle makes no
signature, quorum, or state-machine adoption claim**.

This profile extends the canonical envelope in [`README.md`](README.md). It
freezes byte layouts and deterministic object-local rejection rules only. It
does not authorize a node, validator signer, witness, WAL, catch-up path, or
network route to accept a non-zero round. The current `round > 0` fail-closed
guards remain normative until the atomic activation gate in section 8 closes.

The existing `0301 ConsensusProposal`, `0302 ConsensusVote`, and
`0303 ConsensusCommit` schemas remain immutable legacy round-zero objects.
They are not PrepareQC, CommitQC, HighQC, or TimeoutCertificate objects.

## 1. Additional primitive

Kind `0a` is `BYTES32_LIST`: a `u16` count followed by exactly that many
32-byte values. Values MUST be strictly lexicographically increasing by raw
bytes and MUST NOT repeat. Its byte encoding is deliberately identical to
`HASH32_LIST`, but the distinct kind prevents a list of public keys from being
silently reinterpreted as a list of message digests.

Every certificate/member list in this profile MUST contain 1..4096 entries at
the codec boundary. The state layer MUST impose the tighter active-validator
set bound before cryptographic work.

## 2. Common domains

`ConsensusValidatorSet` fields 1..7 are:

1. `network_domain:TEXT R` (Network, 64)
2. `zone_id:TEXT R` (Zone, 64)
3. `currency_genesis_root:HASH32 R`
4. `protocol_era:U64 R`
5. `crypto_era:U64 R`
6. `consensus_protocol_version:U64 R` (non-zero)
7. `validator_set_epoch:U64 R`

All other schemas in this profile use those fields followed by:

8. `validator_set_commitment:HASH32 R`
9. `parent_height:U128 R`
10. `parent_block_id:HASH32 R`
11. `parent_state_root:HASH32 R`

The trusted verifier context MUST compare every applicable field, including
the consensus protocol version, validator-set epoch/commitment, parent height,
parent block id, and parent state root. A valid signature from another network,
Zone, genesis, era, validator set, height, or parent is a replay and MUST fail.

## 3. Schemas

### `030f` ConsensusValidatorSet — subject

Fields 1..7 from section 2, then:

8. `validator_public_keys:BYTES32_LIST R`

The RLD-WIRE-V1 subject digest of this object is the only
`validator_set_commitment` defined by this profile. The key list is non-empty,
strictly sorted, unique, and capped at 4096. A message cannot choose its own
quorum: the state layer resolves this committed historical set and computes
`floor(2n/3)+1`.

The experimental hashes currently present elsewhere in the repository are not
aliases for this commitment and MUST NOT be silently accepted.

### `0310` TimeoutVote — signature

Fields 1..11 from section 2, then:

12. `timed_out_round:U64 R`
13. `high_prepare_qc_round:U64 O`
14. `high_prepare_qc_block_id:HASH32 O`
15. `high_prepare_qc_hash:HASH32 O`
16. `voter_public_key:BYTES32 R`

Fields 13..15 are all absent or all present. When present, field 13 MUST be at
most field 12. `timed_out_round == u64::MAX` is invalid because the next round
cannot be derived with checked addition.

The full signed TimeoutVotes remain required evidence for a TC. Flattening a
TC to a signer list loses each signer's HighQC commitment and is forbidden.

### `0311` TimeoutCertificate — subject

Fields 1..11 from section 2, then:

12. `timed_out_round:U64 R`
13. `selected_high_prepare_qc_round:U64 O`
14. `selected_high_prepare_qc_block_id:HASH32 O`
15. `selected_high_prepare_qc_hash:HASH32 O`
16. `timeout_vote_hashes:HASH32_LIST R`

Fields 13..15 are all absent or all present. Field 13 cannot exceed field 12.
The list is non-empty, sorted, unique, and capped at 4096. Every digest MUST
resolve to one exact canonical, valid, signed `TimeoutVote`; missing, extra,
duplicate-signer, out-of-set, malformed, or invalid-signature evidence rejects
the entire TC.

The selected HighQC MUST be recomputed from those verified votes. It is the
valid PrepareCertificate with the greatest round. If two different block ids
or PrepareCertificate hashes exist at the same greatest round, verification
fails closed; hash order or arrival order is not a tie-breaker. A leader that
omits a higher reported valid QC is invalid.

### `0312` PrepareVote — signature

Fields 1..11 from section 2, then:

12. `round:U64 R`
13. `block_id:HASH32 R`
14. `proposal_hash:HASH32 R`
15. `command_hash:HASH32 R`
16. `expected_height:U128 R`
17. `expected_state_root:HASH32 R`
18. `voter_public_key:BYTES32 R`

`expected_height` MUST equal `parent_height + 1`; overflow is invalid. State
validation MUST resolve the proposal digest and compare every bound value.

### `0313` PrepareCertificate — subject

Fields 1..17 are identical to `PrepareVote`, excluding the voter key, then:

18. `prepare_vote_hashes:HASH32_LIST R`

The list is non-empty, sorted, unique, and capped at 4096. A fully verified
PrepareCertificate is the only HighQC type in this profile. It is not finality.

Every digest MUST resolve to one exact signed `PrepareVote` with identical
domain, instance, round, block, proposal, command, height, and root. All signer
keys MUST be distinct active members of the committed historical validator set,
and the exact verified set MUST meet the locally computed quorum. Invalid extra
members reject the whole certificate; implementations MUST NOT discard garbage
and count the remaining signatures.

### `0314` CommitVote — signature

Fields 1..17 are identical to `PrepareVote`, then:

18. `prepare_certificate_hash:HASH32 R`
19. `voter_public_key:BYTES32 R`

The referenced PrepareCertificate MUST be fully verified and MUST bind the
same instance, round, block, proposal, command, height, and state root before a
CommitVote may be signed or accepted.

### `0315` CommitCertificate — subject

Fields 1..17 are identical to `PrepareCertificate`, then:

18. `prepare_certificate_hash:HASH32 R`
19. `commit_vote_hashes:HASH32_LIST R`

The member rules are the same fail-closed rules as for PrepareCertificate.
Only a fully verified CommitCertificate may establish finality. A
PrepareCertificate, the legacy `0303 ConsensusCommit`, a TC, or a collection of
TimeoutVotes is not a CommitCertificate.

### `0316` ViewChangeProposal — signature

Fields 1..11 from section 2, then:

12. `round:U64 R` (non-zero)
13. `proposer_public_key:BYTES32 R`
14. `block_id:HASH32 R`
15. `command_hash:HASH32 R`
16. `expected_height:U128 R`
17. `expected_state_root:HASH32 R`
18. `timeout_certificate_hash:HASH32 R`
19. `high_prepare_qc_round:U64 O`
20. `high_prepare_qc_block_id:HASH32 O`
21. `high_prepare_qc_hash:HASH32 O`

Fields 19..21 are all absent or all present. When present, field 19 MUST be
less than field 12. `expected_height` follows the successor rule.

State validation MUST require a fully verified TC for exactly `round - 1` and
the same instance. The HighQC fields MUST exactly match the TC's selected
HighQC. When a HighQC exists, the proposal MUST re-propose its locked value;
when none exists, a fresh value is permitted by this wire profile but remains
subject to execution and policy validation. The proposer MUST be the locally
computed deterministic leader for the target round and committed validator
set.

Round-zero proposals continue to use `0301` until a separate atomic protocol
era deliberately replaces them. `0316` MUST reject round zero.

## 4. Cross-type separation

`PrepareVote`, `PrepareCertificate`, `CommitVote`, `CommitCertificate`,
`TimeoutVote`, `TimeoutCertificate`, and `ViewChangeProposal` have distinct,
permanent schema ids. A correct signature or subject digest under one schema
MUST fail under every other schema even when an attacker makes all shared
fields byte-identical. Implementations MUST NOT retry verification under a
legacy schema or a generic `subject_hash` verifier.

Signature bytes and certificate member evidence are not embedded in their own
signing/subject wire object. The subject binds the exact sorted member-message
digests; transport must supply each complete signed member and reject any
missing or extra evidence.

## 5. Persistence and signer rules deferred from codec

Before returning a signature, both node and isolated signer must durably and
monotonically record at least:

- the unique block id for every `(height, round, phase)` vote;
- the unique TimeoutVote and its HighQC for every `(height, round)`;
- the target-view proposal lock;
- `last_voted_round`, `lockedQC`, `highQC`, and any accepted TC.

Signing a timeout for round `r` forbids a new block vote at `r` or below.
Entering a higher round forbids all lower-round signing requests. Commit voting
requires the same-value PrepareCertificate. Crash tests must cover every
write/fsync/rename/response boundary and prove that rollback cannot produce a
conflicting second signature. None of these properties is claimed by the codec
vectors.

## 6. Resource and evidence limits deferred from codec

Before signature verification, the runtime must enforce a per-type body limit,
fixed nesting depth, `quorum <= member_count <= active_validator_count`, fixed
key/signature widths, unique member keys, bounded verification work, bounded
per-peer/per-validator queues, and one forwarding slot per canonical message.
Old and far-future rounds, non-members, duplicates, and invalid signatures must
be rejected before broadcast or durable queues.

This codec vector bundle intentionally declares all of these false:

- `runtime_adoption_claim`
- `signature_verification_claim`
- `quorum_verification_claim`
- `state_machine_claim`

## 7. Frozen vectors

`vectors/wire-v1/consensus-rounds.json` contains 43 content-addressed cases and
a SHA-256 sidecar. It covers all eight schemas, exact preimages/digests,
optional-group rules, height/round overflow, empty/duplicate/unsorted member
sets, cross-schema/purpose substitution, strict decoding, and trusted-context
replay rejection. Both the Rust codec and the independent Python standard-
library implementation recompute the bundle.

It does not contain Ed25519, member-qualification, quorum, highest-QC evidence,
leader-selection, locking, WAL, or recovery proofs. The separate frozen
[`CONSENSUS-CERTIFICATES.md`](CONSENSUS-CERTIFICATES.md) profile now closes the
offline signed-member, historical-set, quorum and highest-QC evidence sub-gate;
it does not change this bundle's claims and does not provide runtime state,
locking, persistence, recovery or liveness.

## 8. Atomic activation gate

Runtime adoption is forbidden until one protocol-era transition activates all
of the following together:

1. typed Prepare/Commit/Timeout/ViewChange verification with no generic-QC
   fallback;
2. the historical validator-set subject and quorum lookup;
3. node, isolated signer, witness, WAL, snapshot, recovery, and catch-up state;
4. highest-QC recomputation, same-rank conflict fail-stop, locked-value rules,
   and deterministic leader validation;
5. cross-language signed-member/quorum vectors, mutation/fuzz tests, crash
   matrix, partition recovery, hidden-quorum tests, and formal invariants;
6. a mixed-version rejection/rollback plan and a checkpoint proving no active
   legacy lock can be reinterpreted.

Deleting an existing non-zero-round guard, treating the current one-stage vote
or final commit as HighQC, adopting the experimental `view_change.rs` bytes, or
migrating lock state implicitly is a release-blocking violation.
