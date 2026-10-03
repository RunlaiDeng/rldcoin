# RLD-WIRE-V1 signed consensus evidence profile

Status: **frozen offline evidence profile; runtime and state-machine adoption
remain disabled**.

This profile supplies the complete signed-member evidence that the codec-only
objects in [`CONSENSUS-ROUNDS.md`](CONSENSUS-ROUNDS.md) deliberately omit. It
defines deterministic offline verification of Ed25519 members, historical
validator-set membership, quorum, Prepare-to-Commit linkage, and Timeout
Certificate HighQC selection. It does not authorize any node, signer, witness,
WAL, recovery path, pacemaker, or network route to accept a non-zero round.

## 1. Cryptographic contract

- The algorithm is pure Ed25519 as defined by RFC 8032. Ed25519ctx and
  Ed25519ph are different protocols and MUST be rejected.
- A signature covers exactly `RLD-SIGNATURE-PREIMAGE-V1 || canonical_wire`.
  Signing the canonical wire alone, its SHA-256 digest, an ASCII hexadecimal
  digest, a subject preimage, a legacy schema, or a generic `subject_hash` is
  invalid.
- Public keys are exactly 32 raw bytes and signatures exactly 64 raw bytes;
  their JSON projection is lowercase hexadecimal.
- Verifiers MUST apply strict point/scalar validation. In particular, the
  frozen `S + L` scalar mutation MUST fail even though it represents the same
  scalar modulo the group order.
- Every signed artifact carries the exact public key inside its frozen wire
  source. A detached transport identity cannot replace it.

The seeds in the vector bundle are public deterministic **test-only** material.
Production software MUST NOT load them as validator keys.

## 2. Trusted historical validator sets

A certificate never chooses its own validators. The verifier receives a
trusted history of canonical `030f ConsensusValidatorSet` subjects, each with
an inclusive parent-height interval. For every root and dependency it MUST:

1. recompute the set subject digest;
2. match network, Zone, currency genesis, Protocol Era, Crypto Era, consensus
   protocol version, validator-set epoch and commitment;
3. require the object's parent height to fall in that set's active interval;
4. reject missing, overlapping, duplicate, conflicting or attacker-supplied
   untrusted set records; and
5. compute `q = n - floor((n - 1) / 3)` from the resolved set length.

An old certificate remains verifiable at an old height. It cannot be replayed
after a validator-set transition merely because one key remains in both sets.

## 3. Exact evidence graph

The root and each evidence entry contain:

- a frozen schema name and complete JSON source;
- independently recomputable canonical wire bytes and RLD-WIRE digest; and
- for signature-purpose schemas only, the detached Ed25519 signature.

References are resolved by the pair `(schema, digest)`, never by digest alone.
Every reference MUST resolve to exactly one artifact of the required schema.
The verifier walks the root's dependency closure with bounded object count and
depth. Missing, duplicate, cyclic, wrong-schema, digest-mismatched or
unreferenced extra evidence rejects the whole case. Transport arrival order is
irrelevant; the frozen builder emits stable order.

Certificate verification is deliberately fail-closed: all listed members must
be well formed, in the active historical set, unique, correctly bound and
strictly signed before quorum is counted. An implementation MUST NOT discard a
bad, out-of-set or otherwise extraneous listed member and count the remaining
valid signatures.

## 4. Certificate rules

### PrepareCertificate

Every `prepare_vote_hashes` entry resolves to an exact signed `0312
PrepareVote`. Network/Zone/genesis/eras/version/set, parent instance, round,
block, proposal, command, successor height and expected root MUST equal the
`0313 PrepareCertificate`. Signers are unique active members and their exact
set meets locally computed quorum.

### CommitCertificate

The referenced PrepareCertificate is first fully verified. Every signed `0314
CommitVote` references that same PrepareCertificate and matches its complete
instance and value. The `0315 CommitCertificate` matches both and independently
meets quorum. A legacy commit, PrepareCertificate alone, TC or member hash list
does not establish finality.

### TimeoutCertificate and highest QC

Every signed `0310 TimeoutVote` matches the `0311 TimeoutCertificate` instance
and timed-out round. Each reported HighQC resolves to a fully verified
PrepareCertificate whose round and block match the report.

After every member and dependency verifies, the verifier chooses the greatest
reported HighQC round. The TC's selected round, block and certificate digest
must equal that result. If two different block ids or PrepareCertificate
digests occur at the greatest round, verification fails with
`highest_qc_conflict`; arrival order or hash order is not a tie-breaker. An
omitted higher verified QC fails with `selected_high_qc_not_max`.

### ViewChangeProposal

A signed `0316 ViewChangeProposal` references a fully verified TC for exactly
`round - 1` and the same instance. Its HighQC fields exactly equal the TC's
selection. If a HighQC exists, block, command, height and expected state root
equal that PrepareCertificate's locked value. The proposer is the deterministic
leader from the sorted committed validator keys:

```text
leader_index = (parent_height mod n + round mod n) mod n
```

These offline rules do not supply persistent vote locks or prove that a live
node has obeyed them across crashes.

## 5. Frozen evidence and implementations

`vectors/wire-v1/consensus-certificates.json` contains 24 content-addressed
cases: 7 accepting closures and 17 isolated rejections. It covers 3-of-4 and
4-of-4 Prepare quorum, Commit linkage, TC with and without HighQC, deterministic
locked-value view change, historical-set rotation, insufficient quorum,
invalid signature, out-of-set signer, missing/extra/duplicate evidence,
inactive set, cross-instance HighQC, Prepare mismatch, hidden or conflicting
highest QC, wrong leader, changed lock, signature-domain substitution,
non-canonical Ed25519 scalar, small-order key and signature-width rejection.

The Go standard-library implementation in
`tools/consensus-certificate-verifier` independently builds and verifies the
whole bundle, its sidecar, strict duplicate-free JSON, stable error classes,
all graph rules and all negative cases. It imports no Rust or Python project
code. Its default command requires an exact byte match with the deterministic
frozen builder; accepting an unfrozen diagnostic corpus requires an explicit
flag and emits no conformance/adoption claim. Bundle, sidecar, case, test-key,
history, artifact and member limits are checked before unbounded allocation or
signature work. The Rust codec test independently recomputes all seven accepted closures,
derives every public key and deterministic signature from the frozen seeds,
uses `ed25519-dalek::VerifyingKey::verify_strict`, and separately rejects the
non-canonical `S + L` vector.

This closes an offline interoperability/evidence sub-gate only. It is not a
second full node implementation, and the Rust test does not yet duplicate every
Go negative-case error priority.

## 6. Remaining atomic runtime gate

Non-zero-round runtime adoption remains forbidden until all of the following
are activated in one protocol-era transition:

1. typed verification with no fallback to the existing generic QC path;
2. durable and monotonic `last_voted_round`, phase vote, timeout, `lockedQC`,
   `highQC` and accepted-TC state in node, isolated signer and witness;
3. persist-before-sign and crash-boundary tests backed by a non-resettable
   external monotonic anchor;
4. authenticated transport and validator-key pinning, bounded queues/bodies,
   hidden-quorum and resource-exhaustion defenses;
5. production pacemaker, deterministic proposal policy, certified catch-up,
   snapshots and recovery without unsafe lock migration;
6. partition, leader-loss, conflicting-QC, corrupted-WAL, rollback and
   mixed-version exercises with safety and finite-progress evidence; and
7. Rust/state-machine refinement plus two additional complete independent
   clients and external review.

Until that atomic gate closes, the node MUST reject `round > 0`, the checked-in
safety case MUST remain `INCOMPLETE`, and value capacity MUST remain
`VALUE_CAP_0`.
