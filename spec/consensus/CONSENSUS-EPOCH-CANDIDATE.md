# Consensus epoch descriptor candidate

Status: **internal structural candidate; non-authoritative; runtime disabled**.

The implementation is `crates/rld-core/src/consensus_epoch.rs`. It prepares a
typed boundary for a future weighted validator epoch without changing the
frozen `030f ConsensusValidatorSet` wire subject or enabling non-zero rounds.
No node, signer, witness, WAL, certificate, or state transition consumes this
candidate.

## Security boundary

`ConsensusEpochDescriptor` is untrusted declaration data. Structural
validation and a stable digest do not prove that a validator owns stake, that
delegation exists, or that two declared control groups are independently
controlled. `stake_snapshot_root` is currently only a bound digest. Until the
ledger independently reconstructs every record and control relation from a
finalized stake snapshot, a descriptor MUST NOT authorize a proposal, vote,
QC, TC, epoch transition, reward, slash, withdrawal, or value-cap increase.

The candidate descriptor binds:

- network domain, Zone, currency genesis, protocol era and crypto era;
- non-zero consensus protocol version and consensus epoch;
- an inclusive activation parent height and exclusive exit parent height;
- stake snapshot root;
- canonical validator id, Ed25519 public key, key era, voting weight,
  control-group id, self bond, delegated weight and unbonding height;
- recomputed total voting weight, quorum power and exact quorum-rule
  parameters.

This digest has the distinct Rust type
`ConsensusEpochDescriptorCommitment`. It is not, and cannot be substituted for,
the `030f` subject digest carried in current `0310..0316` messages. A future
wire activation requires a new permanent schema and atomic protocol-version
transition.

## Structural rules

- Input contains 4..4096 validators and is already strictly ordered by
  `(validator_id bytes, public_key bytes)`; alternate public list order is
  rejected rather than normalized behind the caller's back.
- Validator ids and public keys are unique. Weight and self bond are non-zero;
  `weight == self_bond + delegated_weight` uses checked `u128` arithmetic.
- Ed25519 keys use lowercase 32-byte hex, canonical `y < 2^255-19` compressed
  encoding and a non-small-order point.
- Quorum is `total_weight - (total_weight - 1) / 3`, with all arithmetic
  checked. Each declared control group's aggregate weight must be no greater
  than `total_weight - quorum_power`. This rule also bounds every individual
  validator.
- A descriptor is valid for a message only when
  `activation_height <= parent_height < exit_height`. No validator may declare
  an unbonding height earlier than the epoch exit.
- Untrusted JSON is accepted only through the bounded decoder: at most 4 MiB,
  no unknown fields and no more than 4096 retained validator records.

These rules prove deterministic structure and the quorum-intersection
arithmetic only under the declared control map. They do not prove that the map
is true.

## Required activation work

1. Define finalized stake, delegation, exit, evidence-window and UBO/control
   state in the ledger; independently derive the snapshot root and every
   validator record.
2. Freeze a new RLD-WIRE-V1 epoch descriptor and chain format without changing
   existing `030f` or `0310..0316` bytes; add independent content-addressed
   accept/reject vectors.
3. Bind the authoritative epoch/set commitment into Proposal, PrepareVote/QC,
   CommitVote/Certificate, TimeoutVote/TC, ViewChangeProposal, signer locks,
   witness requests, checkpoints and catch-up proofs.
4. Persist epoch, last-voted phase/view, lockedQC, HighQC and accepted TC before
   signing, with an external non-resettable anchor and crash-point tests.
5. Keep `VALUE_CAP_0` and reject every non-zero round until the above work,
   multi-operator drills, independent implementations and external audits are
   complete.
