# Initial R6 formal traceability

This is an initial, bidirectional index from R6 rules to the bounded model and
the current workspace. An implementation anchor means only that related code
exists at that symbol; it does **not** mean the TLA+ model refines that Rust
code, that the implementation satisfies the invariant, or that the R6 safety
case item is closed.

The implementation column is intentionally symbol-based because the workspace
has no committed baseline and line numbers are not stable. All referenced Rust
anchors are under `crates/rld-core/src/` unless stated otherwise.

| R6 requirement / threat | Model state and transition | Checked invariant | Current implementation anchor | Initial gap / next evidence |
|---|---|---|---|---|
| Fixed `10^35` runlai supply; fees are transfers, never mint/burn (1, 2.2, 2.4, 5.2, 16.4, 17) | `ledger.*Balance`; `Export`, `Import`, `BeginReturnAfterRejection`, `FinalizeReturnAfterRejection`, `ClaimFee` | `SupplyConserved` | `amount.rs`: `TOTAL_SUPPLY_RUNLAI`, `Amount`; `ledger.rs`: `Ledger::supply_buckets`, `Ledger::supply_certificate`, `Ledger::assert_conservation` | Model uses 3 abstract units and mathematical integers. Add `u128/u256` overflow refinement, every production bucket, fee remainder rules, and cross-Zone audit snapshots. |
| A UMCO has one canonical amount location; source shadow and destination amount are never both counted (2.4, 3.1, 5.2, 16.4, 17) | `ledger.coinLocations`; export/import/rejection/refund lifecycle | `UmcoHasSingleCanonicalLocation` | `types.rs`: `CoinState`, `CoinObject`; `ledger.rs`: `Ledger::export_payment`, `Ledger::import_capsule`, `Ledger::finalize_export`, `transit_coin_ids` | No `TransferEdgeRecord` implementation anchor was found. Build a refinement map that distinguishes a non-canonical source shadow from spendable/canonical value and proves audit de-duplication. |
| Import and final rejection consume one shared Transit Nullifier exactly once (3.1, 5.2, 10.1, 16.5, 17) | `ledger.transitNullifier`; `Import`, `RejectAtDestination` | `TransitNullifierUnique` | `ledger.rs`: `transit_nullifiers`, `rejected_transit_nullifiers`, `Ledger::create_destination_rejection`, `Ledger::certify_destination_rejection`, `Ledger::import_capsule` | Rust currently represents import and rejection in two sets, while the model uses one enumerated state. Prove their atomic mutual exclusion under consensus/crash recovery or replace them with a single persisted state. |
| A destination-bound fee entitlement is claimable at most once (2.4, 5.2, 10.1, 16.4, 17) | `ledger.feeNullifier`, fee escrow/pool; `ClaimFee` | `FeeNullifierUnique` | No matching destination fee-voucher/nullifier symbol found; route fees currently flow through export/payment logic | Define the fee-voucher commitment, target binding, claim/refund states, persistence, and the implementation/test-vector link before claiming coverage. |
| Timeout, non-inclusion, route exhaustion, or capsule return cannot refund (3.1, 3.3, 10.1, 16.5) | `ledger.timeoutExpired`; `ExpireTimeout`; refund requires rejected state | `RefundRequiresDestinationRejection` | `ledger.rs`: `Ledger::begin_return_from_rejection`, `Ledger::finalize_return`, `DestinationRejectionProof` | Model assumes proof validity. Add invalid/stale/wrong-destination proof states, QC/DA/validity separation, crash recovery, and concurrent import-vs-return refinement. |
| A final destination rejection permanently blocks every late/duplicate import (3.1, 10.1, 16.5) | rejected Nullifier plus `UnsafeLateImportAfterRejection` mutation | `LateImportAfterRejectionFails`, `TransitNullifierUnique` | `ledger.rs`: rejection-set check in `Ledger::import_capsule`; insertion in rejection creation/certification | Need atomic durable ordering and consensus replication proof; current isolated model does not cover two processes, database rollback, or inconsistent replicas. |
| With Byzantine weight strictly below 1/3, conflicting blocks cannot both finalize (2.4, 4.3, 16.5) | four validators, one Byzantine, two blocks, honest vote lock, quorum 3; `CastVote`, `Finalize` | `NoDoubleFinality` | `types.rs`: `required_quorum`, `ConsensusProposal`, `ConsensusVote`, `ConsensusCommit`; `ledger.rs`: `Ledger::lock_consensus_vote`, `Ledger::apply_consensus_commit`; `crates/rld-node/src/main.rs`: `run_consensus` / vote collection | Equal/static voters only. Model validator weights, rounds/views, locked QC rules, reconfiguration, signer rollback, persistence, network partitions, and liveness separately. |
| `VALUE_CAP_0..3` and per-path limits are consensus enforced; frontend/admin/legacy caller cannot bypass (0.4, 2.4, 10.3, 16.8, 17) | `valueState.cap`, `highestActivatedCap`, per-path exposure and four caller classes; `AcceptValue`, blocked direct attempts | `ValueCapCannotBeBypassed`, `DirectUpgradeCallersAreBlocked` | `types.rs`: `ValueCap`, `ValueRiskLimits`, `ValueRiskPolicy`; `ledger.rs`: `next_value_risk_total`, guarded payment/import/DSC paths | Workspace anchors are not refinement-linked. Extend to every single/account/Zone/global/source-group limit, concurrent requests, restart, and every value-bearing command. |
| Cap increases require pending one-level activation, challenge delay, a bound valid/unexpired `MainnetSafetyCase`, and threshold authorization; expired runtime evidence blocks new value (0.3, 0.4, 2.4, 16.8, 17) | `logicalHeight`, `pending*`, `pendingSafetyCaseHash`, `approvals`, `safetyCaseValid`; propose/authorize/activate/tick/runtime accept | `PendingCapUpgradeWellFormed`, `NoUnauthorizedCapUpgrade`, `ChallengePeriodEnforced`, `SafetyCaseFreshOnUpgrade`, `RuntimeSafetyCaseExpiryBlocksNewValue` | `ledger.rs`: `submit_value_risk_policy_update`, `activate_pending_value_risk_policy`, `verify_value_risk_policy_update`; `types.rs`: `ValueRiskPolicyUpdate` | Model uses one fixed safety-case hash, a 1-height challenge, two abstract groups, and expiry height 4. Add evidence revocation/renewal, real weighted authorization, evidence hash resolution, restart persistence, and runtime checks on all implementation entry points. |
| Risk deterioration immediately cancels pending increases, downshifts/freeze-closes new exposure, preserves accepted exposure, and cannot alter supply (0.3, 0.4, 16.8) | `riskHealthy`, `newValueFrozen`, `frozenExposure`; `RiskDeteriorates` leaves `ledger` unchanged | `RiskDownshiftIsFailClosed`, `SupplyConserved` | `ledger.rs`: value-risk policy/exposure fields and policy-update functions | Atomic model event does not cover asynchronous monitors, competing blocks, stale replicas, or partial persistence. Refine detection-to-consensus latency and crash recovery without rolling back accepted payments. |
| Once a Crypto Era disables an old suite, handshake, verification, history, and updates cannot downgrade (2.4, 5.1, 12.1, 12.4, 16.6, 17) | `cryptoState.era`, `disabled`, `lastAcceptedSuite`; `AdvanceCryptoEra`, `AcceptCryptoSuite` | `CryptoEraCannotDowngrade` | `types.rs`: `CryptoSuiteDescriptor`, `EraContinuityCertificate`; `ledger.rs`: `Ledger::apply_era_transition`, `Ledger::verify_era_certificate`, intent/request era context checks | Model assumes an authoritative disabled-suite set. Implement/trace suite negotiation and disable heights across network, history, update, Zone identity, wallet, validator, and notary paths; include mixed-version partitions. |
| Every non-testnet proposal commits to one implementation-independent encoding of the exact executable command (2.4, 12.1, 16.6, 17) | No current TLA+ byte-level state | Not modeled | `command_wire.rs`: explicit numeric tags and field encoders for all current `ConsensusCommand`/`ProductionCommand` variants; `types.rs`: non-testnet proposal verification; `spec/wire/COMMANDS.md`; 60 independent Python/Rust vectors | Current command set is covered, but there is no byte-parser refinement. Complete PaymentRequest/UPI, standalone QC/attestation and other subjects, strict JSON ingress, persistent-operation encoding, u128 counters and two independent clients. |

## Independent crash-consistency traceability

The following rows refer to `RldcoinCrashConsistency.tla`. Rust anchors in this
table are under `crates/rld-node/src/`; they show where a future refinement map
would attach, not that a refinement or filesystem proof exists.

| Persistence / consensus requirement | Model state and transition | Checked invariant | Current implementation anchor | Initial gap / next evidence |
|---|---|---|---|---|
| A mutation is not published before its operation WAL is complete and fsynced; publishing retains a durable recovery source | `AppendWalRecord1`, `AppendWalRecord2`, `FsyncCompleteWal`, `AdvanceRollbackAnchor`, `PublishNewState` | `UnfsyncedStateNeverPublished`, `PublishedStateHasDurableRecoverySource` | `persistence.rs`: `PersistentStore::commit`, `append_record`, `write_anchor_file`; `main.rs`: `durable_mutation` | Model treats `fsync`, anchor replacement, and publication as atomic abstract steps. Add platform/filesystem crash tests and a linearization/refinement map for the in-memory ledger swap. |
| Recovery yields the complete old or complete new state, never a mixture; truncated, out-of-order, bad-link/hash, and old-checkpoint-plus-short-WAL states fail closed | `RecoverStorage`, `RecoveryDecision`, five `CorruptWalStatuses` | `CompleteWalRecoveryIsAtomic`, `RecoveryNeverMixesStates`, `CorruptWalFailsClosed` | `persistence.rs`: `PersistentStore::recover`, `read_wal`, `validate_record_chain`, `validate_head_matches_ledger` | Enumerated corruption classes are not byte-level torn-write semantics. Add generated crash images around every write/sync/rename boundary and prove decoded records correspond to the abstract statuses. |
| Checkpoint failure cannot destroy the already committed WAL | `CheckpointFails`; unsafe `UnsafeCheckpointOverwritesCommittedWal` | `CheckpointFailurePreservesCommittedWal` | `persistence.rs`: `PersistentStore::write_checkpoint`, `write_checkpoint_file`, `FaultPoint::BeforeCheckpointRename` | Model has one checkpoint and one WAL operation. Verify directory-sync guarantees, replacement ordering, repeated checkpoints, disk-full behavior, and post-error poisoning on each supported filesystem. |
| A rollback anchor detects locally inconsistent backward recovery | `anchorEpoch`, `maxAnchorEpoch`, `AdvanceRollbackAnchor`; unsafe `UnsafeRollbackAnchor` | `AnchorNeverRollsBack` | `persistence.rs`: `read_anchor`, `write_anchor_file`, anchor/history checks in `PersistentStore::recover` | Both modeled epochs live in the same trust domain. Local rollback detection does not cover a consistent rollback of every file. |
| An honest validator persists its consensus-instance lock before signing, and reloads it after crash | `SelectProposal`, `FsyncVoteLock`, `SignLockedVote`, `CrashVoter`, `RecoverVoter` | `NoHonestDoubleVote`, `EveryIssuedVoteHasDurableLock` | `persistence.rs`: `DurableMutation::ConsensusVoteLock`, cross-round replay/checkpoint-forgery tests; `main.rs`: `accept_consensus_proposal` persists the parent-height/root instance lock before `sign_bytes` and rejects every nonzero round | The crash model abstracts one signer/two proposals and does not refine the Rust checkpoint/WAL reconstruction. The Rust safety subset has no view change, highQC, weighted reconfiguration, HSM signer or distributed liveness. |
| A whole-directory consistent rollback requires evidence outside the restored directory | `WholeDirectoryConsistentRollback` resets all local freshness fields while a ghost event records rollback | `WholeDirectoryRollbackNeedsExternalWitness` (deliberately violated) | `crates/rld-witness`: independent checkpoint and vote-authorization heads; `crates/rld-node`: startup gate and durable node lock; `crates/rld-signer`: separate durable lock, signer-side quorum revalidation and release ordering | Node-only rollback fails closed, but a coordinated rollback of the software signer's key and complete state remains possible. Mainnet needs a non-exportable HSM/KMS key, external non-resettable monotonic anchor, rotating independent operators, mutually authenticated pinned transport and real DoS evidence. |

## Independent Byzantine view-change and catch-up traceability

The following rows refer to `RldcoinBftViewChange.tla`. They connect model
operators to current symbol names only; they do not claim a Rust refinement.

| BFT / catch-up requirement | Model state and transition | Checked invariant / property | Current implementation anchor | Initial gap / next evidence |
|---|---|---|---|---|
| Four fixed equal-weight validators with at most one Byzantine cannot finalize conflicting roots at one height across views | `votes`, `voteQCs`, `commitQCs`, `FormVoteQC`, `FinalizeProposal`, view-1 `ByzantineLeaderEquivocates` | `NoDoubleFinality`, `NoHonestDoubleVoteInView`, `HonestVotesStayOnOneRootPerHeight` | `types.rs`: `ConsensusProposal`, `ConsensusVote`, `ConsensusCommit`, `required_quorum`; `ledger.rs`: cross-round parent-instance lock and commit conflict checks; `crates/rld-node/src/main.rs`: deterministic sorted-set round-zero leader and rejection of nonzero rounds | Rust closes the observed overlapping-quorum cross-round attack by implementing only the model's round-zero safety subset; it does not implement the model's view-change/highQC/TC transitions and therefore loses liveness when the selected leader fails. Mainnet still needs a refined authenticated view-change protocol, weighted/dynamic membership, reconfiguration and mixed-version evidence. |
| An honest signer persists its lock before releasing a vote and reloads lock/highQC after crash | `SelectHonestProposal`, `FsyncSelectedVoteLock`, `CastHonestVote`, `CrashHonestValidator`, `RestartHonestValidator` | `EveryHonestVoteWasDurablyLocked`, `PersistentLockNeverRegresses`, `PersistentHighQCNeverRegresses` | `ledger.rs`: `lock_consensus_vote`, `consensus_vote_locks`; `persistence.rs`: `DurableMutation::ConsensusVoteLock`, vote-lock replay test; `main.rs`: `accept_consensus_proposal` persists before `sign_bytes` | The model includes persistent highQC, but no matching Rust highQC persistence symbol was found. Prove lock/highQC linearization through WAL, simultaneous faults, HSM signing, and view transitions. |
| Byzantine votes and stale messages cannot be re-counted or accepted as a QC | `VotersFor`, `staleMessageCount`, `FormVoteQC`; unsafe `UnsafeFormVoteQCFromStale` | `ByzantineAndStaleMessagesCannotMakeQC` | `types.rs`: `ConsensusCommit::verify`, `verify_wire_v1` distinct-voter and signature checks | The model treats signature validity as a predicate and stale traffic as a count. Add replay-window/view binding, byte-level vectors, duplicate identities, key rotation, and adversarial network tests. |
| View advancement requires a 3-of-4 timeout certificate containing at least two honest timeout votes | `timeoutVotes`, `timeoutCerts`, `FormTimeoutCertificate` | `TimeoutCertificatesNeedQuorum` | No timeout-certificate or persistent highQC implementation exists; the node deterministically rotates the round-zero leader by parent height and rejects every nonzero round | Implement and refine timeout messages/certificates, highQC selection, new-view validation, durable view state and recovery before claiming Byzantine view-change support. Height-to-height leader rotation is not view change. |
| After a partition heals, a bounded fair schedule commits two heights and lets a lagging node catch up | `networkMode`, `ProgressNext`, `ProgressSpec`, `ProgressComplete` | `BoundedFairProgress` | `main.rs`: `consensus_catch_up_round`, `plan_consensus_catch_up`, `apply_catch_up_plan` | The temporal check is one 17-transition scripted weakly fair scenario, not general liveness. Add a separate partial-synchrony model with message buffers, GST assumptions, rotating leaders, time bounds, crash budgets, and non-vacuous fairness review. |
| A lagging node accepts only authenticated, consecutive commits whose parent root equals its current root | `receivedCatchupCerts`, `catchupAccepted`, `AcceptCertifiedCatchup` | `CatchupOnlyAcceptsCertifiedCommits`, `CatchupHasNoHeightHoles`, `CatchupChainIsContinuous`, `CommittedChainIsContinuous` | `main.rs`: bounded peer decoding, two distinct signed-head reporters, staged commit verification, predecessor/root checks and witness authorization held through each at-most-128-commit apply batch | Conflicting/forged peers, bounded restart convergence and authorization-revocation concurrency have deterministic tests. The model still has only two heights and abstracts cryptography, witness operators, era changes, disk failure, total-round bandwidth, snapshot transfer and partial synchrony. |

## Independent isolated-signer traceability

The following rows refer to `RldcoinIsolatedSigner.tla`. The model is a bounded
abstraction of one hostile node, one signer and two conflicting proposals. It
is not a refinement proof of `rld-signer`, filesystem durability, cryptography,
HSM behavior or operator independence.

| Signer requirement | Model state and transition | Checked invariant | Current implementation anchor | Open production evidence |
|---|---|---|---|---|
| A validator key is absent from the default node build and no generic signing capability is exposed | typed request actions plus hostile `AttemptRawSign`; signer key is a distinct state owner | `NoRawSigningCapability`, `PinnedValidatorKeyIsMandatory` | `crates/rld-node`: default feature set excludes `--validator-wallet` and all local signing branches; `crates/rld-signer`: four typed routes, strict JSON and key/context pins | Prove release artifact composition, OS/process isolation, non-exportable HSM key custody, API authentication and no operational fallback. |
| A proposal signature follows one durable signer-owned lock for the exact parent instance | `PersistProposalLock`, `ReleaseProposalSignature` | `EveryProposalHasDurableSignerAuthorization`, `AtMostOneProposalPerParentInstance` | `SignerEngine::sign_proposal`: wire/domain/leader/command/root validation, state-file persistence before response and exact retry | Linearize real concurrent requests and supported filesystem/power-loss behavior; independently audit full state-transition validation. |
| A vote requires the exact independently verified witness quorum and signer-owned durable authorization | `PersistVoteAuthorization`, `ReleaseVoteSignature` | `EveryVoteHasExactWitnessAuthorization`, `EveryVoteHasDurableSignerAuthorization`, `AtMostOneVotePerParentInstance` | node persists `ConsensusVoteLock`; signer signs the exact witness request, re-verifies 3-of-N domain receipts, then persists and releases the vote | Deploy independent witness operators; prove transport identity, revocation, DoS limits, reconfiguration and HSM enforcement. |
| Restart cannot erase signer locks or regress the monotonic node-WAL view | `CrashSigner`, `RecoverSigner`; unsafe rollback/lost-lock mutations | `SignerLocksSurviveRecovery`, `SignerMonotonicHeadNeverRegresses` | signer state binds key/policy and stores parent roots, proposal/vote locks, maximum durable sequence/hash and signed heads using temp-file sync/rename/directory sync | A whole signer-directory rollback is still possible. Require a non-resettable hardware/external monotonic anchor and witnessed recovery ceremony. |

## Counterexample-to-requirement map

| Deliberate mutation | Minimal abstract trace | Requirement exposed |
|---|---|---|
| `TIMEOUT_REFUND` | export → timeout → source refund | timeout alone must not refund |
| `TIMEOUT_REFUND` with supply invariant only | export → timeout → refund → late import | fixed supply and single canonical UMCO location |
| `LATE_IMPORT_AFTER_REJECTION` | export → target rejection → late import | shared Transit Nullifier finality |
| `DUPLICATE_FEE_CLAIM` | export → fee claim → second claim | fee Nullifier uniqueness |
| `WEAK_QUORUM` | disjoint honest votes plus one Byzantine side → two 2-of-4 finalizations | quorum intersection / no double finality |
| `VALUE_CAP_BYPASS` | caller accepts value while cap is zero | consensus-layer limits cannot be bypassed |
| `UNAUTHORIZED_UPGRADE` | frontend/admin/legacy caller directly sets cap 1 | only threshold-authorized protocol activation can increase cap |
| `CHALLENGE_NOT_MET` | proposed and approved cap activates before its challenge height | cap increases must be delayed |
| `EXPIRED_SAFETY_CASE` | pending approved cap activates at/after evidence expiry | stale evidence cannot raise cap |
| `EXPIRED_VALUE_ACCEPTANCE` | valid cap activates, evidence expires, then new value is accepted | runtime evidence expiry must fail closed without rolling back exposure |
| `CRYPTO_DOWNGRADE` | Era 2 disables classic → classic accepted | no old-suite downgrade |

Crash-consistency counterexamples:

| Deliberate mutation | Minimal abstract trace | Requirement exposed |
|---|---|---|
| `SIGN_BEFORE_LOCK` | select A → sign A without durable lock → crash/recover → select/sign B | a vote lock must be durable before signature release |
| `IGNORE_PARTIAL_WAL` | inject malformed or short WAL → recover it as old complete | corrupt/inconsistent WAL must fail closed |
| `ANCHOR_ROLLBACK` | fsync WAL → advance anchor → move visible anchor backward | local rollback-anchor monotonicity |
| `CHECKPOINT_OVERWRITE_WAL` | fsync/publish → checkpoint fails while erasing WAL | checkpoint failure must preserve committed WAL |
| `LOSE_VOTE_LOCK_ON_RECOVERY` | persist/sign A → crash → lose recovered lock → persist/sign B | crash recovery must restore the signer lock |
| `WHOLE_DIRECTORY_ROLLBACK` | complete new checkpoint → replace every local artifact with the old consistent directory | local evidence alone cannot detect whole-directory rollback |

BFT view-change and catch-up counterexamples:

| Deliberate mutation | Minimal abstract trace | Requirement exposed |
|---|---|---|
| `DELETE_PERSISTENT_LOCK` | vote B in Byzantine view → crash → delete lock → next view → same honest signer votes conflicting A | persistent lock must survive restart and constrain later views |
| `SKIP_QC_VALIDATION` | receive stale messages → Byzantine leader equivocation → one Byzantine vote → accept as QC | stale/Byzantine messages cannot replace a distinct 3-of-4 quorum |
| `SKIP_PARENT_ROOT_CHECK` | receive certified B1 and A2 → accept B1 → accept A2 although its parent is A1 | catch-up certificates must form one continuous root chain |
| `BAD_TIMEOUT_RULE` | receive stale messages → create TC with no timeout quorum | view change requires a valid timeout certificate |
| `DROP_HIGH_QC_ON_RECOVERY` | form QC → persist highQC → crash → restart with highQC erased | highQC must not regress through recovery |
| `CATCHUP_WITHOUT_CERT` | apply height-1 commit without receiving its certificate | catch-up must authenticate every applied commit |

Isolated-signer counterexamples:

| Deliberate mutation | Minimal abstract trace | Requirement exposed |
|---|---|---|
| `RAW_SIGNING_API` | hostile node submits arbitrary bytes -> signer releases signature | signer API must be typed and domain constrained |
| `BYPASS_WITNESS_QUORUM` | typed vote request -> signature without the exact receipts | signer, not node, must verify witness quorum |
| `SIGN_BEFORE_PERSIST` | authorize vote -> release signature -> no durable signer lock | signer state must be durable before release |
| `LOSE_LOCKS_ON_RECOVERY` | sign A -> crash -> lose lock -> sign conflicting B | restart must reload non-equivocation locks |
| `ROLLBACK_SIGNER_STATE` | observe newer WAL head -> restore older signer state | local signer persistence alone cannot prevent coordinated rollback |
| `BYPASS_KEY_PIN` | request targets an unpinned validator identity -> signature | validator key and deployment context pins are mandatory |

## Bidirectional coverage status

Every model invariant above points to a safety requirement or an explicitly
open assumption. The reverse direction is deliberately incomplete: R6 also
requires authorization, deterministic encoding,
execution-validity/data-availability proofs, dynamic weighted BFT, real
filesystem and power-loss evidence, governance authority, resource bounds,
and ownership recovery. The four bounded model families do not refine the Rust code or
prove liveness, and these items remain open `MainnetSafetyCase` / section 17
work.
