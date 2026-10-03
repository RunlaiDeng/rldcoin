# Ledger-derived stake Epoch candidate v1/v2

Status: `DERIVED_ONLY / RUNTIME_DISABLED / VALUE_CAP_0`

This document specifies the deterministic derivation kernel intended to bridge finalized ledger state to a weighted `ConsensusEpochDescriptor`. The public kernel still accepts a caller-provided view plus a claimed finalized context. R6.7 through R6.11 added ledger ownership, certified authority/Epoch commands, Coin-backed locks, candidate lifecycle and delayed unbond. R6.12 added owner-signed V2 objective-fault slash terms, an exact legacy-position migration, and a per-position liability root in every derivation-version-2 Epoch. R6.13 added exact double-sign, conflicting-checkpoint and invalid-state-commitment evidence plus an atomic full-slash transition against that frozen liability. R6.14 retains that complete signed evidence in the immutable slash record, ledger/checkpoint state and audit bundle, and re-verifies it during restore/audit. Legacy V1 positions remain withdrawable but contribute no weight to a V2 Epoch and cannot be slashed by this path. Once a bootstrap authority exists, broad governance may no longer rewrite candidate lifecycle or reintroduce an unbonding position. Certified commits state-root these results and support exact historical replay. This remains a bounded fixed-set authorization path for `STAGED_ONLY / DERIVED_ONLY` records, not runtime dynamic proof of stake: no command changes `ZoneDescriptor.validator_keys`, and no node creation route, signer, witness or runtime membership resolver adopts the derived descriptor. A valid slash sends the entire exact escrow to a fixed non-spendable safety-pool owner; it does not reward the reporter, activate membership, authorize reward or activate value.

## Security claim

The current implementation may claim only:

> Given the same bounded, well-formed input view, the Rust reference derives the same stake snapshot root and structurally valid `ConsensusEpochDescriptor` candidate regardless of candidate and position insertion order.

The Rust ledger may also claim that a fixed-set certified commit can stage the one bootstrap authority view only when its dual QC, exact current parent, predecessors, prospective commitment and subject hash match; a second certified command can produce only the exact next `DERIVED_ONLY` record; and owner-authorized lifecycle commands are failure-atomic. A V2 lock requires one signature authorizing the mutation and a separate retained signature accepting the protocol-fixed objective-fault policy. Migration attaches those terms to one exact active legacy position without moving or resizing its Coin. A V2 Epoch independently reconstructs descriptor self-bond, delegation and minimum-unbonding totals from canonically ordered liabilities that freeze the position, owner, escrow, historical validator key/key era, activation/exit/evidence deadline and slash-terms commitment. R6.13 verifies complete signed evidence rather than trusting a caller's evidence hash, nullifies each accepted evidence/liability pair, consumes the exact live escrow, creates one equal fixed-safety-pool descendant, and records the result without changing total supply. The same objective fault may therefore slash every separately frozen liability for its validator, but cannot slash one liability twice. R6.14 stores the full evidence object in that immutable record. Ledger/checkpoint and audit-bundle validation re-resolve the exact historical Epoch/liability and re-verify evidence content hash, union shape, context, historical key, signatures, objective conflict, fixed slash rate and fault/applied-height ordering. Active and pending-unbond positions are handled explicitly; a pending request becomes a permanent `FULLY_SLASHED` tombstone with no payout. Registered stake escrows, unbond tombstones, slash records and complete accepted evidence are state-rooted and included in audit bundles. Production replica retention duration, repair proofs and disaster-recovery exercises remain separate activation requirements. Exact certified replay returns historical V1/V2 Lock, Migration, Request, Complete and Slash outcomes. This remains a fixed-set state-machine claim, not proof that dynamic membership, independent complete derivation or production operation is implemented.

The `stake_snapshot_root` preimage now has a frozen binary schema and one checked Rust/Python cross-language vector. That evidence establishes exact preimage and hash reproduction only. The Python verifier deliberately does not validate selection, proof of possession, ledger authority, state transitions or runtime adoption, and the vector marks every such claim false. “Independent implementations derive the complete descriptor” remains a later activation claim.

It must not claim that a submitted control group is a cryptographic proof of a real-world ultimate beneficial owner. That requires independently governed evidence, challenge, expiry and external review. Until those authorities and the mutation commands are implemented and audited, every result remains `DERIVED_ONLY`.

## Authoritative input boundary

An Epoch must never trust a network-supplied descriptor as authority. Its inputs are:

- the exact finalized Zone, currency genesis, Protocol Era, Crypto Era, parent height and parent state root;
- a versioned stake policy intended to be committed by the ledger, including a nonzero first-activation delay;
- validator candidates committed by the ledger, including owner, validator ID, strict Ed25519 consensus key, key era, registration height, exit state and proof of possession;
- stake positions committed by the ledger, each referencing one unique `Reserved` escrow `CoinObject` whose owner and amount exactly match the position;
- a versioned, non-expired control map intended to be committed by the ledger, with nonzero sequence, predecessor, verifier-set and evidence commitments;
- a nonzero Epoch anchor for the first record, or the exact preceding Epoch-chain record thereafter.

`StakeLedgerContextV1` can still be constructed by an ordinary caller; the name does not confer finality. The ledger command path instead reconstructs that context from the current `Ledger`, stores a canonical `STAGED_ONLY` authority, and derives the next record from the stored fields. `SubmitStakeAuthorityUpdate` is authorized by the current fixed validator and notary sets and is bootstrap-only. Once any authority exists, every later broad submission is rejected even if it claims to preserve the current bytes; policy, candidates, positions and UBO may change only through separately specified narrow commands. Tags 11 and 12 are the historical post-bootstrap candidate admission/exit paths; tags 10 and 15 are historical position-registration paths; tags 13/14 are historical unbond paths; tag 16 is slash-terms migration; tag 17 is liability-bound evidence slash; tags 18–24 govern and fund candidate/position/Epoch resource retention; tag 25 only appends an exact lease-renewal segment. None activates the derived Epoch as runtime membership.

## R6.13 consensus-command boundary

- `ConsensusCommand` tags `8` through `17` are `SubmitStakeAuthorityUpdate`, `DeriveNextStakeEpoch`, legacy `LockConsensusStake`, `RegisterConsensusValidator`, `ExitConsensusValidator`, `RequestConsensusStakeUnbond`, `CompleteConsensusStakeUnbond`, `LockConsensusStakeV2`, `MigrateConsensusStakeSlashTerms` and `SlashConsensusStake`. Their payloads use explicit `RLD-WIRE-V1` schemas rather than generic JSON maps.
- The authority update binds network, Zone, currency genesis, Protocol/Crypto Era, current proposal height/expiry, both predecessor commitments, the complete canonical authority view, the prospective ledger-owned authority commitment and the exact subject hash. Its validator and notary QC signer sets must be disjoint.
- The derivation request binds the same ledger identity and eras, current proposal height/expiry, exact authority sequence/commitment, exact next Epoch and exact current snapshot height/root.
- Both stake-lock requests bind Zone/currency/Eras, proposal/expiry height, exact authority sequence/commitment, position kind, direct validator candidate, owner, source Coin, amount and commitment-through height. V2 additionally binds a separately signed `ACCEPT_CONSENSUS_STAKE_SLASH_TERMS_V2` authorization into the `LOCK_CONSENSUS_STAKE_V2` mutation authorization. The two authorization IDs must differ and both become nullifiers atomically. Policy/derivation version 2 rejects new legacy V1 admission; policy version 1 may admit a V2-prepared position before a later narrow policy transition exists.
- The V2 slash policy is protocol-fixed: double sign, conflicting checkpoint and invalid state commitment each specify 10,000 basis points; maximum cumulative slash is 10,000 basis points; reporter reward is zero; destination is `RLD_CONSENSUS_SLASH_SAFETY_POOL_V2`. It contains no downtime or subjective-performance penalty. R6.13 implements only those fixed full penalties; partial or caller-selected penalties and destinations are invalid.
- Migration binds the exact active legacy position/escrow/owner and current authority predecessor. It requires separate terms and mutation authorizations, rejects any existing terms or unbond record, changes no Coin and no amount, and advances the authority and UBO predecessor chains exactly once.
- The unbond request binds Zone/currency/Eras, exact authority predecessor, position and escrow IDs, owner, beneficiary and requested withdrawal height under action `REQUEST_CONSENSUS_STAKE_UNBOND_V1`. The signer must be the registered position owner and the beneficiary must be that same owner. The ledger assigns the request height and freezes a request commitment; no governance command can cancel, shorten or re-add that position.
- The minimum withdrawal height is the maximum of request-effective height plus the current immutable bootstrap policy activation delay, the position's `committed_through_height`, and every matching derived validator record's `unbonding_height`. All additions are checked. Derivation had already required `committed_through_height >= exit_height + evidence_window`, so this conservatively preserves the obligation without recomputing old history from a later policy. Version-2 records freeze the exact per-position evidence deadline and signed-terms commitment used by tag 17.
- Completion tag 14 is permissionless only after maturity and must bind the exact pending request commitment and immutable beneficiary. It atomically marks the escrow `Consumed`, removes the active escrow registry entry and creates one equal `Spendable` child with the escrow as its only parent. A failed request or completion changes no live state and consumes no owner authorization nullifier.
- Registration binds the exact predecessor, owner, validator ID, key/key era, expiry and candidate-key PoP. `registered_height` is always the ledger's next height, never caller-selected, and a separately governed UBO entry must already exist. Exit binds the complete registered candidate, one future exit height, an owner authorization and a new candidate-key PoP. It cannot shorten the activation-delay notice or any already-derived Epoch; it is irreversible and prevents new locks to that candidate.
- Slash evidence is a fixed-shape union. `DOUBLE_SIGN` requires two canonically ordered valid vote statements from the liability's historical key for one exact parent/round but different proposal hash or state root. `CONFLICTING_CHECKPOINT` requires two canonically ordered valid checkpoint signatures for the same network/Zone/currency/Eras/protocol/Epoch/height/previous hash/validator/key era but different state roots. `INVALID_STATE_COMMITMENT` requires a valid historical proposer statement and a valid liability-key vote for that exact proposal hash and context whose expected state root differs from the proposal. Inactive union fields, wrong historical keys, noncanonical order, malformed signatures, context substitutions, identical statements and heights outside the liability's `[activation, exit)` interval fail closed.
- Tag 17 binds the current authority predecessor, exact derived-record hash, position/liability commitment, exact escrow and optional pending-unbond commitment. Evidence must be submitted strictly before the frozen evidence deadline. Acceptance persists the single-use nullifier `hash_parts("RLD-CONSENSUS-STAKE-SLASH-NULLIFIER-V1", evidence_hash, liability_commitment)`, consumes the exact escrow and creates one equal `Reserved` descendant owned by `RLD_CONSENSUS_SLASH_SAFETY_POOL_V2`; total supply is unchanged. Per-liability nullification is intentional: one signed objective fault can slash every independently frozen self-bond/delegation liability for that historical validator, while the same liability cannot be slashed twice. An active position is removed while advancing authority/UBO predecessors. A pending unbond becomes `FULLY_SLASHED` with its slash ID, full amount and completion height but no payout. A matured completed unbond is unreachable to slash because completion is no earlier than the liability deadline while slash acceptance is strictly earlier.
- Consensus-significant evidence verification orders failures as invalid Epoch, liability mismatch, union shape, context, liability window, historical key, canonical pair, encoding/signature, then absence of an objective fault. The ledger transition separately validates envelope/context/height/expiry, replay, authority predecessor, Epoch/liability/evidence, future-fault/deadline, exact live position/escrow/pending-unbond, then accounting. All failures occur on a staged clone and leave live state unchanged.
- All ten stake commands execute against a cloned ledger during certified commit. The clone replaces live state only after the expected post-height and post-root match. Replay of an already committed command returns the original authority, derived record, exact V1/V2/migrated stake position, exact historical candidate, exact pending/completed unbond record or immutable slash record even after later transitions.
- The generic durable-mutation/WAL envelope round-trips all eighteen adopted stake/resource command variants. One real certified value commit is fault-injected before WAL append, after WAL sync, before/after rollback-anchor replacement and before/after checkpoint replacement; recovery exposes only the complete old or complete new ledger. Real device/controller power loss, the unimplemented resource-bound unbond write set, signer/witness coupled recovery and multi-operator DR remain activation gates.
- Command-view heights and durations are currently unsigned 64-bit values because the running ledger and proposal height are `u64`; the derivation kernel retains `u128` deep-time heights. Mainnet requires an explicit, independently tested width migration before any value-bearing release can claim the master plan's deep-time counter invariant.
- No public node route constructs these commands. Acceptance through the generic certified-commit path is not permissionless staking UX and does not activate the resulting membership.

## R6.14 retained-evidence boundary

- `ConsensusStakeSlashRecordV1` retains the exact `ConsensusStakeSlashEvidenceV1`, not only its hash. Because slash records are in `Ledger::state_root`, serialized ledger/checkpoint state and `AuditProofBundle`, accepted signed evidence remains content-addressed and self-contained across reference-state restore.
- Restore validation does not trust the retained object. It locates the exact `consensus_epoch + derived_epoch_record_hash + liability_commitment + position_id`, runs the same objective-evidence verifier, and requires the recomputed evidence hash, evidence kind and fixed slash rate to match the record. The verified fault height must not exceed `applied_height`, and the application height must remain inside the frozen liability/deadline interval.
- Tests round-trip a ledger containing two liabilities slashed by one evidence object, reconstruct and verify the audit bundle, corrupt an archived signature, and substitute historical Epoch/liability references while recomputing the record hash. All corruptions fail closed without relying on a separate history service.
- This closes the reference-state availability gap only. R6.22B freezes codec-only tags 26/27 and worst-case unbond footprints, but runtime still rejects both commands and its first terminal-reservation prototype is explicitly rejected. R6.22C adds a private accounting-only V2 candidate. R6.22D freezes `UNBOND-RESERVATION-STATE-BINARY-V1`; Rust and independent Python now produce identical bytes/commitments for five full checkpoints and reject the same 12 binary mutation classes. Restore also requires an externally authenticated commitment and trusted full policy. It remains `unbond_reservation_state_primitive=false`: the state lacks network/Zone/genesis/Era/prestate binding, Policy V1 lacks CPU/proof pricing, and no typed real-Ledger read/write or persistence route exists. The system remains `VALUE_CAP_0`, fixed-membership and has no resource-bound unbond/slash-evidence/settlement path, pool payout, terminal bond settlement, value-bearing Era migration or dedicated construction route.

## Stake rules

- A stake ID, claimed source Coin ID and escrow Coin ID may contribute at most once. The claimed source ID must occur exactly once in the escrow Coin's strictly sorted, unique parent list and must differ from the escrow ID; a pure-kernel stake escrow has at most 16 parents. The public pure kernel does not verify the surrounding source/nullifier because that state is not among its inputs. The ledger-owned path is stricter: tags 10/15 require a unique `Spendable` source, consume it, create exactly one-parent escrow lineage and persist the single-use authorization nullifier in the same atomic transition.
- `SELF_BOND` requires the stake owner to equal the validator candidate owner.
- `DELEGATION` is direct from a Coin owner to one validator candidate. Re-delegation and delegation chains are not represented. The ledger command rejects delegations below the nonzero policy floor; transaction fees/state bonds for durable stake records are still required before value activation so attackers cannot consume the bounded state budget for free.
- The escrow Coin must exist, be `Reserved`, carry supply, remain owned by the recorded owner and equal the recorded amount.
- Zero amounts, unmatched Coin data, missing candidates and duplicate references fail the whole derivation.
- A candidate and its stake must be mature before the snapshot height according to the policy. Well-formed but pending, exiting, under-bonded or insufficiently committed records are excluded rather than allowed to stall every otherwise valid Epoch.
- Every counted position must remain committed through at least `exit_height + evidence_window`; an unbond request cannot shorten an already sealed obligation.
- Under policy/derivation version 2, a position without valid owner-signed V2 terms contributes zero weight. A malformed, wrong-owner, wrong-context or reused terms authorization fails the derivation rather than silently counting the position.
- Self bond and delegated weight are summed with checked `u128` arithmetic. Overflow fails the whole derivation.
- Protocol reserves, service escrows, in-transit Coins and any other non-stake `Reserved` object are not accepted merely because their Coin state is `Reserved`. The ledger authority requires an exact match in `consensus_stake_escrows`, keyed by escrow Coin ID; registry validation also requires the consumed source, owner, amount, lineage, version and lock height to match. Generic Coin consumption rejects a registered stake escrow. Only tag 14 may consume a pending matured escrow into its exact owner payout, and tag 17 may consume a V2-liability escrow into the fixed safety pool. The permanent completed or fully-slashed record preserves the original position and exact descendant lineage.

Frozen command additions:

| Tag / schema | Payload fields in field-number order |
|---|---|
| `13 / 0x102f RequestConsensusStakeUnbondV1` | request ID, Zone, genesis root, Protocol Era, Crypto Era, proposed height, expiry, authority sequence, authority commitment, position ID, escrow Coin ID, owner, beneficiary, requested withdrawal height, owner authorization |
| `14 / 0x1030 CompleteConsensusStakeUnbondV1` | completion ID, request ID, Zone, genesis root, Protocol Era, Crypto Era, proposed height, expiry, expected unbond-request commitment, beneficiary |
| `15 / 0x1031 LockConsensusStakeRequestV2` | V1 lock fields through commitment height, slash-terms authorization, mutation authorization |
| `16 / 0x1032 MigrateConsensusStakeSlashTermsV2` | request ID, Zone, genesis root, Protocol Era, Crypto Era, proposed height, expiry, authority sequence, authority commitment, position ID, escrow Coin ID, owner, slash-terms authorization, mutation authorization |
| `17 / 0x1037 SlashConsensusStakeV1` | slash ID, Zone, genesis root, Protocol Era, Crypto Era, proposed height, expiry, authority predecessor, consensus Epoch, derived-record hash, exact position/escrow/amount/liability, optional pending-unbond commitment, evidence hash and full evidence union (`0x1033..0x1036`) |

These append-only tags do not change tags 1–16 or their bytes. The independent command corpus contains an accepted tag-17 vector and rejects unknown tag 18.
- Maturity blocks same-block/flash funding but cannot prove that a holder has no off-chain loan, refund agreement, derivative hedge or common beneficial controller. Economic-security claims require external evidence, conservative haircuts and value caps in addition to this derivation.

## Control-map rules

- Assignments use one canonical order and cover every selected validator exactly once.
- Each assignment binds validator ID, control group, evidence root and validity window.
- The map binds a nonzero sequence, predecessor commitment and verifier-set commitment.
- Every counted assignment must be observed at a finalized height strictly after its public challenge period ends and must remain valid through `exit_height + evidence_window`.
- A structurally malformed/empty map fails the derivation. A candidate with no current, post-challenge assignment is ineligible; every selected validator must have exactly one qualifying assignment.
- Eligible candidates are first grouped by control group. Each group contributes at most one representative: greatest eligible weight wins, with validator ID UTF-8 byte order ascending as the tie-breaker. The global maximum-validator limit is applied only after this group-first reduction. This prevents one minority controller from filling all Top-N slots with aliases and blocking an otherwise safe independent set.
- The non-representative aliases contribute no selected voting weight. Their candidate, stake, UBO and referenced Coin records remain committed by the complete snapshot, so the reduction is auditable and cannot erase the input evidence.
- Any selected group above `total_weight - quorum_power` fails the Epoch; the implementation must not rename a group or count more than one representative from it.
- On mainnet, a valid Epoch requires at least 21 selected validators and 21 distinct qualifying control-group assertions. A test-only context may use the protocol minimum of four. Distinct strings and evidence commitments do not prove distinct real-world controllers; that remains an external-audit gate.

## Deterministic selection and height rules

1. Freeze the pre-scheduled finalized snapshot height and state root. For every Epoch, not only the first, `snapshot_height == activation_height - activation_delay`; the caller cannot choose a later favorable snapshot.
2. Resolve the next Epoch number from the anchor or prior record.
3. For the first record, set activation to `parent_height + activation_delay`. For later records, activation must equal the previous record's exclusive exit height.
4. Compute `exit_height = activation_height + epoch_length` and `slashable_until = exit_height + evidence_window` with checked arithmetic.
5. Filter only mature, non-exited candidates whose eligible stake stays slashable through `slashable_until` and whose control assignment remains valid through that height.
6. Partition eligible candidates by control group and choose exactly one deterministic representative per group: weight descending, then validator ID UTF-8 bytes ascending.
7. Rank the group representatives by weight descending and validator ID UTF-8 bytes ascending, then select no more than the configured maximum.
8. Emit `ValidatorRecord` values in the canonical order required by `ConsensusEpochDescriptor`, not ranking order.
9. Recompute total weight, strict two-thirds quorum and control-group limits. Never accept caller-declared totals.
10. Hash the complete canonical snapshot and use it as `stake_snapshot_root`.
11. Validate the generated descriptor with the existing structural validator.

All height calculations use checked `u128`. The existing node ledger still persists a `u64` height; conversion or wire-width unification is a separate release gate and no narrowing conversion may be implicit.

## Frozen stake-snapshot preimage

`stake_snapshot_root = hash_parts("RLD-LEDGER-STAKE-SNAPSHOT-V1", preimage)`, where `hash_parts` prefixes each part with its unsigned 64-bit big-endian byte length and applies SHA-256. The preimage is not Serde JSON. Every structure uses this envelope:

| Bytes | Meaning |
|---|---|
| `52 4c 44 53` | ASCII `RLDS` magic |
| `u16be` | encoding version, fixed at `1` |
| `u16be` | schema ID |
| `u16be` | field count |
| repeated | `field_id:u16be`, `kind:u8`, `length:u32be`, then exactly `length` value bytes |

Field IDs are nonzero and strictly increasing. Unsigned integers and `Amount` are fixed-width big-endian. Text is exact UTF-8; the ordinary input validator requires bounded, trimmed, control-free NFC text before derivation. A list is `count:u32be` followed by `item_length:u32be || item` for each member. `OPTION_U128` is `00` for absent or `01 || u128be`; `OPTION_TEXT` is `00` or `01 || utf8_length:u32be || utf8`. No trailing bytes, omitted fields, alternative integer widths or reordered fields are canonical.

Frozen kind codes are: `TEXT=01`, `U16=03`, `U64=04`, `U128=05`, `HASH32=06`, `KEY32=07`, `SIGNATURE64=08`, `AMOUNT=09`, `OPTION_U128=0a`, `OPTION_TEXT=0b`, `STRUCT=0c`, `STRUCT_LIST=0d`, `TEXT_LIST=0e`, and `ENUM_U8=0f`. Hashes, keys and signatures decode from canonical lowercase hex to exactly 32, 32 and 64 raw bytes.

Frozen schemas and fields are:

| Schema ID | Name | Ordered fields (`id:kind`) |
|---|---|---|
| `0001` | snapshot | `1:U16 derivation_version`, `2:STRUCT context`, `3:STRUCT policy`, `4:STRUCT anchor`, `5:STRUCT_LIST candidates`, `6:STRUCT_LIST positions`, `7:STRUCT ubo_map`, `8:STRUCT_LIST referenced_coins` |
| `0002` | context | `1:TEXT network`, `2:TEXT zone`, `3:HASH32 genesis`, `4:U64 protocol_era`, `5:U64 crypto_era`, `6:U64 consensus_version`, `7:U128 finalized_height`, `8:HASH32 finalized_root` |
| `0003` | policy | `1:U16 version`, `2:AMOUNT minimum_self_bond`, `3:AMOUNT minimum_delegation`, `4:U128 candidate_maturity`, `5:U128 stake_maturity`, `6:U128 evidence_window`, `7:U128 activation_delay`, `8:U128 epoch_length`, `9:U16 maximum_validators` |
| `0004` | anchor | `1:U64 epoch`, `2:U128 activation_height`, `3:U128 snapshot_height`, `4:HASH32 snapshot_root`, `5:HASH32 record_chain_anchor` |
| `0005` | candidate | `1:TEXT validator_id`, `2:TEXT owner`, `3:KEY32 public_key`, `4:U64 key_era`, `5:U128 registered_height`, `6:OPTION_U128 exit_height`, `7:SIGNATURE64 proof_of_possession` |
| `0006` | position | `1:TEXT position_id`, `2:ENUM_U8 kind`, `3:TEXT validator_id`, `4:TEXT owner`, `5:TEXT source_coin_id`, `6:TEXT escrow_coin_id`, `7:AMOUNT amount`, `8:U128 locked_height`, `9:U128 committed_through_height` |
| `0007` | UBO map | `1:U16 version`, `2:U64 sequence`, `3:HASH32 predecessor`, `4:HASH32 verifier_set`, `5:HASH32 evidence_root`, `6:STRUCT_LIST records` |
| `0008` | UBO record | `1:TEXT validator_id`, `2:TEXT control_group`, `3:U128 valid_from`, `4:U128 challenge_ends`, `5:U128 valid_through`, `6:HASH32 evidence_hash` |
| `0009` | Coin | `1:TEXT object_id`, `2:TEXT lineage_root`, `3:TEXT_LIST parent_ids`, `4:TEXT owner`, `5:TEXT zone`, `6:AMOUNT amount`, `7:ENUM_U8 state`, `8:U64 version`, `9:U64 created_height`, `10:OPTION_TEXT transit_id`, `11:OPTION_TEXT imported_from`, `12:TEXT origin_zone`, `13:HASH32 origin_genesis_root` |
| `000a` | staged authority commitment | `1:U16 authority_version`, `2:ENUM_U8 status`, `3:TEXT network`, `4:TEXT zone`, `5:HASH32 genesis`, `6:U64 protocol_era`, `7:U64 crypto_era`, `8:U64 consensus_version`, `9:U64 sequence`, `10:HASH32 previous`, `11:U128 source_height`, `12:HASH32 source_root`, `13:U128 effective_height`, `14:STRUCT policy`, `15:STRUCT_LIST candidates`, `16:STRUCT_LIST positions`, `17:STRUCT ubo_map` |
| `000b` | V2 position | fields `1`–`9` equal schema `0006`; `10:STRUCT slash_terms` |
| `000c` | V2 slash policy | `1:U16 version`, `2:U16 double_sign_bps`, `3:U16 conflicting_checkpoint_bps`, `4:U16 invalid_state_commitment_bps`, `5:U16 maximum_cumulative_bps`, `6:U16 reporter_reward_bps`, `7:TEXT safety_pool` |
| `000d` | V2 slash terms | `1:U16 terms_version`, `2:STRUCT slash_policy`, `3:TEXT authorization_id`, `4:TEXT zone`, `5:HASH32 genesis`, `6:U64 protocol_era`, `7:U64 crypto_era`, `8:KEY32 owner_key`, `9:TEXT action`, `10:HASH32 payload_hash`, `11:U64 nonce`, `12:SIGNATURE64 signature` |

Stake-position kind codes are `SELF_BOND=01`, `DELEGATION=02`. Coin state codes are `SPENDABLE=01`, `RESERVED=02`, `IN_TRANSIT=03`, `RETURNING=04`, `QUARANTINED=05`, `CONSUMED=06`; staged-authority status is `STAGED_ONLY=01`. Candidates sort by validator ID bytes then public-key hex-text bytes. Positions sort by position ID bytes then escrow Coin ID bytes. UBO records sort by validator ID bytes. Referenced Coins appear in canonical position order. The full preimage and every nested/list buffer are bounded by 64 MiB.

The frozen encoding-only vector is `vectors/stake-epoch-v1/snapshot-encoding.json`, protected by its SHA-256 sidecar. Rust consumes the same logical JSON and checks the exact preimage/root. `tools/independent-verifier/verify_stake_epoch_snapshot_vectors.py` independently implements the binary framing and hash with the Python standard library; it does not import Rust code or generated bytes.

## V2 position liability root

For derivation version 2, each counted position produces one `ConsensusStakeEpochLiabilityV2`. The liability freezes the exact embedded position and terms, consensus Epoch, selected validator public key/key era, activation height, exclusive exit height, evidence-window length, exact evidence deadline, slash-terms commitment and its own commitment. Liabilities sort by position ID. The root is `hash_parts("RLD-CONSENSUS-STAKE-EPOCH-LIABILITY-ROOT-V2", liability_commitment...)`; the V2 derived-record hash binds that root.

Strict record validation re-verifies every retained owner signature, requires unique position/escrow/authorization IDs and canonical ordering, recomputes every liability commitment and root, checks `deadline = exit + evidence_window`, and reconstructs each descriptor validator's self bond, delegated weight, total weight and minimum unbonding height from the liabilities. V1 records remain byte/JSON compatible by requiring the zero liability root and an empty list and omitting both fields on serialization. R6.13 uses this exact liability for executable evidence verification and slash accounting, with Rust tests for every evidence kind, key/window/context/shape/order/signature rejection, active slash, pending-unbond slash, multi-liability use of one objective fault, per-liability replay rejection, supply conservation and certified replay. R6.14 also proves retained-evidence ledger/audit round-trip and restored cryptographic revalidation. A second complete independent derivation/evidence implementation remains absent.

## Epoch chain

The required activation path is:

```text
CoinObject
  -> ConsensusStakePosition
  -> per-validator allocation
  -> stake_snapshot_root
  -> ConsensusEpochDescriptorCommitment
  -> LedgerDerivedStakeEpochRecord
  -> ledger state root
  -> ContinuityCheckpoint
```

The public kernel stops at `LedgerDerivedStakeEpochRecord`. R6.14 can store the authority, V1/V2 owner-authorized escrow, exact signed-terms migration, narrow candidate registration/exit, delayed unbond request/completion, derived V2 liability root and accepted evidence slash through fixed-set certified commands; the ledger root and `AuditProofBundle` include active, completed and fully-slashed lineage plus each complete accepted signed evidence object. The current evidence proves the three exact evidence shapes, historical key/window binding, atomic full-slash accounting, exact certified replay, supply preservation, self-contained ledger/audit recovery and command-envelope round-trip. It does not prove a second independent complete implementation, production archival retention, the full process-crash/interruption recovery sequence or dynamic-set adoption.

The first record references a nonzero `ConsensusEpochAnchor`. Every later record must satisfy:

- `epoch == previous.epoch + 1`;
- `activation_height == previous.exit_height`;
- `previous_epoch_record_hash == hash(previous)`;
- identical Zone, currency genesis, Protocol Era, Crypto Era and consensus protocol context;
- one unique successor for the preceding record once the chain is ledger-owned.

The public function rejects a supplied gap, overlap, rollback, jump or missing/zero predecessor. The ledger command derives the next number and predecessor itself, stores at most one record per Epoch key, and its certified parent-root chain prevents two different results from occupying the same committed ledger history under the present fixed-set safety assumptions. This does not prove safety after runtime membership changes, long-range attacks, key compromise or a broken fixed-set BFT assumption. The derived descriptor commitment remains a different Rust type from the frozen `030f ConsensusValidatorSet` digest.

## Resource bounds

- Candidate, stake and assignment collections are rejected before expensive work above 16,384 candidates, 262,144 stake positions or 16,384 control records. Frozen snapshot encoding uses bounded buffers and fails above 64 MiB.
- The selected validator set is limited to 4096 records.
- No recursive delegation traversal is allowed.
- Duplicate IDs and Coin references are rejected with bounded sets before aggregation.
- Descriptor distribution is outside this slice. Future Proposal and Vote messages must carry only a fixed-size Epoch commitment, not an inline multi-megabyte descriptor.

## Required negative tests

- missing, consumed, spendable, wrong-owner or wrong-amount escrow Coin;
- one Coin or stake counted twice;
- forged/replayed owner authorization, stale authority predecessor, source Coin reuse, ordinary `Reserved` Coin injection and attempted generic consumption of a registered stake escrow;
- candidate registration backdating, missing governed UBO entry, duplicate ID/key, invalid candidate-key PoP, owner mismatch, early/repeated exit, exit that truncates a derived Epoch, and broad-governance candidate injection/removal/rewrite after bootstrap;
- zero/insufficient self bond, below-floor delegation and delegation without a candidate;
- immature same-block stake and an unbond window shorter than the evidence window;
- forged unbond owner, changed beneficiary, early completion, duplicate request/completion, authority reintroduction, derived-Epoch truncation and delay arithmetic overflow;
- forged/reused V2 terms authorization, V2 legacy admission, position/owner/escrow substitution during migration, double migration and migration of an unbonding position;
- missing V2 terms removes weight; tampered liability amount, owner, validator key, evidence deadline, terms commitment, order or root fails strict record validation;
- weak, non-canonical or non-prime-subgroup Ed25519 key and invalid proof of possession;
- unsorted, duplicate, missing, expired or conflicting control assignments;
- one UBO split across aliases that exceeds the tolerated weight;
- a minority control group split across enough aliases to occupy the old global Top-N while enough independent groups remain available;
- total, per-validator, group or height overflow;
- fewer than 4 test validators, fewer than 21 mainnet validators or more than 4096 validators;
- missing/zero anchor, Epoch rollback, gap, overlap or jump;
- mutation of any stake, candidate, control map, policy, parent root or predecessor changes the appropriate commitment;
- insertion-order independence for logically identical maps;
- existing wire vectors remain byte-for-byte unchanged;
- no node, signer, witness, Proposal, Vote, QC, TC or WAL code references the derived Epoch as an active authority;
- the executable safety case remains `INCOMPLETE / VALUE_CAP_0`.

## Next activation gates

After the current staged/derived command slice, the following remain mandatory:

1. retain tags 10 through 17 as the only historical/replay stake lock, candidate registration/exit, delayed-unbond, slash-terms migration and exact-evidence slash paths, preserving full-penalty, fixed-destination and historical-liability semantics. The independent Python verifier covers the frozen evidence/archive-validation slice, but a second full ledger/Epoch derivation/slash-transition implementation and adversarial audit remain mandatory;
2. retain the frozen R6.22B fee-only mutation, worst-case terminal footprint and tags 26/27 codecs. R6.22D now has a private V2 accounting candidate with one normative binary codec/commitment shared byte-for-byte by Rust/Python. Before Ledger adoption, add Policy V2 CPU/proof prices and a typed complete Ledger read/write catalog, including trusted execution-context keys, lock ordering, worst-case work and stable error priority. Only after that may the state enter one atomic resource-bound unbond request/completion path against the R6.22A position-liability horizon before closing historical tags 13/14 for new writes. After that cover slash-evidence responsibility and terminal settlement one at a time. No old tag or stake principal gains implicit charging authority;
3. extend the six-boundary certified-value recovery regression to the completed unbond/slash/settlement write sets, signer heads and witness heads, then run real power-loss/device/filesystem and multi-operator recovery exercises. Production evidence retention must also satisfy `docs/operations/SLASH_EVIDENCE_RETENTION.md`, including independent replicas, possession challenges, dual-source repair, offline reconstruction, overlapping migrations and destructive exercises; current evidence must not be pruned;
4. previous-Epoch, rather than bootstrap fixed-set, authorization of each successor after activation, with a transition rule and long-range recovery design that remain safe across membership changes and reject competing siblings;
5. a permanent descriptor/record wire schema and independent complete-derivation vectors; the snapshot-preimage schema and one encoding-only Rust/Python vector are frozen, but they do not cover descriptor selection, V2 liability derivation or signatures;
6. one authoritative Epoch resolver used identically by Proposal, Prepare, Commit, Timeout, ViewChange, catch-up, signer and witness verification;
7. independent implementations, external UBO review, multi-operator deployment and completed mainnet evidence.

Until every gate is satisfied, the fixed round-zero validator set remains the only runtime path and `VALUE_CAP_0` remains mandatory.
