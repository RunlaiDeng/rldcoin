# Selected-plan joint BFT epoch ground candidate

This source adds a separately signed admission:
`RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1`. It is an incompatible no-value
candidate. The legacy BFT profile and the all-participant BFT epoch profile
keep their existing authorization and thresholds. Every changed native source
requires a fresh signed fixture currency/genesis; no balances or private state
migrate from earlier fixtures, retired mainnet or an adopted network.

## Selection before sealing

The old four-validator set first chooses a `Reconfigure` plan in a normal block
using three ordered prepare and commit votes. The command pins currency,
region, old epoch, next epoch number and four ordered new validator keys. The
block commits all command bytes. A plan may share the block with fully signed
owner payments; it creates no allocation or alternate value execution path.
Execution checks the native-verified epoch prefix active at that exact height,
not a later carried membership. More than one plan in a block refuses.

No fence is possible before that closing block has a complete old certificate
and native owner/value replay. Once selected, old-era successor proposals,
votes and timeout signing refuse. Existing durable prepare locks and highest-QC
view changes still govern competition before selection. A selected plan cannot
be replaced by distributing different handoff requests to different signers.

`Transition.selection` carries the complete exact closing block. Its command
commitment, header, plan fields and fully replayed retained snapshot must match.
The activation statement uses the distinct `RLD-BFT-JOINT-EPOCH-V1` marker and
`joint-epoch-handoff-v1` signing domain. Other profiles refuse these fields;
joint activation refuses absent, changed or legacy selection/domain.

## Durable old and new approval

Three distinct ordered old-key approvals come only from `EpochFence` records
persisted in their original BFT journals. Three distinct ordered new-key
approvals come from native candidate journals and bind the same statement.
Both sets have exactly four equal members. Current candidate sets must be
disjoint and historically unused. Unknown, duplicate, unordered, under-quorum
or wrong-role signatures refuse. Every expanded finality, era, current incident,
owner and value check remains mandatory; hashes alone grant no authority.

No missing receipt or local timeout unseals an old key, removes evidence or
refunds value. Incomplete activation and separately retained latest caller
heads must survive. Exact retained old responses may recover without a key;
recover-only cannot first-sign. A stale signer backup cannot override a
surviving latest caller head. All-state/head rollback and copied-key concurrent
custody remain unqualified.

The native store installs a complete transition as an explicit epoch event,
without changing balances. Ordinary local replay refuses a missing epoch event.
Remote checkpoint replay stages already verified exact activation, fully
checks the new suffix, and publishes neither authority nor state for an invalid
tail. New ordinary blocks still need three prepare and three commit votes.
Historical keys cannot return; fresh BFT journals start only at the exact
installed activation boundary.

## Scope and unresolved gates

The companion ceremony remains controller-carried. Individual epoch approvals
are not ordinary BFT mesh control messages; no automatic config/key switch is
implemented. Missing signer exercises must state whether native replicas still
receive controller-carried certificates. A same-host three-signature sample
does not demonstrate independent operators, sustained Byzantine faults,
network partition/reconfiguration liveness, custody or power-loss recovery.
No all-state rollback, arbitrary overlapping membership, cancellation,
long-history/BFT-era execution, compact complete authority or physical route
qualification is claimed. All existing native/evidence/archive bounds remain.

Design background: the original [HotStuff paper](https://arxiv.org/abs/1803.05069)
defines a partially synchronous BFT protocol; its proof does not qualify this
candidate's changed membership path. The primary
[Diem epoch-change proof implementation](https://diem.github.io/diem/src/diem_types/epoch_change.rs.html)
chains verification from a trusted epoch/waypoint through signed ledger epoch
changes. These references motivate explicit certified selection and chained
authority; no third-party proof, implementation or independent validation is
inherited. RLDCOIN I1–I12 remain separate acceptance requirements.

## Fresh local reproduction

Build from the exact frozen source with Rust 1.98 and checked release arithmetic.
Use `contact-fixture bootstrap --bft-joint` only for new public-key ground
fixtures. Run native tests, process regressions and
`tools/regional_bft_joint_epoch_campaign.py` with a new private root. Preserve
failed roots and original source/report bytes; never publish keys, journals,
caller state, wallets, transport/TLS state or generated restoration images.
