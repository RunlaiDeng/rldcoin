# Rldcoin bounded safety models

This directory contains four independent, deliberately bounded TLA+ models for
Rldcoin safety requirements: `RldcoinProtocol.tla` covers protocol/value
state machines, while `RldcoinCrashConsistency.tla` covers operation-WAL crash
recovery and persistent BFT vote locking. `RldcoinBftViewChange.tla` covers a
fixed-validator Byzantine view change, QC/timeout rules, persistent lock/highQC,
and authenticated continuous catch-up. `RldcoinIsolatedSigner.tla` covers the
typed, independently persistent consensus-signer boundary between an untrusted
node and a validator key. They are executable abstractions, not
refinement proofs of the Rust implementation and not evidence that a real-value
network is safe to launch.

## What the model checks

The safe configuration exhaustively explores a bounded composition of four
state machines:

1. one tracked UMCO and its source export, target import/rejection, refund,
   Transit Nullifier, fee entitlement, and fee Nullifier;
2. two competing BFT blocks with four equal-weight validators, one Byzantine
   validator, an honest one-block voting lock, and a three-vote quorum;
3. protocol-enforced `VALUE_CAP_0..3` activation and local, cross-Zone, and DSC
   value exposure, including calls attributed to the protocol, frontend,
   administrator, and a legacy client. Upgrades bind a MainnetSafetyCase hash,
   require two independent approval groups and a logical-height challenge
   period, and fail when evidence is expired. Risk deterioration atomically
   downshifts to cap 0, freezes new exposure, and preserves prior exposure;
4. a two-step Crypto Era migration that disables the classic suite and permits
   only the hybrid suite afterward.

The checked invariants are:

- fixed supply across source, transit, destination, return escrow, fee escrow,
  and fee pool;
- exactly one canonical location for the tracked UMCO;
- mutually exclusive import/rejection use of the Transit Nullifier;
- at-most-once claim of the target-bound fee entitlement;
- a timeout alone cannot authorize a refund;
- a final target rejection makes every later import fail;
- strictly less than one-third Byzantine voting weight cannot finalize both
  competing blocks under the configured quorum and honest vote lock;
- no caller class can bypass `VALUE_CAP_0`, staged cap permissions, the
  single-transfer ceiling, or path exposure ceilings;
- cap increases are only one level at a time, pending, delayed, safety-case
  bound, unexpired, and approved by both modeled governance groups;
- frontend, administrator, and legacy-client direct cap changes are rejected;
- safety-case expiry blocks both new cap activation and all runtime value
  acceptance under an already-active cap;
- risk deterioration immediately cancels pending upgrades, downshifts to cap
  0, freezes new exposure, and neither rolls back exposure nor changes supply;
- a suite disabled by the active Crypto Era cannot be accepted by downgrade.

## Independent crash-consistency model

`RldcoinCrashConsistency.tla` explores every interleaving in a bounded
operation sequence:

```text
append WAL records -> fsync complete WAL -> advance rollback anchor
-> publish state -> checkpoint success/failure -> recover
```

Recovery may be invoked at every modeled crash point. A complete fsynced WAL
recovers a complete new state; an intact old checkpoint without a WAL recovers
the complete old state; and truncated, out-of-order, bad-previous-root,
bad-record-hash, or old-checkpoint-plus-short-WAL input fails closed. No
transition produces a mixed recovered state. A failed checkpoint preserves the
already committed WAL.

The independent voter state machine treats `proposal-a` and `proposal-b` as
conflicting proposals for the same height and round. An honest signer must
persist its vote lock before signing. Crash clears only the volatile lock, and
recovery reloads the persistent lock, so the signer cannot vote for the
conflict after restart.

The crash model checks:

- un-fsynced state is never published;
- published state always retains a durable recovery source;
- recovery from a complete WAL is all-old or all-new, never mixed;
- every modeled malformed or inconsistent WAL fails closed;
- rollback-anchor freshness never decreases locally;
- checkpoint failure cannot erase a committed WAL;
- an honest signer emits at most one vote for the modeled height/round and
  every emitted vote has a durable lock.

A whole-directory rollback that consistently replaces the checkpoint, WAL,
rollback anchor, and vote-lock data with an older snapshot is intentionally
indistinguishable from that older state using only local directory contents.
The dedicated failing configuration records this as an open gate requiring an
external monotonic witness, hardware counter, or independently held
checkpoint.

## Independent BFT view-change and catch-up model

`RldcoinBftViewChange.tla` bounds the system to four equal-weight validators,
one Byzantine validator, a 3-of-4 quorum, four views, two heights, and one
representative honest crash/restart. It models leader selection, Byzantine
leader equivocation, durable vote locks, persistent highQC, vote/commit QCs,
timeout certificates, stale messages, an initial partition, eventual
synchrony, and lagging-node commit catch-up.

The full consensus safety graph explores single-height cross-view quorum/lock
interleavings. A separate two-height catch-up graph checks certificate,
height, and parent-root continuity. A finite fair temporal configuration then
checks the explicit sequence from partition recovery through two honest
commits and two-step catch-up. This is a bounded progress witness, not an
unbounded partial-synchrony liveness proof.

Its safe configurations check:

- conflicting roots cannot both receive commit QCs at one height;
- an honest validator cannot vote twice in one view or switch roots at one
  height;
- every honest vote follows a durable lock, and lock/highQC survives restart
  without height regression;
- Byzantine plus stale messages cannot manufacture a vote QC or timeout
  certificate without a real 3-of-4 quorum containing two honest validators;
- committed children extend a certified parent;
- catch-up accepts only received authenticated commits, never skips a height,
  and never crosses parent roots.

## Independent isolated-signer model

`RldcoinIsolatedSigner.tla` bounds one untrusted node, one isolated validator
signer, two conflicting proposals for one parent instance, node WAL heads
`0..2`, and signer crash/restart. The node may present a second conflicting but
syntactically valid-looking authorization; the signer must still enforce its
own proposal/vote locks. A safe vote follows node durable lock, exact external
witness authorization, typed request validation, signer-state persistence, and
only then signature release. Proposal signing has its own persistent
one-proposal-per-parent lock.

The model checks that:

- there is no arbitrary-byte signing capability and a mismatched pinned key
  cannot receive a signature;
- every released vote has both an exact witness authorization and a durable
  signer authorization;
- every released proposal has a durable signer authorization;
- conflicting votes or proposals for one parent instance cannot both be
  signed, including after restart;
- the signer's independently persistent monotonic head never regresses; and
- a crashed/unavailable signer has no pending request that can release a
  signature.

The safe graph is deliberately hostile to the node but abstracts cryptographic
verification, exact wire bytes, policy parsing, distinct witness operators,
transport authentication, filesystem semantics and hardware non-resetability.

## Exact finite bounds

| Parameter | Bound |
|---|---:|
| Total modeled supply | 3 abstract runlai |
| Tracked principal / fee | 1 / 1 abstract runlai |
| Transit capsules / tracked UMCOs | 1 / 1 |
| Competing blocks | 2 |
| Validators | 4 equal-weight validators |
| Byzantine validators | 1 (`1/4 < 1/3`) |
| Finality quorum | 3 of 4 |
| Value caller classes | 4 |
| Value paths | local, cross-Zone, DSC |
| Per-transfer and per-path limit | 1 abstract runlai |
| Value-cap levels | 4 (`0..3`) |
| Staged risk permissions | local at cap 1, cross-Zone at cap 2, DSC at cap 3 |
| Logical heights | `0..4` |
| Challenge period / safety-case expiry | 1 / height 4 |
| Upgrade authorization | 2 of 2 independent groups |
| MainnetSafetyCase identities | 1 content-hash model value |
| Crypto Eras / suites | 2 / 2 |
| Isolated signers / untrusted nodes | 1 / 1 |
| Conflicting signer proposals | 2 for one parent instance |
| Node and signer monotonic heads | `0..2` |

Crash-model bounds are one operation split into two WAL records, one old and
one new state root, anchor epochs `0..1`, one checkpoint, two conflicting
same-height/same-round proposals, and one honest signer. WAL corruption is an
enumerated fault class rather than a byte-level filesystem model.

These bounds are intentionally reviewable. Passing them says only that TLC did
not find an invariant violation inside this abstraction and state space.

## Reproduce

Requirements: Java 11 or newer, `curl`, and POSIX shell tools available on
macOS/Linux.

```sh
./formal/run-model-checks.sh all
./formal/run-crash-model-checks.sh all
./formal/run-bft-model-checks.sh all
./formal/run-signer-model-checks.sh all
```

The runner downloads the official TLA+ tools release `v1.7.4` only when absent,
then requires both of these digests before execution:

```text
SHA-1   bee4a54f3ee3d4afc347c3240ec2d9e93b075104
SHA-256 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
```

The SHA-1 is the checksum published with the upstream release. SHA-256 is
additionally pinned by this repository. The downloaded JAR and run logs live in
ignored `formal/.tools/` and `formal/out/` directories. TLC state files are
created under a uniquely named ignored `formal/out/.tlc-*` directory and the
runner deletes that exact directory after every pass or expected failure.
Legacy/default `formal/states/`, `*.st`, `*.fp`, temporary files, and `MC.out`
are also ignored, but a clean completed run should leave none of them behind.

Run only one group with `safe` or `counterexamples`. Override the cache/output
locations with `TLC_CACHE_DIR` and `TLC_OUTPUT_DIR`.

## Deliberately failing mutations

Each counterexample configuration enables one unsafe transition or rule and is
required by the runner to fail on the named invariant:

| Configuration | Injected defect | Expected violation |
|---|---|---|
| `timeout-refund.cfg` | timeout unlocks source without a target rejection | refund authorization |
| `timeout-refund-double-spend.cfg` | the refunded source is followed by a late target import | fixed supply |
| `late-import-after-rejection.cfg` | importer ignores the rejected Transit Nullifier | Transit uniqueness |
| `duplicate-fee-claim.cfg` | fee claimant ignores the claimed fee Nullifier | fee uniqueness |
| `weak-quorum.cfg` | finality threshold is weakened from 3 to 2 | no double finality |
| `value-cap-bypass.cfg` | caller bypasses `VALUE_CAP_0` and amount/path ceilings | value-cap enforcement |
| `unauthorized-upgrade.cfg` | frontend/admin/legacy caller directly activates cap 1 | authorized upgrades only |
| `challenge-period-not-met.cfg` | fully approved upgrade activates before its logical challenge height | challenge-period enforcement |
| `expired-safety-case-upgrade.cfg` | pending upgrade activates after its bound safety case expires | fresh safety case on activation |
| `expired-safety-case-value-acceptance.cfg` | an already-active cap accepts new value after its safety case expires | runtime evidence freshness |
| `crypto-downgrade.cfg` | verifier accepts classic after Era 2 disables it | no downgrade |

The independent crash-consistency runner also requires these mutations to
fail:

| Configuration | Injected defect | Expected violation |
|---|---|---|
| `sign-before-lock.cfg` | signer emits a vote before its lock is fsynced | no honest double vote |
| `partial-wal-ignored.cfg` | recovery treats malformed/short WAL as the old state | corrupted WAL fails closed |
| `anchor-rollback.cfg` | locally visible rollback anchor moves backward | anchor monotonicity |
| `checkpoint-overwrites-wal.cfg` | failed checkpoint erases the committed WAL | committed WAL preservation |
| `vote-lock-lost-on-recovery.cfg` | restart drops the persistent vote lock | no honest double vote |
| `whole-directory-rollback.cfg` | every local freshness artifact is rolled back consistently | external rollback witness required |

The BFT runner requires these additional mutations to fail:

| Configuration | Injected defect | Expected violation |
|---|---|---|
| `delete-persistent-lock.cfg` | restart deletes an honest signer's lock | same-height honest root consistency |
| `skip-qc-validation.cfg` | Byzantine vote plus stale messages is accepted as a QC | real QC quorum |
| `skip-parent-root-check.cfg` | catch-up accepts a certified child of another root | continuous catch-up chain |
| `bad-timeout-rule.cfg` | stale messages create a timeout certificate without quorum | timeout-certificate quorum |
| `drop-high-qc-on-recovery.cfg` | restart loses persistent highQC | highQC monotonicity |
| `catchup-without-cert.cfg` | lagging node applies an uncertified commit | certified catch-up only |

The isolated-signer runner requires these mutations to fail:

| Configuration | Injected defect | Expected violation |
|---|---|---|
| `raw-signing-api.cfg` | signer exposes an arbitrary-byte signing path | no raw signing capability |
| `bypass-witness-quorum.cfg` | signer releases a vote without exact witness authorization | every vote has exact witness authorization |
| `sign-before-persist.cfg` | signer releases a vote before its own authorization is durable | every vote has durable signer authorization |
| `lose-locks-on-recovery.cfg` | restart erases proposal/vote locks | at most one vote per parent instance |
| `rollback-signer-state.cfg` | signer storage rolls back below its maximum durable head | signer monotonic head never regresses |
| `bypass-key-pin.cfg` | request for a different validator key is accepted | pinned validator key is mandatory |

## Explicit non-claims and omitted assumptions

- Neither model parses bytes, supplies real filesystem/power-loss semantics,
  verifies signatures/QCs, proves execution or data availability, models
  weighted/dynamic validator sets, or proves network scheduling, liveness,
  DoS economics, ownership authorization, governance thresholds, or
  `u128/u256` arithmetic.
- The crash model verifies only its bounded abstract state machine. It is not a
  Rust refinement, does not establish that every platform honors `fsync` or
  atomic rename as assumed, and does not prove recovery or consensus liveness.
- The BFT progress property covers one explicit 17-transition weakly fair
  schedule after synchrony. It does not prove arbitrary-network liveness,
  weighted/dynamic BFT, real signature/QC verification, or the Rust consensus
  and catch-up implementation.
- The isolated-signer model does not prove that a software service is an HSM,
  that storage cannot be reset by its operator, that TLS peers or witness
  control domains are independent, or that a compromised host cannot tamper
  with IPC. It defines a bounded reference safety contract only.
- It assumes valid export/proof predicates wherever the abstract transition is
  enabled. It checks state-machine consequences, not cryptographic soundness.
- It models one transfer and one fee entitlement; identifier construction and
  collision resistance remain outside the model.
- The value-limit counters are monotonic bounded exposures. This model covers
  delayed one-level cap upgrades, two abstract authorization groups, immediate
  fail-closed risk downshift, and one safety-case expiry. It does not cover
  safety-case renewal, multiple competing cases, real validator weights,
  per-account/Zone/source-group limits, or global multi-Zone aggregation.
- Equal voting weight and a static validator set are not a substitute for the
  planned `OpenContributionBFT` specification; RLD holdings and stake must not
  buy contribution tickets or voting power.
- A passing model cannot close R6 section 17, cannot replace independent
  implementations or external review, and must not be cited as implementation
  correctness or production-readiness proof.

See `TRACEABILITY.md` for the initial rule-to-model-to-code map. Gaps are
intentional and remain open safety-case items.

The latest checked hashes, state counts, counterexample depths, fingerprinting
limits, and temporary-file cleanup evidence are recorded in
`results/2026-09-03-tlc-1.7.4-r2.md` and
`results/2026-09-03-tlc-1.7.4-crash.md`, and
`results/2026-09-03-tlc-1.7.4-bft-view-change.md`.
