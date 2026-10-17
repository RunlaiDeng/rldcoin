# Survivor-first whitepaper implementation acceptance

This is the current acceptance contract for [RLD-SURVIVOR-1](protocol/survivor-v1/README.md).
The [specification manifest](protocol/survivor-v1/SPECIFICATION.json) binds exact rules
and vectors. The [historical mapping](https://github.com/RunlaiDeng/rldcoin/blob/cf37a9e576f2f6ca581bff0201ce21c9c06cc3ab/docs/WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)
and prior publication receipts retain their original failed/unresolved scopes.
Their BFT results do not qualify this incompatible PoW profile.

## Whitepaper-to-implementation matrix

| Paper gate | Exact contract | Required completion evidence |
|---|---|---|
| G1 Open participation and survivor operation | C03/C06-C08, O01/O06; T06-T07 | Independent ordinary installation; remove founder and all others; preserve history/target; mine, mature, pay and perform actual onward payment; repeat survivors and hard-target collapse |
| G2 Partition and convergence | C05-C10, O02-O05; T05/T08-T10 | Conflicting spends/rewards, actual-work selection and deterministic ties; deep reorg removes losing effects; missing history waits; claimed work cannot halt capable local mining |
| G3 Money and wallets | C01-C05/C08-C09, O03-O06/O11/O13; T01-T04/T11-T13/T17/T22 | Cap, zero allocation, issuance boundaries, strict signatures, parent-only inputs, reward h+100, intent-before-release, exact retry, encrypted keys and atomic conditional balances |
| G4 Delayed transport | O07-O10; T14-T16/T21 | Ordinary authenticated multi-hop/offline carriage, complete-history verification, receipt return, durable queues, restart/fault/capacity behavior, no credit or refund from receipts |
| G5 Independent security and durability | C06, O02-O03/O12; T18-T20 | Independent review and validators, sustained history beyond an issuance era, replay/resources, cross-device/power-loss custody and finite crypto/archive horizons |
| G6 Authenticated release | C03/O12 and conformance release gates | Reproducible artifacts, operating limits, explicit adoption and fresh signed zero-allocation genesis; independently supported route/consumer claims |

## Mandatory distinctions

The isolated [native candidate](../tools/survivor-node/README.md) supplies the
implementation entry points below. These are auditable source locations and
required checks, not completion certificates for the campaigns above.

| Scope | Native source | Discriminating executable checks |
|---|---|---|
| Consensus and work | `kernel.rs` | `consensus.rs`, `recovery_target.rs` |
| Durable selection, rollback and restart | `store.rs`, `store/replay_witness.rs`, `observations.rs`, `observation_cache.rs` | `storage.rs`, `observations.rs`, `crash.rs`, `history.rs`, `history_backup.rs`, `cold_groups.rs`, `deep_reorg.rs`; native observation-cache unit cases |
| Wallet, pool and encrypted recovery | `wallet.rs`, `pool.rs`, `keyfile.rs`, `backup.rs` | `wallet.rs`, `wallet_binding.rs`, `wallet_history.rs`, `consumer_status.rs`, `pool.rs`, `pool_policy.rs`, `backup.rs` |
| Authenticated delayed custody and ordinary synchronization | `contact.rs`, `carriage.rs`, `offline.rs`, `tls.rs`, `network.rs` | `contact.rs`, `carriage.rs`, `carriage_sequence.rs`, `offline.rs`, `tls.rs`, `network.rs` |
| Ordinary survivor payment and distribution | `main.rs`, `bin/rld-survivor-package.rs` | `process.rs`, `payment_process.rs`, `contact_pressure.rs`, `listener_recovery.rs`, `distribution.rs` |

Source paths are relative to `tools/survivor-node/src`; checks are relative to
`tools/survivor-node/tests`. The payment process check uses ordinary mining, wallet
review/signing, authenticated synchronization and recipient-authorized onward
payment after the source process exits. The crash check interrupts real processes
at ledger persistence boundaries; it does not simulate a storage controller losing
power. The archive check extracts the allowlisted distribution with the host tar
reader and starts its native executable. Local or CI execution of these checks
cannot satisfy the independent-validator, consumer, physical-route or sustained
history obligations by itself.
The separate connection-pressure fixture starts two fresh stores from the same
fully native-executed common prefix. It retains the original fresh-install/mining
check as a distinct obligation. After the source exits, the sole recipient signs
and includes an onward payment, mines 101 additional blocks and retains ready
storage under at least 120 seconds of bounded unauthenticated stalled/malformed
loopback connections. Complete cold head, signature and conservation checks remain
required. This isolates transport workers from local survivor work; it does not
qualify arbitrary overload, expensive authenticated traffic or a physical route.
Listener recovery must retain authenticated adapter state while its configured
socket is unavailable. Unknown actual listen addresses remain null. Socket-only
retry cannot replace pins/material, reload configuration or discard custody;
outgoing/offline work and local mining remain independent. The ordinary-process
check mines while the port is still occupied, releases it and observes real timer
recovery plus an actual connection at the same endpoint with unchanged credentials.
Native unit cases separately check retained offline bytes, invalid-pin refusal and
the shared two-worker allowance across controlled acceptor restarts. They do not
establish arbitrary operating-system failure or physical-route qualification.
The native deep-reorganization fixture crosses the 144-observation timing window
and 64-block optional status-delta bound. A missing parent must leave the selected
tip, revision, coins and storage readiness unchanged; exact retry follows actual
parent arrival. A losing reward payment and its onward descendant become detached
and unspendable while their exact signatures remain retained. Newly available
winning funds cannot rebase those old intents. Explicit new owner reviews then
authorize a winning-chain payment and onward payment; complete cold replay must
preserve all four signatures, selected state and conservation. This ledger-only
finite fixture does not qualify arbitrary fork/history resources or transport
custody during reorganization.
The distribution size guard still refuses a 64-MiB-plus-one-byte input before
creating any archive or checksum. Limited test debug information cannot remove
runtime assertions/overflow checks, alter that guard or substitute a fake executable
for the extracted ordinary-node check.

Return-receipt wrappers retain normal complete packet authentication and the
retained origin/sequence conflict guard before any receipt state update. The
native counterexample requires recorded/refused equivocation, unchanged existing
custody and original bytes, then acceptance of the authentic receipt under a valid
new wrapper, including out-of-order delivery, exact retry and cold restart. A
kind-9 control copy grants no new custody promise, signing or ledger rights.

Cold wallet verification must bind every original review to the exact native
selected head and revision, and every retained signature to an actual selected
head no earlier than its review. Context indexes and completeness counts provide
no ledger authority. Complete genesis-rooted execution and original outcome/change
checks must precede each context validation. Unknown heads, intermediate batch
members, mismatched revisions and partial signatures refuse; owner, value,
maturity, expiry and strict signature checks remain mandatory. Historical intents
must remain recoverable after inclusion or branch replacement. Growing wallet
journals and independent rollback/custody qualification remain separate obligations.

Bounded history group installation retains complete native execution and atomic
prior/successor recovery. The separate `bin/rld-survivor-history.rs` measurement
entry records actual storage, hashing and cold replay with an explicitly logical
chain clock. A finite growing-reward sample is only one T18 workload; sustained
history beyond an issuance era, spent-state growth, owner activity, malformed
traffic, backups and declared CPU/RAM/disk horizons remain required.
The separate consolidating-payment workload rotates 256 public fixture owners
through mature reward spends and actual next-block onward authorization. It keeps
101 UTXOs while signed/spent history grows, so its result cannot replace the
growing-UTXO campaign. Fixture-direct signatures do not establish wallet custody;
full cold replay and recount of retained transfers remain required for that scope.
The optional history `with-backup` scope adds native pending review/signature,
reservation, explicitly encrypted fixture key and complete ledger/contact snapshot.
Its original total budget includes creation, fresh native restore and ordinary
cold reopening. Complete state, pool, pending-signature, balance and head equality
are required; same-host provided heads cannot establish independent custody or
power-loss durability. Small composition checks do not close the large-history gate.
Native backup record unit cases also require copying/detached-method
interoperability and refusal of edited role/AAD/password/length/tag inputs before
plaintext release. The bounded public-payload resource probe isolates record
allocation; it cannot replace whole-node peak-memory, replay or custody checks.
In-place sealing must reserve the complete record before processing and zeroize
plaintext-bearing temporary output on any error. All original record/storage
limits and cryptographic parameters remain in force.
Cold group notification reconstruction must retain exact native predecessor/member
execution and complete original event comparison. Tests alter attached order,
detached entries, reward/output observations and non-tail block bodies; verified
group membership is never permission to initialize state from metadata or omit a
signature check.

Consumer projection and custody checks distinguish current reservation, known
spent-output maturity and external selected inclusion from local signature release.
Hot journal tests alter a reviewed recipient, substitute recovery bytes and prevent
the required signature-row update. No such case may release a changed/new X.
Detected retained-body corruption suspends mutation, while missing arbitrary peer
objects remain dependency waits. Unknown clock tests preserve read-only observation
and the ability to disable mining; they cannot enable mining or authorize spending.
These finite checks do not qualify all-state rollback, independent custody or
physical power-loss durability.

Local pool checks require one ready spender per input under exact fee/byte and ID
ordering. Status and templates use that same ready set, and expose local preference
separately from selected-history conflict. A valid block containing the lower local
preference must still execute normally. Retained pool identity corruption refuses
without changing the selected state; read-only status cannot reoffer or sign.

The bounded process-local observation witness must agree with complete-history
status after extension, branch replacement, stale anchors, eviction and cold
reconstruction. Failed groups cannot publish candidate observations. Queries must
refuse altered or missing known inclusion material even before the current tip.
Native execution and complete cold change verification precede every seeded or
updated witness; no serialized index initializes authority. The 256-witness/
8192-input-reference and 64-block/1-MiB delta limits discard optional observations,
never history, a valid deep reorg or signing checks. Current wallet/pool/output
projection stays live. Old uncached queries and whole-node replay costs remain
distinct resource obligations. A submission acknowledgment reports retention with
an unavailable ledger observation, not an invented UNSEEN state for an already
included transaction.

Alternate-prefix replay reuse is process-local and bound to one Store's immutable
genesis and resource limits. Full native execution must establish its prefix;
every retained prefix byte must agree again before reuse. Missing or altered
known material refuses and suspends mutation, an invalid suffix cannot seed a
witness, and branch misses/cold starts rebuild from genesis. Retention exceeding
4 MiB of block bytes or 4,096 current coins discards the optional witness, never
the valid history or a deep reorganization. Within unchanged revision/selection/
commit precedence, header-height ordering is a scheduling hint only: every row's
full native execution, parent, exact result, wallet context and revision checks
remain mandatory. Native replay-witness unit cases and `deep_reorg.rs` cover these
contracts; bounded reuse does not qualify arbitrary long-fork resources or T18/T19.

The kernel's bounded transient C09 frontier must agree byte-for-byte with the
retained recursive reference at binary boundaries and after ordered map edits.
It changes temporary allocation only: the selected state still requires complete
native execution and a complete current-map commitment, never a serialized
frontier or unverified state cache. This optimization does not close T18/T19.

- Specification/vector consistency is design evidence, not a complete runtime.
- Native execution, durable node behavior, wallet custody and contact delivery
  require separate checks and composition through ordinary product flows.
- Same-host processes are not independent operators, cross-device custody or physical
  links. Process interruption is not automatically power-loss testing.
- Selected history does not prove absence of stronger unseen work. Every payment is
  conditional; no fixed confirmation count or local maturity means global finality.
- Risk acknowledgment after uncertain restore is O03 policy, not independently
  proved freshness or exclusive custody.
- Unknown, failed, unsupported and unmeasured scopes remain visible. Preserve
  original clocks, submitted operations, pending ages and failure evidence.
  Performance cannot be calculated only from successful submissions.

## Historical obligation disposition

The normative [complete mapping](protocol/survivor-v1/CONFORMANCE.md#disposition-of-historical-obligations)
covers I1-I12, S1-S18, R1-R24, A-G, N1-N10 and P1-P8. It explicitly replaces
quorum finality, regional export/import, permanent conflict quarantine, path-history
claims and mandatory external-witness-dependent availability where incompatible
with the owner's accepted rollback direction. These are contract changes, not
passes under old rules.

Authorization, conservation, complete evidence, durable intent, bounded resources,
honest states, independent review and finite-horizon physical/cryptographic
qualification remain mandatory. Channels, guardians, regional issuers, PQ monetary
adoption and instant/final stellar settlement are not baseline capabilities.
Unsupported extensions refuse.

## Completion rule

All applicable T01-T22 obligations require scoped evidence before a complete-product
claim. Implemented functions alone do not satisfy independent or physical gates.
New money is prohibited until G6 is explicitly met; old test balances, abandoned
archives and fixture keys cannot supply that authority.
