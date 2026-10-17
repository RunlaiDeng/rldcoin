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
| Durable selection, rollback and restart | `store.rs`, `observations.rs` | `storage.rs`, `observations.rs`, `crash.rs`, `history.rs` |
| Wallet, pool and encrypted recovery | `wallet.rs`, `pool.rs`, `keyfile.rs`, `backup.rs` | `wallet.rs`, `pool.rs`, `backup.rs` |
| Authenticated delayed custody and ordinary synchronization | `contact.rs`, `carriage.rs`, `offline.rs`, `tls.rs`, `network.rs` | `contact.rs`, `carriage.rs`, `offline.rs`, `tls.rs`, `network.rs` |
| Ordinary survivor payment and distribution | `main.rs`, `bin/rld-survivor-package.rs` | `process.rs`, `payment_process.rs`, `distribution.rs` |

Source paths are relative to `tools/survivor-node/src`; checks are relative to
`tools/survivor-node/tests`. The payment process check uses ordinary mining, wallet
review/signing, authenticated synchronization and recipient-authorized onward
payment after the source process exits. The crash check interrupts real processes
at ledger persistence boundaries; it does not simulate a storage controller losing
power. The archive check extracts the allowlisted distribution with the host tar
reader and starts its native executable. Local or CI execution of these checks
cannot satisfy the independent-validator, consumer, physical-route or sustained
history obligations by itself.

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
