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
