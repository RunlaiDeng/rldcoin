# Rldcoin implementation plan

## Authority and outcome

The implementation target is [RLD-SURVIVOR-1](protocol/survivor-v1/README.md),
bound by its [specification manifest](protocol/survivor-v1/SPECIFICATION.json).
The [whitepaper research receipt](WHITEPAPER_RELEASE_2026-10-18_MECHANISM.json) binds the
reconciled Markdown/PDF to this exact specification and the additional
[interstellar open-payment requirements](protocol/INTERSTELLAR_OPEN_PAYMENT_REQUIREMENTS.md).
The latter add product and qualification requirements D01-D06 and D-T01-D-T08.
The [local fast-payment requirements](protocol/LOCAL_FAST_PAYMENT_REQUIREMENTS.md)
add F01-F06, F-T01-F-T08 and mandatory G9-G11: normal local usable receipt at
p95 <=3 seconds / p99 <=5 seconds, at least 100,000,000 completed payments in
one continuous 86,400-second day, and a positive funded protocol fee to miners
on every payment. These are required design/acceptance targets, not demonstrated
performance. Their composition preserves ordinary-user mining and causal stellar
carriage. The baseline consensus bytes, work and issuance are unchanged; the fast
layer requires separately versioned, independently reviewed rules and adoption.
The mechanism paper separates scientific exposition from implementation
acceptance. Its body explains rules, proposed accounting, assumptions and scaling
analysis; G1-G11, exact percentile thresholds and campaigns remain mandatory in
this plan and the acceptance contract. This is an editorial separation, not a
relaxation of any target or a completed fast-layer construction.
The [fast-payment receipt](WHITEPAPER_RELEASE_2026-10-18_FAST_PAYMENTS.json),
[interstellar-title receipt](WHITEPAPER_RELEASE_2026-10-18_INTERSTELLAR.json),
[16 October receipt](WHITEPAPER_RELEASE_2026-10-16.json) and
[earlier 18 October receipt](WHITEPAPER_RELEASE_2026-10-18.json) retain their exact
historical meanings. The owner selected the title **Rldcoin: Interstellar
Peer-to-Peer Payments**; open ordinary-user mining remains a core mechanism.
A research receipt is not a deployment receipt.
The owner selected reversible payment acceptance and continued operation by any
capable surviving full node. This replaces mandatory regional quorum finality,
irreversible regional export/import and the former seconds-scale final-spendability
target. G9 now requires local conditional fast usability, not that historical
irreversible finality or an interstellar communication deadline. No signed
historical network or old experiment is upgraded by this target.
The [historical plan](https://github.com/RunlaiDeng/rldcoin/blob/cf37a9e576f2f6ca581bff0201ce21c9c06cc3ab/docs/RLDCOIN_MASTER_PLAN.md)
and original release receipts retain their meaning.

The ordinary product must provide a validating node with optional mining, native
owner-controlled wallet, restart-safe storage and authenticated delayed relay.
Ordinary participation requires self-constructed templates and CPU solo mining on
declared ARM64 and x86-64 hardware, without accounts, stake, rosters, mandatory
pools, remote API credentials or founder service. Permissionless entry cannot be
advertised as equal reward, profitability or immunity to specialized hardware.
It operates without the founder or another online participant, provided it retains
authentic history, keys when spending, a working clock, computation and sufficient
storage. Remote receipt requires physical communication. Payments, rewards and
descendants can be removed by a valid winning history.

The isolated executable is [tools/survivor-node](../tools/survivor-node/README.md).
It intentionally accepts only no-value genesis manifests. Its native stdin API,
encrypted wallet/whole-node backup, pinned TLS and separately admitted offline
carriage form the candidate engineering surface. Distribution packages contain
only the executable, public contract, license and byte inventory. Monetary adoption
and consumer qualification require the separate gates below; a downloadable test
binary does not change them.

The interstellar product target separates an exact owner-signed intent, refreshed
complete verification evidence, durable custody and recipient-executed conditional
state. A logical payment capsule supplies no new accepted wire codec or balance
authority. Ordinary forwarding must support a sender-offline, forward-only path;
reorganization must reconsider the original signatures only where exact inputs,
maturity and expiry remain valid. Orphan rewards and their descendants cannot be
restored by a receipt or a preserved signature. G7 requires ordinary-hardware
participation; G8 requires payment usefulness under declared contact, history and
unequal-work partition envelopes. Neither gate is completed by this revision.

## Implementation boundaries

The fast-layer design is a separate necessary workstream, specified by F01-F06.
First resolve noncustodial locked backing, independently verifiable state and
per-payment miner-fee completeness, unilateral recovery and mass-exit capacity.
Survivor-1 C04 has no scripted/mixed-owner transfer: names such as channels or
batch proofs cannot supply missing execution rights. Fix exact extension versions,
bytes, bounds, data/monitoring assumptions and public vectors before coding or
adoption. Keep G9-G11 open until independently qualified in composition with G1-G8.
No fast service may become a prerequisite for ordinary CPU mining or one-way
stellar intent carriage. All unmeasured performance remains unsupported.

Use separate binaries and fresh no-value directories. No legacy BFT store, wallet,
genesis or test balance is converted. Unrelated source changes and running services
remain untouched. Reuse utilities only when exact semantics match this profile;
old passing tests do not qualify changed rules or new binaries.

| Component | Required implementation | Acceptance |
|---|---|---|
| Consensus kernel | C01-C11: strict bytes/crypto, genesis, transfers, issuance, recovery, work, roots, branch selection | T01-T05, T08-T10 |
| Durable node | O01-O04: ordinary lifecycle, pinned genesis, exclusive writer, atomic intent/commit/replay, deep reorganization and revisions | T06-T12, T18 |
| Local provisioning and recovery | O02-O03/O09: explicit local budgets, intact capacity recovery, bounded authenticated backup chunks and complete native/material verification on fresh-target restore | T11-T13, T18, T22 |
| Wallet | O05-O06/O11/O13: bounded pool, exact review in its original selected context, durable intent/reservation, recover-only retries, encrypted keys, conditional balances | T03-T04, T11-T13, T17, T22 |
| Contact protocol | O07-O09: canonical packets/frames, origin/link authentication, offline carriage, receipt return, quotas and fair retry | T14-T16 |
| Node integration | O01/O10: default neighbor synchronization and forwarding, independent recipient verification, actual onward payment | T06-T10, T14-T17, T22 |
| Maintenance/release | O12: unsupported behavior, authentic artifacts, finite horizons and independent qualification | T18-T21 and adoption gates |
| Open ordinary participation | D01: account-free CPU solo templates/mining, explicit supported hardware and hostile-load envelope | D-T01, D-T07; G7 |
| Causal payment composition | D02-D06: exact portable intent, complete dependencies, forward-only custody, original-signature reconsideration, honest risk and bounded route viability | D-T02-D-T08; G8 |
| Local fast usable receipt | F01-F02/F05-F06: funded enforceable durable recipient state, actual onward payment, unilateral recovery and explicit local communication assumptions | F-T01/F-T04-F-T08; G9 with G1-G8 |
| Daily payment scale | F03/F06: at least 100,000,000 unique completions per continuous day with G9 latency, real authorization/custody/fees, declared peaks/resources and safe mass exit | F-T02/F-T04-F-T08; G10 with G9/G11 |
| Per-payment miner fees | F04/F06: owner-authorized positive fee, reserved backing, exact completeness/allocation, native settlement, maturity and reorg without diversion or inflation | F-T03-F-T05/F-T07-F-T08; G11 with G3/G5 |

## Ordered behavior milestones

1. Synchronize whitepaper Markdown/PDF, public reader and acceptance plan with the
   exact candidate. Preserve historical published artifacts and receipts.
2. Implement the reusable native kernel against frozen public vectors. Exercise
   malformed bytes, arithmetic and unchanged-state refusal.
3. Implement durable standalone execution and wallet intent. Exercise actual reward
   maturity, payment/onward payment, crash recovery and conflicting histories.
4. Integrate exact contact formats and authenticated adapters into ordinary startup.
   Exercise independent stores, directed/offline multi-hop carriage, receipt return,
   restart and capacity refusal without granting money from receipts.
5. Package ordinary commands and consumer flows. Independently test full history,
   resource limits, custody and sustained use. Publish only scoped claims.
6. Qualify D01-D06 with the complete predeclared D-T01-D-T08 cohorts. Exercise
   ordinary CPU participation, retained hard-target collapse, sender-offline
   one-way onward payment, exact-signature reconsideration and smaller-branch
   losses. A passing baseline check can be reused only for its exact overlapping
   source and scope; it cannot stand in for unmeasured G7/G8 obligations.
7. Specify the fast-layer extension and prove its ownership, cross-mode backing
   conservation, fee completeness, unilateral exit and versioned adoption. Select
   a concrete construction only after a counterexample-driven safety review;
   operator credits, final balance hashes and unbacked accrued fees are insufficient.
8. Qualify F01-F06 with F-T01-F-T08: compose local p95 <=3s/p99 <=5s usability,
   one continuous day with at least 100,000,000 distinct real completions, actual
   miner-fee settlement and ordinary-hardware/stellar-mode preservation. Measure
   funding, hostile exit, liquidity, failed/pending operations and independent
   reproduction. No short extrapolation or three unrelated demonstrations closes
   G9-G11. Earlier base-runtime work does not by itself satisfy this new target.

Local resource provisioning is separate from consensus. Every startup selects
published defaults or an explicit chain-pinned local policy. Expansion must preserve
retained history, intents and custody obligations, while backup/restore admits total
images only under caller-provisioned limits. Bounded ciphertext processing cannot
replace full native replay, correct communication material or the declared freshness
policy. Default limits and every historical failed scope retain their exact meaning.

Contact verification may retain one completely checked intrinsic block body,
bounded by the unchanged 262,144-byte block limit. Only identical full bytes and
chain under the same executable's fixed validation domain can reuse that result.
All new packet/frame authentication and parent-dependent native execution remain
mandatory. This optional process-local witness supplies no ledger, work, custody
or freshness authority and does not qualify arbitrary authenticated overload.
Retained offline re-emission also reauthenticates the complete delivery and exact
packet bytes on each read. Valid signatures from another packet, link role or
session cannot authorize the selected outgoing row; malformed retained evidence
refuses without repair or an inferred custody receipt.
Receipt import authenticates that same retained delivery and exact packet before
recording either destination custody or a hop observation. A later role error
cannot leave an earlier acknowledgment committed.
Indexed packet reads also bind the complete signed packet to the requested ID and
retained origin, sequence and kind before bytes or duplicate acknowledgments leave
the store. A valid signature cannot authenticate a mismatched index entry.

A milestone completes only when its behavior and discriminating checks are
implemented. The vector oracle is not a node. A disk hash is not ledger validation.
Transport delivery is not inclusion. Software does not establish independent
security or a qualified physical interstellar route.
An offline contact cannot assume that requests or receipts can travel back. Its
ordinary scheduling must proactively retain and offer complete selected-history
dependencies to explicitly admitted offline peers, in bounded batches. Progress
cursors select carriage work only; they neither initialize a ledger nor prove a
recipient has received anything. Unacknowledged history remains a custody
obligation, including after restart or a selected-history change. A finite spool
may refuse further offers rather than discard an earlier obligation.
The distribution installation check must use the extracted executable itself to
create an encrypted wallet, mine with no configured neighbor and reopen the exact
result by native cold replay. Open admission does not promise mining profitability
or useful recovery speed after a hard-target collapse.

## Verification method

Use the [acceptance matrix](WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md) and complete
[T01-T22 campaign contract](protocol/survivor-v1/CONFORMANCE.md). Each engineering
experiment names a falsifiable hypothesis, the smallest distinguishing observation,
a finite budget and an outcome-dependent action. Preserve failures and original
timing/resource bounds locally. Reuse applicable bound evidence; rerun expensive
scopes only when a relevant change justifies it.

For the consensus milestone the hypothesis is that a fresh reusable validator can
replay every published branch to the exact roots/work and refuse altered evidence
without oracle-produced state. Exact vector agreement and negative state-atomicity
cases discriminate this claim. A mismatch stops storage integration until narrowed;
agreement permits durable integration, not an independent security claim.

## Publication and external gates

Use the ordinary stage workflow for reviewed code, interfaces and public no-value
vectors. Keep keys, wallet/node state, generated backups and internal run evidence
out of public commits. Document limitations rather than converting a revision into
completed acceptance.

Independent security review, a second independently written validator, cross-device
custody, long-history resources, cryptographic horizons, funded maintenance and
actual physical routes remain distinct requirements. Mainnet needs separate
monetary adoption and a fresh authenticated zero-allocation genesis. No test money
or fixture key migrates. Supply remains 100 billion RLD with zero initial allocation
and the exact C08 reserve-era schedule.
The complete-product target includes G1-G11, T01-T22, D-T01-D-T08 and F-T01-F-T08.
All local speed, daily scale and per-payment miner-fee claims need composed evidence.
No route may claim irreversible independent stellar settlement under global work selection.
