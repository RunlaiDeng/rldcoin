# Rldcoin implementation plan

## Authority and outcome

The implementation target is [RLD-SURVIVOR-1](protocol/survivor-v1/README.md),
bound by its [specification manifest](protocol/survivor-v1/SPECIFICATION.json).
The [whitepaper research receipt](WHITEPAPER_RELEASE_2026-10-16.json) binds the
reconciled Markdown/PDF to this exact specification; it is not a deployment receipt.
The owner selected reversible payment acceptance and continued operation by any
capable surviving full node. This replaces mandatory regional quorum finality,
irreversible regional export/import and the former seconds-scale final-spendability
target. It does not alter signed historical networks or qualify old experiments.
The [historical plan](https://github.com/RunlaiDeng/rldcoin/blob/cf37a9e576f2f6ca581bff0201ce21c9c06cc3ab/docs/RLDCOIN_MASTER_PLAN.md)
and original release receipts retain their meaning.

The ordinary product must provide a validating node with optional mining, native
owner-controlled wallet, restart-safe storage and authenticated delayed relay.
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

## Implementation boundaries

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

Local resource provisioning is separate from consensus. Every startup selects
published defaults or an explicit chain-pinned local policy. Expansion must preserve
retained history, intents and custody obligations, while backup/restore admits total
images only under caller-provisioned limits. Bounded ciphertext processing cannot
replace full native replay, correct communication material or the declared freshness
policy. Default limits and every historical failed scope retain their exact meaning.

A milestone completes only when its behavior and discriminating checks are
implemented. The vector oracle is not a node. A disk hash is not ledger validation.
Transport delivery is not inclusion. Software does not establish independent
security or a qualified physical interstellar route.

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
