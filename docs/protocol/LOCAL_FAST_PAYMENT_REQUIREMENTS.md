# Local fast payment, daily capacity and miner-fee requirements

## Authority and scope

The owner requires ordinary-user permissionless mining, causal interstellar
payment, local seconds-scale usable receipt, at least 100,000,000 payments per
24 hours, and a miner-directed protocol fee on every payment. This contract adds
F01-F06, F-T01-F-T08 and mandatory paper gates G9-G11. It composes with G1-G8,
T01-T22 and [D01-D06 / D-T01-D-T08](INTERSTELLAR_OPEN_PAYMENT_REQUIREMENTS.md);
none of those obligations is discharged by adding a performance target.

The architecture separates an open proof-of-work base, a noncustodial fast
payment layer and asynchronous authenticated interstellar carriage. The base
remains [RLD-SURVIVOR-1](survivor-v1/README.md) until an explicitly versioned
extension is specified, reviewed, implemented, qualified and adopted. Its single
owner C04 transfer cannot implement channels, escrow or scripted dispute rights.
This document does not add an accepted opcode, transaction, state proof or wire
codec, change mining/issuance or activate an extension on an existing network.

Exact algorithms, canonical bytes, limits, fee allocation, data availability,
dispute rules, monitoring assumptions and public interoperability vectors MUST
precede adoption. A channel, batch or proof is a candidate method, not a completed
construction. A server balance, committee acknowledgment or hash is not money.

## F01. Preserve open mining, one supply and survivor operation

The base MUST preserve ordinary ARM64/x86-64 CPU solo mining with self-built
templates, no account, prior balance, stake, roster, mandatory pool, hosted API
or founder permission. Fast-layer liquidity prerequisites MUST NOT become mining
prerequisites. No fast operator, prover or route may become a mandatory base-chain
signer. Ordinary miners MUST independently verify every adopted settlement rule
within a declared ordinary-hardware resource envelope; an opaque operator result
cannot authorize their templates or validation.

Supply remains 100,000,000,000 RLD, zero genesis allocation and the exact C08
reserve-era schedule. Locked backing is existing selected-chain value, not a
second allocation. Conservation MUST account mutually exclusively for free
funds, locked backing, fast claims and fee obligations without double-counting
claims against backing as additional supply. Reorganizations MUST remove invalid
backing and all unsupported descendants/fee rights; no receipt recreates money.

A lone capable node MUST retain ordinary validation and probabilistic mining.
Loss of a fast counterparty, liquidity or network can suspend fast service; it
cannot silently suspend base operation or promise a seconds-scale fallback.

## F02. Local seconds-scale receipt means usable, durable owner authority

For each predeclared normal local communication/load cohort the target is
**p95 <= 3 seconds and p99 <= 5 seconds** from the payer's original native
authorization/submission to the recipient's independent verification and durable
retention of an enforceable, funded fast-layer state that permits onward payment.
The recipient MUST actually authorize and complete onward payments in each
predeclared composition cohort. A sender acknowledgment, signature, animation,
relay receipt or operator credit alone MUST NOT stop this clock.

The metric is conditional fast-layer usability, not immediate base-chain inclusion,
withdrawal or irreversible global finality. Publish the exact state and backing,
selected-chain reference, unresolved risk, online/monitoring obligations and
dispute/exit rights. A noncustodial design MUST provide a specified unilateral
base-chain recovery path under explicit communication, work and inclusion
assumptions; counterparty cooperation cannot be its only exit.

Predeclare devices, geography, RTT, loss, uptime, payment sizes, routes, liquidity,
history, load, clock uncertainty and success/refusal policy. Include first use,
funding, depleted liquidity, disconnected recipients and forced exit as separately
named cohorts, never quietly discard them or apply the fast label to them. Every
valid submission within a declared normal cohort, including capacity refusal,
retry, failure and pending work, stays in its original denominator. Uncompleted
operations have infinite completion latency for percentiles, with counts, causes
and pending ages reported separately. Retries never reset the original clock.
Declared thresholds/cohorts MUST NOT change after outcomes are known.

## F03. At least one hundred million real payments in one day

The target is **at least 100,000,000 distinct, valid, completed user payments in
one continuous 86,400-second wall-clock interval**, equivalent to an average of
100,000,000 / 86,400, approximately 1,157.41 payments per second. Completion is
the recipient-authorized usable state in F02, not submission, a relay copy, a
batch root, a balance query or a duplicate retry. Count each logical payment once.
The same campaign MUST meet F02 in every predeclared normal cohort while carrying
real signatures, backing, durable state, resource accounting and F04 fee rights.

Predeclare peak rates/burst lengths, users, ownership/payment distributions,
amounts, route lengths, liquidity movement, devices, bandwidth, storage, CPU,
history and independent operators. Measure total offered/valid/completed/failed/
pending work, completion ratio, backlog and drain time. A short run extrapolated
to a day, unlimited-RAM counters, synthetic acknowledgments or an omitted fee/
settlement cost cannot establish G10. Independent reproduction remains required.

Measure base-chain funding, liquidity maintenance, cooperative settlement,
dispute and mass-exit demand separately. Survivor-1 permits only 128 transfers
per block and 262,144 bytes with nominal 600-second spacing: 18,432 transfers/day
at full count and nominal spacing, not a guaranteed service rate. This bound
neither meets F03 nor establishes enough exit capacity. Fix safe adoption limits,
exit windows and attack/inclusion assumptions before enabling a fast-layer scale;
if demand cannot safely fit, that scale fails. Do not merely shorten spacing or
raise bounds without work-security and ordinary-hardware qualification.

## F04. Every payment owes a funded, verifiable fee to miners

Every conforming base or fast payment MUST carry a positive protocol fee in
runlai explicitly bound by the owner's authorization to the currency, payment,
amount and applicable fee rules. All protocol payment fees belong to miners,
not the founder, treasury or a fast-layer operator. This is not an equal reward
to all nodes: adopted rules MUST identify the eligible selected-block miner(s).
Ordinary validation or relay alone grants no mining reward.

C04/C08 already transfer each base transaction's fee to its selected-block miner.
For fast payments, completion MUST create a verifiable miner-fee entitlement
backed by reserved existing value. Specify its canonical commitment, amount,
allocation, settlement trigger, deadline/exit path and claim rules. If batching
is used, native verification MUST establish every conforming payment's fee and
the exact aggregate without fee omission, double charging, duplicate claims or
withdrawal of reserved fees. A final balance, unsigned count or batch hash alone
cannot prove per-payment payment/fee completeness. Cooperating parties must not
be able to erase an already accrued miner entitlement during close or dispute.

The lifecycle MUST distinguish RESERVED/ACCRUED, INCLUDED and MATURED. Accrual
is not actual miner receipt; actual settlement and maturity are measured, including
delays and failures. Settled miner fees MUST retain the 100-block reward maturity
rule, with no supply increase, advance from the unissued reserve or administrative
compensation. Reorganization removes losing entitlements/payouts consistently.
Absence of future blocks is not a guarantee of actual payout by a fixed time.

No separate mandatory route/operator payment may be used to relabel or divert
the required miner fee. Disclose how routing, liquidity, proving and storage
costs are funded. Any optional separately owner-authorized service purchase is
distinct from the protocol payment fee and MUST be disclosed in the total cost.
Until the enforceable per-payment construction and its economics pass independent
review, G11 and the composed fast-payment claim remain open.

## F05. Preserve asynchronous interstellar payment and honest limits

D02-D06 remain mandatory for ordinary signed C04 intent and full native evidence:
sender-offline forward-only multi-hop carriage, recipient verification, actual
onward payment and original-signature reconsideration where inputs survive.
Fast-layer updates are new explicit owner authorizations under a separate version;
they MUST NOT rewrite an existing C04 intent, refund it from a timeout or spend
the same reserved backing through both modes.

Seconds-scale targets apply only inside the declared normal communication cohort.
Remote transfer still needs real physical contact and causal propagation. Each
stellar locality may offer fast service only under its declared backing, contact
and dispute assumptions, conditional on selected history. No regional mint,
permanent autonomous settlement or universal Earth service is implied. Recipient
arrival, source acknowledgment and base settlement remain distinct clocks.

A dispute protocol requiring return traffic or a bounded observation window MUST
NOT be assumed safe on a one-way or indefinitely disconnected interstellar leg.
Publish separate route/time/retention bounds; unsupported fast paths refuse while
the ordinary asynchronous transport requirement remains. No partition may obtain
both unconditional seconds-scale finality and conflicting conserved spends.

## F06. Versioned safety and composition precede release claims

Specify exact locked-fund authority, state sequencing, signatures, replay domains,
fee evidence, cooperative and unilateral exits, old-state attacks, censorship,
data loss, unavailable operators, capacity exhaustion, deep reorg, cross-mode
reservations, backups and crash recovery. Data availability and monitoring
assumptions MUST be explicit. Cryptographic proofs, if chosen, need exact suites,
soundness assumptions, public vectors, prover/verifier costs and upgrade rules;
they cannot be assumed to replace native verification by name.

G9 local seconds-scale usability, G10 daily volume and G11 per-payment miner fees
are mandatory design/release gates, alongside G1-G8. A fast release claim needs
their composition, not three unrelated demonstrations. Baseline conformance
remains exact; no old pass, document edit, local simulation or same-author review
qualifies the new extension. Use fresh no-value fixtures for changed consensus,
preserve old failures and obtain separate monetary adoption authorization.

## Conformance and acceptance mapping

| Check | Required discriminating observation and counterexample | Gates |
|---|---|---|
| F-T01 Local usable receipt | Original payer clock through independent durable recipient verification, p95 <=3s/p99 <=5s in each normal cohort, actual onward payment; acknowledgments and unchecked balances never complete; retain refusals/pending as specified in F02 | G9, G3, G5 |
| F-T02 One-day composed capacity | Complete at least 100,000,000 unique valid payments in one continuous wall-clock day with F02 latency, actual signatures, durable funded states and fees; predeclared peaks, distributions, liquidity and resource budgets; independent reproduction and complete denominator | G10, G9, G11, G5 |
| F-T03 Per-payment miner fees | Verify exact owner-approved positive fee and reserved backing for each completed payment; test omitted/changed fees, erased accrual, duplicate claims, unauthorized close and reorg; actual native payout to specified selected miners and h+100 maturity | G11, G3 |
| F-T04 Unilateral exit and congestion | Counterparty/prover/route unavailable, stale-state fraud, unavailable data and simultaneously forced exits at declared scale; enforce exact ownership/fees without cooperation within fixed dispute/inclusion assumptions; capacity overflow or unsafe loss fails the advertised scale | G9-G11, G2, G5 |
| F-T05 Open ordinary mining under composed load | Independently build templates and CPU solo mine on declared ARM64/x86-64 without account/stake/pool/operator; verify new settlement rules under fast-layer load; remove all fast services and retain ordinary survivor operation and its actual uncertainty | G7, G1, G9-G11 |
| F-T06 Stellar mode and causal boundary | Sender-offline one-way D-T02-D-T08 payment and actual onward execution; separately demonstrate local fast service where supported; impossible deadlines/return paths refuse without losing ordinary carriage, rewriting intent or allocating new supply | G8, G4, G9 |
| F-T07 Custody, rollback and cross-mode safety | Process/power-loss and independent cross-device restore, prior-state attack, changed backing, deep reorg, pending fees and simultaneous ordinary/fast spends; retain exact authorization/reservation, refuse duplication, fully replay/reconcile under adopted rules | G2, G3, G5, G9-G11 |
| F-T08 Independent release and economics | Independent validator/operator reproduction, fee/conservation argument, routing/liquidity/storage funding, resource/exit envelopes, canonical positive/negative vectors and authenticated adoption; absent construction or evidence keeps composed qualification open | G5-G11 |

Each campaign MUST predeclare its falsifiable hypothesis, smallest discriminating
observation, finite budget, outcome-dependent decision and exit criterion. Preserve
all attempts and original clocks. Unmeasured or impossible envelopes remain
unsupported; thresholds, maturity, fees and custody bounds cannot be relaxed to
obtain a pass. A physical route and long-horizon qualification remain separate.
