# Permissionless mining and causal interstellar payment requirements

Status: **normative product and qualification requirements; implementation and
route qualification remain open**. This overlay expresses the whitepaper target
of permissionless mining and causal interstellar payments. It does not change the
bytes, validity rules or branch selection of
[RLD-SURVIVOR-1](survivor-v1/README.md), whose exact consensus contract remains bound
by [SPECIFICATION.json](survivor-v1/SPECIFICATION.json). Cxx and Oxx below refer to
that contract's [consensus](survivor-v1/CONSENSUS.md) and
[operations](survivor-v1/OPERATIONS.md) clauses. Dxx requirements add conditions on
the ordinary product and the evidence needed to claim useful operation.

These requirements create no monetary network, allocation, migration entitlement,
new consensus format or claim that physical interstellar routes exist. A passing
design review is distinct from an implemented flow, an independent review and an
operationally qualified service. Existing failed evidence retains its meaning.

## D01. Ordinary users can validate and mine without permission

The ordinary installation MUST support full validation, local template construction
and CPU solo mining with an owner-selected valid reward key. It MUST NOT require
an account, KYC, invitation, prior balance, stake, validator roster, founder
approval, manufacturer attestation, API subscription, pool membership or another
online participant. An independently authenticated genesis,
authentic required history, usable clock, computation and sufficient resources
remain prerequisites under C03/C06/O01. Pinning a willing neighbor's public contact
key and literal endpoint is transport configuration, never mining admission.

Claims of ordinary-machine participation MUST declare a finite supported hardware,
software, history, storage and power envelope including ordinary ARM64 and x86-64
computers without a specialized accelerator, and show the extracted public product
constructing its own templates and mining without neighbors or a pool. Permissionless
entry is not a promise of equal hash rate, profitable rewards, ASIC resistance,
constant energy cost or a finite time to win a block. Hard-target survivor recovery
and reward maturity MUST be shown separately from an easy fresh-genesis sample.

## D02. Signed payment intent travels independently of changing evidence

The portable payment intent is the exact complete C04 transaction
`X = U || signature`. Its owner, inputs, ordered outputs, fee, chain and height
expiry MUST remain unchanged in transit and during retries. No relay, wallet,
receipt or evidence refresh may re-sign, rebase or replace it. Receiving to its
output owner does not require an online recipient.

Validation material MAY be refreshed independently of X as more authentic history
becomes available. Any proposed payment capsule codec MUST specify its exact
version, canonical bytes, explicit count/byte limits and failure behavior before
implementation or interoperability is claimed. It MUST bind the pinned chain,
exact X bytes and the branch/checkpoint material actually carried. An X identifier
alone cannot replace byte binding; a valid signature does not authenticate a
different evidence wrapper. No new capsule wire format is specified or claimed
implemented here. Existing v1 contact formats retain their exact rules and bounds.

Evidence refresh may change an observation of inclusion or usability; it cannot
change the authorization, claim independent freshness or turn an orphaned input
into selected-chain money. A root, header, receipt or asserted work total cannot
replace the complete native validation required by C05/C09/C10.

## D03. Payments and dependencies can cross one-way delayed contacts

Ordinary forwarding MUST retain exact authenticated payment and history material
durably, offer missing dependencies before dependents in bounded batches, and
support multiple willing relays and directed contacts. Full required ancestry MUST
eventually be obtainable and validated; a bounded offer batch is not a license to
omit the older prefix. Partial arrival reports waiting, never partial money.

A forward-only route MUST work without a reverse request, receipt or advertisement.
The sender may leave after releasing the durably retained material to a willing
carrier; continued progress cannot require the sender to return online. This is
conditional on actual later contacts, retained evidence, willing custody and
sufficient finite capacity. Unacknowledged delivery remains unknown at the sender.
No missing receipt authorizes deletion of an unresolved custody obligation, a
refund or a fabricated delivery claim. Admission may refuse before undertaking a
new obligation when capacity is exhausted; existing acknowledged bytes remain.

Progressive discovery assumes the node has already authenticated its genesis and
that a real contact is possible. Advertised identity, candidate route, observed
contact, hop custody, destination custody, ledger inclusion and spendability MUST
remain separate. Relays choose whether to accept custody. Discovery cannot force
service, create a route or safely authorize an advertised endpoint. Contact keys,
literal endpoints and adapter access require independent local admission under
O07; advertisements alone MUST NOT trigger arbitrary network or file access.

## D04. Reorganization preserves intent, not losing-branch value

After C10 replaces the selected history, the product MUST remove every losing
reward, payment, fee, maturity effect and dependent credit atomically under O04.
It MUST reconsider exact detached signed transfers under O05's dependency order,
and reoffer one only if its exact inputs exist, belong to its signer and meet
maturity, expiry and conservation checks on the new selected parent state. A
descendant waits until its exact parent output exists on that state. Original
signatures cannot spend an orphaned mining reward on a different history.

Wallet observations MUST distinguish orphaned reward/input, expired at the current
selected height, conflicted, waiting for history/input, and currently eligible
unincluded intent. Reconsideration is not an inclusion guarantee. A height rollback
can change expiry eligibility; expiry is not global revocation.

The original durable intent and local reservation MUST survive connection loss,
receipt arrival, pool eviction and reorganization. If a reorg restores an input,
restore its unresolved reservation unless O06's explicit recorded user waiver
exists. This overlay grants no automatic waiver, re-signing, rebasing, cancellation,
refund or compensation. An owner's separately reviewed conflicting transfer remains
a new explicit action and has no guaranteed winning outcome. Relays never acquire
that authority.

## D05. Recipients independently observe conditional money and known risk

A recipient MUST authenticate the pinned chain and fully validate the carried
history, exact transfer and its dependencies before reporting selected-chain
inclusion or a usable output. Actual onward payment requires its owner's separate
authorization and later native execution. Receipt of a signature or custody receipt
alone is not money; missing acknowledgment is unknown delivery, not failure proof.

Every balance/payment observation MUST identify the local selected tip, revision,
validated cumulative work and observation time/age. The product MUST expose its
known authenticated contact observations and any declared synchronization, clock,
history or resource uncertainty without implying those contacts are the universe.
It MUST state that unseen stronger work may exist and that no observation of
unseen work is available. Known work, age and confirmation depth are observations,
not an invented numerical probability of safety. Contact count is not hash power.

Acceptance policy MAY express a recipient's informed local preference, but MUST NOT
veto valid reorganization, claim permanent disconnected finality or silently assign
a confidence percentage. Delayed information can improve a later observation only
after real causal delivery and native validation. The display MUST retain the
possibility that both an accepted payment and a subsequent onward payment disappear.

## D06. Usefulness requires bounded resource and partition evidence

The product MUST demonstrate finite bandwidth, storage, memory, replay CPU, durable
queue and reorganization viability for each claimed operating envelope. A claim
MUST declare the hardware/history size, contact directions/delays/capacities,
partition length, competing work and custody budgets before measurement. It MUST
retain the original submission clocks, every admitted valid payment, pending age,
backpressure, refusal, failure and resource exhaustion; reporting successful
payments alone cannot establish usefulness. No universal latency is inferred from
a finite cohort. No threshold, deadline, maturity or bound may be relaxed to pass.

During a long partition, each capable branch may mine and make locally conditional
payments. After asymmetric work reconnects, the smaller-work branch's rewards and
dependent payments may all disappear. Branch balances and issuance MUST NOT be
added together. The service MUST disclose that local conditional authority can
remain useful to consenting parties while offering no guaranteed retained value
after convergence. Tests MUST include this loss, not only compatible histories.

The full-history cost and potentially deep reorganization cost remain real. A
finite implementation that cannot complete a declared workload reports the exact
limit and waiting/refusal behavior; it cannot adopt an unchecked snapshot, prune
unresolved custody, manufacture finality or change the mining algorithm to hide
the limit. Ordinary-node history, economic security, independent operations,
cryptographic horizons and physical routes remain separate qualification gates.

## Conformance and release evidence

G1–G6 retain their existing meanings in the
[acceptance mapping](../WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md): open survivor
operation; partition/convergence; money/wallets; delayed transport; independent
security/durability; authenticated release. This overlay additionally defines
**G7, ordinary-hardware participation**, and **G8, causal payment usefulness**.
These are obligations, not completed gates. D-T checks supplement, never replace,
the baseline T01–T22 or independent release obligations.

Every campaign MUST declare one falsifiable hypothesis, its discriminating
observation, a bounded time/attempt budget, outcome decisions and an exit criterion.
Use fresh no-value fixtures and source/binary/controller-bound evidence. Retain
failed attempts and the entire eligible cohort. Independent reproduction MUST use
the published product and exact declared envelope; author-run checks alone do not
satisfy independence. No private keys, node stores or generated private artifacts
belong in public evidence.

| Check | Required discriminating observation and counterexample | Gates |
|---|---|---|
| D-T01 Open ordinary entry | Independently install the public product on declared ordinary ARM64 and x86-64 CPU hardware; pin genesis, build local templates and mine with no account, roster, API, pool or neighbors. Exercise reward maturity and an owner-authorized payment, local stop/resume and early selected reward concentration. Any hidden remote dependency or privileged mining path fails. Report probabilistic trial/clock bounds; separately retain a hard history/target while removing 99% and 99.99% of work and measure recovery through actual onward payment. Easy genesis cannot replace these cases. | G1, G3, G6, G7 |
| D-T02 Exact intent and evidence refresh | Retain one exact signed X while refreshing complete authentic branch evidence. Refuse another chain, changed X bytes, mismatched carried branch and unsupported/overbound wrapper versions; missing dependencies remain WAITING_FOR_HISTORY or WAITING_FOR_INPUT. Neither refusal nor waiting changes intent or monetary state. An implementable codec and executable negatives are required before a capsule implementation claim. | G2, G3, G4, G6, G8 |
| D-T03 Sender-offline forward route | Use at least two relay hops and a forward-only offline leg with no reverse traffic. Stop the sender after actual willing durable custody. Carry a prefix longer than one offer batch, independently include the payment and perform recipient-authorized onward payment. A missing prefix must wait; source reactivation, hidden reverse requests or credit from a receipt fails. | G1, G3, G4, G8 |
| D-T04 Custody, discovery and capacity | Interrupt and restart a willing carrier with exact unacknowledged data; exhaust its declared queue and test duplicate/corrupt input. Preserve prior custody and refuse new excess work. Advertise an unadmitted endpoint and require no access; unknown route/destination receipt remains unknown. Deletion, endpoint following or inferred acknowledgment fails. | G4, G5, G6, G8 |
| D-T05 Original-signature reconsideration | Reorg a payment and its descendants onto a fully validated competing history. Where identical inputs survive, reconsider in dependency order with identical X; separately test missing parent, orphan reward, insufficient maturity, expiry and conflict. Preserve original reservation across restart. Automatic replacement, refund or use of losing value fails. | G2, G3, G5, G8 |
| D-T06 Independent recipient and honest observations | A recipient independently cold-replays delivered evidence and binds payment/balance/status to one tip/revision/work/time. Withhold a stronger branch and return no acknowledgment; require explicit unseen-work/delivery uncertainty and no numerical confidence invention. Later deliver the branch and observe complete rollback, including onward effects. Header/root/receipt-only credit or a finality claim fails. | G2, G3, G4, G5, G8 |
| D-T07 Finite history/contact viability | Under predeclared ordinary hardware and increasing history, run bounded bandwidth, queue pressure, replay and deep-reorg cohorts. Record every original submission, pending age, resource use and refusal through cold restart. Crossing an advertised limit, omitting failures or skipping validation fails that claim; an honest refusal narrows the supported envelope rather than passing the larger one. | G4, G5, G6, G7, G8 |
| D-T08 Asymmetric long partition | Run disconnected branches with explicitly unequal actual work and local owner payments, including spending matured local rewards. Deliver complete histories after the declared partition and require work/tie selection, complete smaller-branch removal and preserved conditional/loss observations. Adding branch issuance, protecting local payments with a checkpoint or reporting only surviving payments fails. | G1, G2, G3, G5, G8 |

## Research frontier

This target selects open PoW participation, causal evidence carriage and explicit
reversibility. It does not solve permanent finality during indefinite disconnection,
merge conflicting DAG balances, allocate disjoint regional issuance rights or
eliminate attacks involving withheld work, recovery timestamps or mining
concentration. Novel alternatives need separately specified safety, accounting,
security and adoption arguments. They cannot silently replace RLD-SURVIVOR-1 or
convert these design requirements into qualified operation.
