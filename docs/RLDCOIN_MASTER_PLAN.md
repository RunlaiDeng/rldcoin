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
state. The [streamed file capsule](protocol/PAYMENT_CAPSULE_V1.md) fixes one
application-layer codec for exact intent and complete native history, with public
byte vectors and local export/refresh/verification/import commands. It changes no
consensus transaction or contact registry and supplies no balance authority from a
digest. Initial full native replay precedes ordinary local acceptance; weaker
carried history cannot override stronger local work. Ordinary forwarding must
support a sender-offline, forward-only path;
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

The [prospective miner-fee claim component](protocol/FAST_MINER_FEE_CLAIMS_V1.md)
separates owner-signed fee ranges from principal-state sequence selection and
retains complete supporting certificates for monotone numerical fee floors.
It explicitly requires independent timely claim retention; withholding a highest
claim remains an indistinguishability problem. Its canonical context/certificate
bytes and public no-value vectors define a verification component only. It does
not authenticate funding, enforce principal exits, pay miners or qualify F04/G11.
The next native extension must compose those missing operations and their exact
custody/inclusion assumptions before any fast-service or capacity claim.
The [native no-value escrow candidate](protocol/NATIVE_FAST_ESCROW_V1.md) adds a
separate genesis/header domain and actual mature-input funding, independent
principal/fee challenges, fixed height/time windows and one-use miner/refund
settlement. Its replay-only command derives all value from genesis and complete
PoW blocks. It supplies no owner custody, retainer delegation/acknowledgment,
ordinary fast service or adoption; G9-G11 and mass-exit qualification remain open.
The [funded invoice/retention component](protocol/FAST_PAYMENT_RETENTION_V1.md)
binds complete old/new states, invoice, amount and exact positive payer fee to
both owners' state and invoice signatures. A native-origin miner delegation
authorizes a separate fee-retainer key; complete receipt preparation and exact
acknowledgment have distinct durable journal records and keyless recovery.
Native origin is obtained by full funding-prefix replay, not a context assertion.
The [owner authorization journal](protocol/FAST_OWNER_AUTHORIZATION_V1.md) adds
unsigned proposal construction, exact owner review, pre-key durable reservation,
own partial persistence, complete counterparty/retainer proof retention and keyless
recovery. Each owner has a separate private journal and external latest head;
timeouts never release a pending slot. Latest complete exit evidence remains
available during a subsequent pending invoice. Consumer approval/latest-head
custody, authenticated native updates, operational fee liquidity and continuous
independent monitoring remain required before fast completion; the native and
local caller components below compose these journals without waiving those gates.
The [native fast-node selector](protocol/FAST_NATIVE_NODE_V1.md) provides a
separate bounded exclusive-writer journal and local stdin executable. It retains
every accepted full branch, chooses greatest native work with the existing
smaller-ID tie rule, and cold-reconstructs selection through full genesis replay.
Explicit latest storage/selected heads precede admission, mining and current-state
borrows. A stronger branch removes old funding from owner/retainer pre-key checks;
exact keyless tail recovery preserves that knowledge across process restart.
The local node supplies actual bounded self-constructed CPU mining and funding
inspection, not a peer transport, live monitored payment/caller-head service,
independent freshness, mass-exit or composed daily qualification.
The [serialized payment session](protocol/FAST_PAYMENT_SESSION_V1.md) composes
that selector with per-owner authorization and delegated custody. Its key-free
caller journal persists exact requests before child work and verified head/review
effects before response. Cold opening authenticates all native/actor histories
and each caller-to-child transition; record hashes or status fields never create
money/signing authority. Explicit recovery can reproduce an existing partial,
ack or native selection, never first-sign or free a pending owner slot. The local
stdin interface builds unsigned proposals from retained native/owner state and
requires exact persisted review plus explicit approval before encrypted-key use.
This supplies a local caller/session component, not authenticated peer delivery,
consumer consent UI, continuous fee-solvent monitoring, independent latest-head
custody or G1-G11 composition. Its fixed32-MiB caller/actor and16-actor bounds
require separate archival/scaling/resource qualification before capacity claims.
The [direct payment peer adapter](protocol/FAST_PEER_NETWORK_V1.md) adds separately
pinned mutual TLS1.3 data carriage to session startup. It durably queues exact
native blocks, invoices, retained partials, full receipts and retainer proofs;
fresh connection challenges and complete envelope signatures precede duplicate
handling. Destination file/parent custody precedes its scoped data response, and
local response custody precedes retry suppression. Original queued times survive
restart. Local explicit native import and owner/retainer review remain mandatory;
network reception never supplies a ledger, approves a review or loads wallet keys.
Exact last-record recovery authenticates an existing data head without new signing
or truncation. The separate [trusted-file custody profile](protocol/FAST_PEER_HEAD_CONTROL_V1.md)
uses fresh version2 data storage and explicitly trusted local head input to retain
each exact pending record before append and each completed head before response.
It allows reconciliation of an interrupted prepared data transition after full
prefix/record authentication; old storage refuses without conversion. Its local
integrity/latest-state assumption supplies no independent freshness, caller
approval or native authority. Direct ground sockets and explicit local imports do not qualify
autonomous latest-head coordination, discovery/multi-hop, continuous funded claims,
independent operations/custody, long history, mass exit or composed G1-G11.
The separate [trusted caller-control profile](protocol/FAST_SESSION_HEAD_CONTROL_V1.md)
uses fresh version2 caller journals and exact pending requests before child work.
Its optional bounded block-only ingress uses full native prevalidation and normal
admission during local client inactivity. Exact controlled recovery never first-
executes, signs or rebases an approval; existing proofs remain available without
keys. Local trusted head integrity/latest-state is not independent protection.
Continuous solvent fee/challenge service and composed product gates remain required.
The [bounded fee-wallet policy](protocol/FAST_FEE_WALLET_POLICY_V1.md) supplies a
separate actual-input-owner signature for fixed channel/input lineage, fee budget,
count and expiry. Policy-specific current native preparations/signatures preserve
signature-time liabilities across losing branches, manual conflicts and restart.
No retainer receipt, hash or approval boolean replaces that owner certificate.
This authorization dependency does not itself select proofs, unlock a key,
maintain solvency, submit claims or qualify continuous monitored operation.
The [native action authorization](protocol/FAST_NATIVE_ACTION_AUTHORIZATION_V1.md)
adds explicit ordinary-input review/reservation and encrypted-key signing for
close, principal challenge, miner-fee claim and settlement. Preparation uses full
nonmutating native execution; exact approved signatures are retained in the
caller reply before release. Retained owner/retainer exit certificates remain
historical proof, never current backing. Bounded own-template CPU candidate
construction stays separate from actual native admission and peer carriage.
Fixed challenge windows, exact funding-miner allocation and h+100 maturity are
unchanged. Cold audit fully checks every authorization; process-local immutable
prefix reuse is never serialized or initialized from peer state. Independent
latest-head/key custody, continuous funded claim/challenge monitoring, timely
inclusion and composed resource/exit qualification remain required.

The [ordinary native transfer authorization](protocol/FAST_NATIVE_TRANSFER_AUTHORIZATION_V1.md)
adds explicit ordered-output review and encrypted-key signature custody for
existing kind0 transfers. It uses the actual fast native ledger and shared
execution, preserving C04 bytes and domain. Ordinary transfer and escrow input
reservations compose before key loading and across cold recovery. A retainer can
receive real ordinary funds and pay its own claim inputs under its own explicit
approval; receipt delegation is never spending authority. This supplies a funding
path, not continuous solvent monitoring, joint opening, independent custody or
composed performance/adoption qualification.
The [joint opening authorization](protocol/FAST_NATIVE_OPENING_AUTHORIZATION_V1.md)
adds native proposal construction, separate own-input review/reservation and
encrypted-key owner partials for the existing two-owner opening. Exact retained
caller closure combines both real signatures without new signing; its short
reply preserves existing bounds for64 total inputs. Versioned peer data carries
proposals/partials before explicit local review and normal native pool admission.
Neither a partial, caller hash nor transport receipt supplies backing. Ordinary
funding, real payment/onward authorization and native principal/fee challenges
remain distinct steps. Continuous monitoring, trusted latest-head coordination,
consumer operation, independent custody/resource qualification and G1-G11 remain
required.
The [signed native operation pool](protocol/FAST_NATIVE_OPERATION_POOL_V1.md)
retains already signed complete operations in the caller history, carries them
as versioned peer data and builds bounded ordinary-node templates through normal
native execution. Missing dependencies/conflicts remain retained with their first
local queue time. Candidate discovery, explicit native admission and conditional
selected-history inclusion are separate. Cold replay, exact keyless request
recovery and reorganization preserve those distinctions. This supplies no
continuous solvent monitor, automatic trusted caller-head coordination,
independent operation/custody, scalable archival/mass exit or composed G1-G11.

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
| Streamed exact-intent file codec | PAYMENT_CAPSULE_V1: canonical versioned X/history binding, one-record streaming, full genesis replay, unchanged-X refresh and ordinary native import | `capsule.rs`, public capsule byte vectors and `capsule_process.rs`; D-T02/D-T06 plus independent/capacity qualification |
| Local fast usable receipt | F01-F02/F05-F06: funded enforceable durable recipient state, actual onward payment, unilateral recovery and explicit local communication assumptions | F-T01/F-T04-F-T08; G9 with G1-G8 |
| Daily payment scale | F03/F06: at least 100,000,000 unique completions per continuous day with G9 latency, real authorization/custody/fees, declared peaks/resources and safe mass exit | F-T02/F-T04-F-T08; G10 with G9/G11 |
| Per-payment miner fees | F04/F06: owner-authorized positive fee, reserved backing, exact completeness/allocation, native settlement, maturity and reorg without diversion or inflation | F-T03-F-T05/F-T07-F-T08; G11 with G3/G5 |
| Prospective fee-range verifier | FAST_MINER_FEE_CLAIMS_V1: context-bound ordered owner signatures, independent maximal fee ranges and exact bounded numerical accounting; no funded-ledger authority | `fast_fee_claims.rs` and public component vectors; native funding/exit/retainer/settlement and independent F04 qualification remain required |
| Native no-value escrow executor | NATIVE_FAST_ESCROW_V1: independent pinned genesis/PoW, ordinary transfers and actual funding locks, one-use close/challenge/settlement and h+100 miner payout | `kernel/fast.rs`, `kernel/fast/codec.rs`, replay-only CLI and `native_fast_escrow.rs`; complete custody/retainer/fast-service, mass-exit and independent qualification remain required |
| Funded invoice and delegated retention | FAST_PAYMENT_RETENTION_V1: native-origin full payment transition, ordered state/invoice signatures, miner-delegated bounded durable prepare/ack and keyless recovery | `fast_payment.rs`, `fast_retainer.rs`, public codec vectors and native invoice-to-settlement checks; owner custody, continuous monitoring, operational liquidity and composed G9-G11 remain required |
| Fast owner authorization | FAST_OWNER_AUTHORIZATION_V1: unsigned proposal, separate owner review/reservation/signature, full receipt/ack retention and keyless recovery | `fast_owner.rs`, `bin/rld-fast-owner-recover.rs` and `tests/fast_owner.rs`; no frontend approval/caller-head service, independent custody, live native selection/monitoring or composed G9-G11 qualification |
| Native fast-node selection | FAST_NATIVE_NODE_V1: durable full known-branch custody, greatest native work, exact current-state lease, bounded local control/mining and keyless tail recovery | `fast_store.rs`, `bin/rld-fast-node.rs`, `tests/fast_store.rs`; peer synchronization, owner/caller sessions, fee-solvent monitoring, independent custody and composed G9-G11 remain required |
| Serialized native payment session | FAST_PAYMENT_SESSION_V1: exact key-free caller intent, audited native/actor effects, persisted review/approval and keyless cross-journal recovery | `fast_session.rs`, `fast_session/journal.rs`, `bin/rld-fast-payment-session.rs`, `tests/fast_session.rs`; authenticated peers, actual consumer approval/latest-head custody, fee monitoring/claim solvency, scalable archival and composed independent gates remain required |
| Direct session peer data carriage | FAST_PEER_NETWORK_V1: pinned mutual TLS, fresh signed connection binding, bounded durable queue/receive/response custody, retry and exact data-tail recovery | `fast_peer.rs`, `fast_peer/{codec,store}.rs`, session/peer binaries and `tests/fast_peer.rs`; explicit local native/owner verification, autonomous head coordination, fee monitoring, independent operators and all composed gates remain required |
| Explicit trusted-file peer head control | FAST_PEER_HEAD_CONTROL_V1: version2 local data custody, exact prepared record and durable committed head, full-authentication recovery without tail repair | `fast_peer/head_control.rs`, shared peer store/session controls and `tests/fast_peer.rs`; local head-file integrity/latest-state is trusted, while native/caller coordination, independent freshness/custody, continuous solvent monitoring and G1-G11 remain required |
| Trusted caller control and native ingress | FAST_SESSION_HEAD_CONTROL_V1: version2 caller state, exact key-free preparation, audited recovery and optional block-only background import | `fast_session/{control,ingress,journal}.rs`, native prevalidation and session/peer controls; `tests/fast_control.rs` and `tests/fast_peer.rs`; owner approval, independent custody, continuous solvent claims, scalable resources and all composed gates remain required |
| Bounded fee-wallet authority | FAST_FEE_WALLET_POLICY_V1: signed actual-input-owner scope, fixed budgets and exact native policy preparations/signatures | `fast_session/fee_policy.rs`, shared caller/native audits and `tests/fast_fee_policy.rs`; no principal signing, close or ordinary-transfer authority, automatic monitoring, independent custody or composed qualification |
| Explicit local monitor and independent background mining | [FAST_LOCAL_MONITOR_V1](protocol/FAST_LOCAL_MONITOR_V1.md): authenticate acknowledged and pending complete custody, compare native protection, resume policy-bounded claims/settlement and mine ordinary own templates | `fast_session/monitor.rs`, private session CLI and `tests/fast_monitor.rs`; automatic carriage, hostile inclusion, physical-time continuity, independent custody, resources/mass exit and composed G1-G11 remain mandatory |
| Native escrow action authorization | FAST_NATIVE_ACTION_AUTHORIZATION_V1: exact ordinary fee-input reservation, full native review, explicit encrypted-key signature custody, historical exit evidence and own-template CPU candidates | `kernel/fast/planning.rs`, `fast_session/onchain.rs`, session caller/CLI and `tests/fast_onchain.rs`; continuous solvent monitoring, guaranteed inclusion, independent latest-state/key custody, physical routes and composed G1-G11 remain required |
| Signed operation carriage and pool mining | FAST_NATIVE_OPERATION_POOL_V1: bounded existing-signature custody, versioned peer data, normal native own-template selection and explicit candidate admission | `fast_session/pool.rs`, peer codec/session CLI, `fast_store.rs` and `tests/fast_pool.rs`; queue/candidate/inclusion/maturity remain distinct, with all autonomous coordination, monitoring, custody/resource and composed gates still required |
| Ordinary native funding authorization | FAST_NATIVE_TRANSFER_AUTHORIZATION_V1: exact existing C04 transfer review, cross-operation input reservation and explicit encrypted owner signature custody | `kernel/fast/transfer.rs`, `fast_session/transfer.rs`, shared authorization audit and `tests/fast_transfer.rs`; real retainer funding is distinct from continuous service, joint opening, independent custody and all composed obligations |
| Joint native opening authorization | FAST_NATIVE_OPENING_AUTHORIZATION_V1: exact proposal, independent own-input reservations/partial signatures and fully verified retained closure within original limits | `kernel/fast/{codec,opening}.rs`, `fast_session/opening.rs`, shared authorization/peer controls and `tests/fast_opening.rs`; proposals/partials/combine/inclusion remain distinct, while continuous monitoring, latest-state custody, independent resources and composed gates stay required |

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
