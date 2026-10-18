# Interstellar peer-to-peer payment implementation acceptance

This is the current acceptance contract for [RLD-SURVIVOR-1](protocol/survivor-v1/README.md).
The [mechanism-paper research receipt](WHITEPAPER_RELEASE_2026-10-18_MECHANISM.json) binds
the [interstellar open-payment requirements](protocol/INTERSTELLAR_OPEN_PAYMENT_REQUIREMENTS.md).
D01-D06 add product and qualification obligations without changing v1 consensus.
The [local fast-payment requirements](protocol/LOCAL_FAST_PAYMENT_REQUIREMENTS.md)
add F01-F06, F-T01-F-T08 and G9-G11: local p95 <=3s/p99 <=5s usable receipt,
at least 100,000,000 unique completions per continuous day, and a funded positive
protocol fee to miners on every payment. All G1-G11 obligations apply; T01-T22
and D-T01-D-T08 remain mandatory. These requirements do not implement or adopt
a fast-layer codec, script or proof; exact versioned rules and independent
qualification are required before adoption.
The [specification manifest](protocol/survivor-v1/SPECIFICATION.json) binds exact rules
and vectors. The [historical mapping](https://github.com/RunlaiDeng/rldcoin/blob/cf37a9e576f2f6ca581bff0201ce21c9c06cc3ab/docs/WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)
and prior publication receipts retain their original failed/unresolved scopes.
Their BFT results do not qualify this incompatible PoW profile.

The paper body explains mechanisms and analysis. The G1-G11 gate identifiers,
local percentile thresholds, one-day campaign and release checks remain here and
in the bound requirement contracts. Removing their checklist from the paper
does not remove any obligation or qualify an unresolved fast-layer construction.

## Design-to-implementation acceptance matrix

| Implementation gate | Exact contract | Required completion evidence |
|---|---|---|
| G1 Open participation and survivor operation | C03/C06-C08, O01/O06; T06-T07 | Independent ordinary installation; remove founder and all others; preserve history/target; mine, mature, pay and perform actual onward payment; repeat survivors and hard-target collapse |
| G2 Partition and convergence | C05-C10, O02-O05; T05/T08-T10 | Conflicting spends/rewards, actual-work selection and deterministic ties; deep reorg removes losing effects; missing history waits; claimed work cannot halt capable local mining |
| G3 Money and wallets | C01-C05/C08-C09, O03-O06/O11/O13; T01-T04/T11-T13/T17/T22 | Cap, zero allocation, issuance boundaries, strict signatures, parent-only inputs, reward h+100, intent-before-release, exact retry, encrypted keys and atomic conditional balances |
| G4 Delayed transport | O07-O10; T14-T16/T21 | Ordinary authenticated multi-hop/offline carriage, complete-history verification, receipt return, durable queues, restart/fault/capacity behavior, no credit or refund from receipts |
| G5 Independent security and durability | C06, O02-O03/O12; T18-T20 | Independent review and validators, sustained history beyond an issuance era, replay/resources, cross-device/power-loss custody and finite crypto/archive horizons |
| G6 Authenticated release | C03/O12 and conformance release gates | Reproducible artifacts, operating limits, explicit adoption and fresh signed zero-allocation genesis; independently supported route/consumer claims |
| G7 Ordinary-user mining | D01/D06; D-T01/D-T07 and G1/G5 | Ordinary ARM64/x86-64 self-template CPU solo mining without accounts, balances, stake, rosters, mandatory pools or hosted credentials; declared work/resource/power envelope, hostile load, hard-history collapse and early reward concentration; all attempts and uncertainty |
| G8 Causal payment usefulness | D02-D06; D-T02-D-T08 and G2-G5 | Sender-offline directed multi-hop path, complete history beyond one batch, recipient native/cold validation and actual onward payment; exact-signature reconsideration with surviving inputs, explicit orphan reward/conflict/expiry failures, retained reservations and complete route/partition cohorts |
| G9 Local seconds-scale usability | F01-F02/F05-F06; F-T01/F-T04-F-T08 | Each declared normal cohort p95 <=3s/p99 <=5s from original owner submission through independently verified funded durable recipient state; actual onward payment, unilateral recovery, full failure/pending denominator and honest separate settlement clocks |
| G10 One hundred million daily payments | F03/F06; F-T02/F-T04-F-T08 | At least 100,000,000 unique real completions in one continuous wall-clock day with G9 latency and G11 fees; declared peaks, distributions, liquidity/resources, actual funding/settlement/mass-exit capacity and independent reproduction |
| G11 Every-payment miner fees | F04/F06; F-T03-F-T05/F-T07-F-T08 | Positive owner-authorized fee per payment, exact backed entitlement/completeness/allocation, no omitted/duplicate/diverted fees, actual native payout, h+100 maturity, conserved reorg and funded service economics |

G7-G11 are additional gates, not a new certificate of implementation. The exact
D-T01-D-T08 procedures in the overlay supplement the baseline. A logical capsule
needs a separately fixed canonical codec and negative interoperability vectors
before a capsule implementation claim. The [version-1 file codec](protocol/PAYMENT_CAPSULE_V1.md)
and its public byte vectors define a streamed complete-history container; its
native API and checks are mapped below. It does not extend the contact payload
registry or qualify a physical carriage adapter. An existing transaction/block
packet alone does not complete that obligation. Full history remains required; no manifest,
header or receipt supplies ledger authority. Reuse evidence only for the exact
overlapping source/profile and observation, without upgrading baseline passes to
unmeasured G7-G11 or independent/physical qualification.

The normative F-T01-F-T08 matrix defines the new exact campaign obligations.
G9-G11 require composition in the same daily campaign, not separate speed, volume
and fee demonstrations. Unfinished normal-cohort operations count as infinite
completion latency; all original clocks, failures/refusals and pending ages remain.
Fast entitlement, selected base inclusion, actual miner settlement and maturity
are separate observations. Ordinary C04 packets do not implement channels; an
unchecked operator credit, aggregate hash or unbacked future fee does not qualify.
No changed extension can borrow baseline or historical fixture qualification.

## Mandatory distinctions

The ordinary three-process offline-payment check requires the recipient to remain
at genesis until the source exits normally. The relay must then reopen its exact
retained native history and admitted contacts without a configuration argument,
deliver only forward frames and exit before the recipient authorizes an actual
onward spend of that exact output. Recipient cold startup likewise omits the
configuration argument and fully replays both signatures and conserved value.
No reverse receipt, source restart or controller-injected ledger can satisfy this
observation. This finite composition is necessary evidence for D-T03, not complete
G7/G8, independent operations, physical carriage or fast-layer qualification.
The full two-relay case additionally requires the source to exit before the first
relay forwards to the second. Stop the first relay after exact downstream native
custody, restart the second with retained admission, then complete only the final
forward leg. Both original payment bytes and recipient-authorized onward spending
must survive cold replay. An export-peer choice cannot hide other admitted direct
destinations or turn their traffic into unknown-route carriage. Retaining those
packets for their correct peer is scheduling, not a receipt or custody discharge.
Receiver-local destination receipts are expected even on a one-way path. Check
each complete receipt against its original packet and actual local receiver key;
such self-signed rows do not establish reverse delivery. The source still retains
zero imported destination/hop receipts, and no controller leg carries reverse bytes.

The isolated [native candidate](../tools/survivor-node/README.md) supplies the
implementation entry points below. These are auditable source locations and
required checks, not completion certificates for the campaigns above.

| Scope | Native source | Discriminating executable checks |
|---|---|---|
| Consensus and work | `kernel.rs` | `consensus.rs`, `recovery_target.rs` |
| Durable selection, rollback and restart | `store.rs`, `store/replay_witness.rs`, `observations.rs`, `observation_cache.rs` | `storage.rs`, `observations.rs`, `crash.rs`, `history.rs`, `history_backup.rs`, `cold_groups.rs`, `deep_reorg.rs`; native observation-cache unit cases |
| Wallet, pool and encrypted recovery | `wallet.rs`, `pool.rs`, `keyfile.rs`, `backup.rs`, `backup/stream.rs` | `wallet.rs`, `wallet_binding.rs`, `wallet_history.rs`, `consumer_status.rs`, `pool.rs`, `pool_policy.rs`, `backup.rs` |
| Authenticated delayed custody and ordinary synchronization | `contact.rs`, `contact/syntax_witness.rs`, `carriage.rs`, `offline.rs`, `tls.rs`, `network.rs`, `network/offline_history.rs` | `contact.rs`, `intrinsic_reuse.rs`, `carriage.rs`, `carriage_sequence.rs`, `offline.rs`, `offline_binding.rs`, `offline_oneway.rs`, `tls.rs`, `network.rs`; offline-history scheduling unit cases |
| Ordinary survivor payment and distribution | `main.rs`, `bin/rld-survivor-package.rs` | `process.rs`, `payment_process.rs`, `offline_payment_process.rs`, `contact_pressure.rs`, `listener_recovery.rs`, `operating_policy.rs`, `distribution.rs` |
| Retained ordinary contact admission | `network.rs`, existing CLI retained-config startup | `retained_configuration.rs`; native admission restart/replacement, interrupted publication, backup mismatch and symlink refusal cases |
| Exact-intent evidence capsule | `capsule.rs`, native CLI capsule commands | `capsule.rs`, `capsule_process.rs`; canonical public byte vectors, initial invalid-tail refusal, changed reread, unchanged-X refresh, stronger-local-work/clock checks and actual recipient onward payment/cold replay |
| Prospective fast fee-range component | `fast_fee_claims.rs`; [candidate component rules](protocol/FAST_MINER_FEE_CLAIMS_V1.md), not an adopted funding/payout profile | `fast_fee_claims.rs`; exact public context/certificate bytes, cooperative fee-erasure counterexample, retained monotone ranges, unchanged-state refusal and explicit withheld-claim limitation |
| Native no-value escrow execution | `kernel/fast.rs`, `kernel/fast/codec.rs`, `bin/rld-fast-escrow-candidate.rs`; [separate profile](protocol/NATIVE_FAST_ESCROW_V1.md), not an adopted service | `native_fast_escrow.rs`, native window boundary unit; real nonce search/mature funding, original-input double-spend refusal, immutable windows, old fee proof, exact settlement/maturity, invalid complete block atomicity and full cold process replay |

Source paths are relative to `tools/survivor-node/src`; checks are relative to
`tools/survivor-node/tests`. The payment process check uses ordinary mining, wallet
review/signing, authenticated synchronization and recipient-authorized onward
payment after the source process exits. The crash check interrupts real processes
at ledger persistence boundaries; it does not simulate a storage controller losing
power. The archive check extracts the allowlisted distribution with the host tar
reader and uses only its extracted executable to create an encrypted wallet, mine
actual blocks without neighbors, check exact issuance/reward ownership and restart
with the same chain, selected head, revision, root and wallet balance. It retains
the original fresh-genesis zero-allocation check. Local or CI execution of these checks
cannot satisfy the independent-validator, consumer, physical-route or sustained
history obligations by itself.

An intrinsic block-syntax witness retains at most one complete 262,144-byte body
and its exact chain in this process/executable validation domain. It is recorded
only after all intrinsic checks, including every transaction signature, succeed.
Different bytes/chain, eviction, unavailable allocation or lock contention uses
normal complete validation. Every new packet/frame signature, challenge and role
still authenticates independently; all parent, timing, ownership, maturity,
conservation and state-root execution remains native and uncached by this witness.
The checks re-mine a changed bad signature, reject a changed chain and new invalid
envelopes, and preserve ledger state after repeated intrinsically valid false-root
bodies. These finite checks do not qualify arbitrary distinct expensive inputs,
independent security or sustained whole-system load.
Retained offline deliveries must reauthenticate their exact local sender,
configured receiver, zero-challenge adapter and nonzero nonce on every re-emission.
The entire carried packet must equal the requested durable bytes, including its
signature. `offline_binding.rs` substitutes independently valid packets and frames,
including a different valid signature with the same packet ID, and requires warm
refusal without rewriting data or creating custody. Cold rejection remains
mandatory; it cannot substitute for checks during the existing process lifetime.
Packet lookup must bind the decoded signed packet to its requested ID and retained
origin/sequence/kind fields before returning it or acknowledging duplicate custody.
The same regression checks valid signed-byte substitutions and altered indexes,
with unchanged retained bytes, sequence and custody counts after refusal.
Receipt import must repeat the complete retained-delivery role, adapter, nonce and
packet-byte checks before either destination or hop custody is written. A correctly
signed receipt cannot cure a substituted outgoing row. Negative controls include
another valid signature for the same packet ID, zero nonce and wrong link roles;
an error must not leave a destination receipt committed before hop validation.
Forward-only offline history checks must start a recipient behind the sender and
carry no reverse request, receipt or advertisement. The sender must proactively
offer the complete prefix through ordinary ticks; one missing block and a prefix
longer than the 16-block offer batch are separate checks. Adapter restart must keep
unreceipted exact packets; the recipient must independently execute and cold-replay
the same complete selected state. Scheduling checks also require reorg reset,
quota refusal without skipped dependencies and refusal of malformed progress.
These are finite ground checks. Full ancestry walks, indefinite missing receipts,
arbitrary history size and route capacity remain explicit resource obligations;
forward delivery cannot grant the sender an unreturned custody acknowledgment.
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

Explicit local operating policies must be typed, duplicate-free, chain-pinned and
validated before native state/key creation. Each startup chooses published defaults
or its explicit local file; no peer, packet or backup increases budgets. A declared
small-budget capacity refusal must preserve the native prefix and pending operation;
reopening with a separately predeclared larger policy must fully replay that same
history, recover the exact request, and perform actual owner-authorized payment and
onward payment. Resource expansion cannot prune evidence or create a new allocation.
Mining trial observations count actual hash calls, not inferred work or profit;
unknown counters never suspend mining. Honest-time collapse remains a distinct gate.

V2 whole-node backups authenticate fixed bounded chunks, exact file lengths,
index/order, role, chain, bundle and inventory. A full local head also binds exact
communication keys/material and admitted configuration. Source material changes
refuse; restore must validate all material, key pairing and native ledger/custody
state before clearing RESTORING, with no socket activity or key regeneration.
Changed/reordered/missing/repeated/cross-role chunks, tail data, wrong password,
unsupported metadata and valid-but-substituted transport keys cannot authorize a
complete restore. Only caller-provisioned budgets admit larger images; ciphertext
buffers remain bounded independently of total file size. Native operating-policy,
stream-record and material unit cases cover these contracts. Whole larger-state,
power-loss, independent freshness/custody and finite-horizon qualification remain
separate; the format alone proves none of them.

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
qualification remain mandatory. The required fast layer must receive separate
versioned safety, conservation, fee and adoption qualification; it is not an
existing Survivor-1 capability. Guardians, regional issuers, PQ monetary adoption
and instant/final stellar settlement remain outside baseline capabilities.
Unsupported extensions refuse.

## Completion rule

All applicable T01-T22, D-T01-D-T08 and F-T01-F-T08 obligations require scoped
evidence before a complete-product claim; G1-G11 and independent release duties
all apply. G9-G11 targets are not satisfied by publication of this revision.
Implemented functions alone do not satisfy independent or physical gates.
New money is prohibited until G6 is explicitly met; old test balances, abandoned
archives and fixture keys cannot supply that authority.
