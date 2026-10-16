# Conformance, security obligations and adoption

## Required invariants and proof obligations

Every implementation must preserve these invariants over all accepted transitions,
including replay, reorganization, lost responses and resource refusal:

1. A selected state is the execution of exactly one complete genesis-rooted valid
   chain. Indexes, receipts, peer claims and caches never initialize authority.
2. Every consumed output existed in the parent, was mature and authorized by its
   owner, and is consumed at most once within that history. All transfer outputs
   and fees conserve its amount. Canonical bytes bind every authorization.
3. UTXO sum equals deterministic selected-height issuance <=10^35. A reorg replaces
   issuance; it never sums branches. Recovery work uses actual target, not base.
4. Deterministic execution of identical inputs gives identical IDs, roots and work.
   Selection of an identical complete eligible candidate set is arrival-independent.
5. An acknowledged state change or custody result has all required exact bytes
   durably retained. Invalid/incomplete transitions cannot publish partial value.
6. No absent peer, quorum, directory or remote clock approval prevents a correctly
   resourced full node from attempting recovery mining. This does not override
   signature validity, clock prerequisites, resource exhaustion or probabilistic work.
7. User-visible balances and inclusion bind one selected revision. Rollbacks and
   incomplete validation remain visible; confirmation is always conditional.

Induction on chain length provides the accounting argument: zero genesis supplies
the base case; disjoint mature owner-authorized inputs are replaced by equal outputs
plus fees; adding reward returns those fees and exactly the specified subsidy.
Reorganization selects another chain satisfying the same induction, not the union.
This reasoning assumes correct canonical parsing, signatures and execution. It is
not an independent proof of implementation correctness, economic security, clock
honesty, asynchronous convergence or crash durability. Those require separate
adversarial analysis and verification. The C06 recovery mechanism in particular
does not inherit Bitcoin's security analysis unchanged.

## Public executable vectors

[vectors.json](vectors.json) contains deliberately public **NO-VALUE** fixtures.
Its deterministic signing material is derived solely from published RFC 8032 test
inputs and must never secure assets. Public keys/signatures and transaction/block
bytes are included so other implementations can reproduce every stated result.
JSON amounts/heights are decimal strings; hex is lowercase. JSON itself is not a
consensus serialization. The associated Rust tool regenerates and compares the
complete expected object, rather than checking only a few digest substrings.

The vectors cover genesis and zero state; transfer bytes, signature and ID; empty
and populated tree roots; complete mined blocks through reward maturity, payment
and onward payment; a competing greater-work branch and deterministic tie selection;
issuance boundaries including the final nonzero reserve; target scaling and actual
recovery work; packet/delivery/receipt bytes; and exact byte mutations with the
required rejection/wait interpretation. Small fixtures do not establish throughput,
durability or production implementation conformance. Vector-tool code is an oracle
for these finite examples, not an alternate node or an adoption authority.

## Required implementation campaigns

The following are acceptance contracts, not claims that the tests have run. Each
campaign must bind exact protocol/source/build/genesis and distinguish independent
operators from multiple processes under one controller. Negative cases must verify
that selected tip, balances, reservation heads and acknowledged custody remain
unchanged when no commit is permitted. Failures and original deadlines are retained.

| ID | Required stimulus | Discriminating expected observation |
|---|---|---|
| T01 | Independently decode/reencode all public vectors on two architectures and two independently written validators | Exact bytes, IDs, signatures, roots, work and selection agree; unknown fields/versions and noncanonical encodings refuse |
| T02 | Overflow/underflow; zero/over-cap outputs; rounding at every era boundary and final reserve; work near maximum width | No wrap or inflation; exact cap; post-exhaustion zero subsidy; fees still transferred |
| T03 | Duplicate inputs, reordered inputs/IDs, mixed owners, signature/chain/expiry edits, torsion/noncanonical A/R/S, same-block child | Refuse exact malformed/unauthorized block without state change; no library-policy divergence |
| T04 | Reward at h; spends in h+99 and h+100; ordinary output and next-block onward spend | First immature spend refuses, mature spend accepts, ordinary output spends only in a later block; wallet boundaries agree |
| T05 | Every target-window boundary; clamp endpoints; gap14399/14400; future now+7200/+7201; clock rollback | Exact B/T/work; future defers and later activates, wrong intrinsic timestamp refuses; clock fault suspends mutation |
| T06 | Stop all other declared processes/hosts; repeat with each surviving ordinary full node, no privileged key/server | Survivor mines actual block, matures actual reward, signs/includes payment and subsequent recipient-authorized onward transfer under the ordinary lifecycle |
| T07 | A valid very-hard base followed by collapse to one weak miner, with other services unavailable | Recovery rule activates without committee; honest clock and actual hashing used; preserve real waiting times and unsuccessful attempts; never call a forced easy genesis a collapse test |
| T08 | Two partitions spend the same input differently; extend both; reconnect in both arrival orders | Fully replay winner; same work/ID rule; losing reward/payment/descendants removed; no sum of branches; reoffering preserves exact signatures |
| T09 | Equal work, lower-ID rival; greater height but less work; low-target many-block branch; withheld heavy history | Winner follows actual cumulative work/tie only; no confirmation-depth checkpoint or base-work inflation |
| T10 | Reorg older than cache/active window; missing ancestor and then recovered ancestor; corrupted snapshot | Full replay or REORG_WAIT, never an invented state; recover exactly after evidence arrives |
| T11 | Crash at each intent/object/commit/response boundary, torn writes, disk-full, lost responses and duplicate operation IDs | Prior or exact committed successor only; exact retry cannot double-pay; torn intent grants no new authority; power-loss tested separately from process kill |
| T12 | Old whole-wallet backup, copied keys, stale caller heads, interrupted restore and missing independent freshness | Latest evidence checked where available; FRESHNESS_UNKNOWN disclosed otherwise; explicit signing policy; no claim of independent single-active custody |
| T13 | Password/KDF/header/tag/chain/key mismatch, nonce/entropy failure and wrong-purpose file | Native refusal without plaintext release or fallback; interrupted replacement retains old encrypted file |
| T14 | Multi-hop directional contacts, arbitrary long simulated delay, no return link, offline frame delivery, destination initially behind | Ordinary relay resumes; exact history requested; destination independently validates before ledger credit; no simultaneity assumption |
| T15 | Packet substitution, wrong origin/destination, changed signature/nonce, receipt replay, zero challenge on TCP, forged HEAD/work | Refuse unauthorized custody/claims; no peer hint becomes money; destination receipt binds exact packet and roles |
| T16 | Duplicate/reordered/lost packets, restart, connection loss after ack, queue saturation, alternate path, loop traffic | Durable idempotence and fair retry; no timeout refund/deletion of obligations; capacity refusal preserves accepted data |
| T17 | Reorg after destination custody, after local inclusion and after onward payment | Historical receipt remains true, selected balances/statuses change atomically and visibly; descendants do not retain invalid value |
| T18 | Sustained history beyond200000 blocks, many owners, growing spent/UTXO/archive state, cold restore, heavy malformed traffic | Measure separate CPU/RAM/disk/replay/carriage costs; bounded resource refusal preserves state; no test-only lifetime height cap |
| T19 | Independent build/replay/security/custody review and adversarial differential fuzzing | Publish disagreements/unresolved threats; no same-author tool counted as a second independent implementation |
| T20 | Unsupported suite/version, stale trust, simulated broken old key, missing originals, compromised relay and local eclipse | Refuse unsupported authority; no fake renewal or automatic migration; disclose inability to infer hidden competing work |
| T21 | Real independently operated physical contact route and separately declared long-disconnection/storage horizon | Demonstrate actual link capacities, custody, interference, key validity and restoration; simulation cannot pass this gate |
| T22 | Consumer installation through backup/restart/payment/reorg, stale API and missing notifications | Clear conditional status and resync; no fabricated balance, payout guarantee, irreversible confirmation or “delivered” based only on local queue |

T06 alone does not prove T07, T18 or T21. An unlimited wall-clock guarantee is not
an acceptance target. Cohorts must predeclare hardware, hash rate, clocks, load,
capacity, fault model, observation budget and success criterion. Exhaustion is a
reported limit or failure, never permission to relax validity or silently raise
bounds. Distinguish protocol liveness from implementation throughput and from
continued ability to buy power, storage and archival service.

## Security disposition and service boundaries

| Threat | Defined defense/behavior | Residual and required gate |
|---|---|---|
| Sybil/eclipse | Signatures for ownership; actual work for selection; independently admitted contact pins | Peer count cannot establish honesty; eclipsed survivor may accept a later-losing history; T07–T09/T15/T20 |
| Recovery/timestamp grinding | Exact time and target rule, actual low work, future eligibility | No proof of physical elapsed time; analyze strategic waits, withholding and difficulty oscillation before adoption |
| Interstellar partitions | Independent local mining and delayed complete-history exchange | No guaranteed branch preservation, global finite finality or universal confirmation count; T08/T14/T17/T21 |
| Forged funds/overflow | C04/C08 full execution and conservation | Cryptographic/kernel bugs remain; T01–T04/T19 |
| Lost data/old backups | Full history, atomic recovery, explicit freshness state | Extinct bytes/keys cannot be recovered; no eternal maintenance assumption; T10–T13/T18 |
| Storage/CPU flooding | Canonical bounded objects, explicit queue capacity, no credit from hints | A malicious valid load can exhaust a finite device; T16/T18; availability requires resources |
| Governance/compensation abuse | No protocol administrator mint, freeze, refund or recovery override | Off-chain agreements and future opt-in forks are not monetary guarantees; T20 |
| Privacy | Local key custody; pinned TLS on interactive ground links | Transparent ledger, public routing metadata and offline packets are not confidential; physical/offline encryption needs separately qualified adapters |
| Funding | Fees and capped subsidy; explicit capacity refusal | No promise fees fund eternal mining/archives, profitable mining or liquidity; service providers disclose budgets and finite commitments |
| Cryptographic aging | Explicit suite/version and unsupported refusal | Suite1 is not PQ; future upgrade is separately specified/adopted; journey qualification cannot exceed defensible trust horizon |

## Disposition of historical obligations

This mapping explicitly replaces incompatible **candidate** behavior under the
owner's survivor/rollback direction. It does not rewrite historical papers, weaken
the meaning of earlier failures or claim compliance with the former BFT-finality
contract. Monetary accounting, authentic authorization, complete evidence,
independent review, resource disclosure and honest qualification remain mandatory.

| Historical IDs | Survivor-1 disposition |
|---|---|
| I1, S1–S2 | Pinned single genesis/C01–C03 replaces regional issuance/admission. Discovery still grants no monetary authority. |
| I2, S3 | Replaced by C06/O01 single-node PoW progress; missing local quorum is no longer a stopping rule. No Byzantine-finality claim. |
| I3, S5/S8, R14 | Preserved cap/zero allocation/recurrence/conservation; C04/C08 selected-chain accounting replaces regional U/E/T buckets. |
| I4–I6, S6–S7 | Replaced by one-chain transfers and reorg semantics C04/C10/O10. No exports/imports, permanent import IDs, cancellation certificates or independent regional balances. Actual onward/return transfers must still be verified. |
| I7, S4/S9–S10 | BFT locks/epochs/quorum-finality/conflict quarantine replaced by work-based branch replacement and opt-in version adoption. A valid fork is not a double-finality incident. No administrator compensation mint. |
| I8, S13 | Preserved causal custody and ordinary relay O07–O09; receipt is never ledger authorization. |
| I9, S18 | Preserved independent verification and honest states; irreversible finality/3–5-second final-spendability promises explicitly removed. O04/O11 always show conditional selection. |
| I10, S11/S16 | Preserve full history, atomic restoration and explicit freshness limits. Mandatory external freshness witness before all operation is replaced by O03's intact-state autonomy and disclosed risk acknowledgment for uncertain restored signing. Independent anti-rollback protection is not claimed. |
| I11 | Preserve finite-horizon crypto/renewal duties; C02/O12 do not claim implemented PQ migration or indefinite qualification. |
| I12, S14/S17 | Preserve independent implementations/builds, review, resource/funding/operational qualification and separately supported claims. |
| S12 | Direct-key ownership only, O13; no guardian threshold or confiscatory inheritance override. |
| S15 | Public-ledger/metadata privacy limits disclosed; TLS protects only its declared link, not all cosmic traffic. |
| R1–R2 | Delay/partition risk retained; local termination no longer waits for BFT quorum, while conflicting branches and rollback remain allowed. |
| R3 | Sybil/control concentration retained as mining and eclipse risk; identity count grants no work. |
| R4–R5 | Duplicate-credit and descendant contamination duties become parent UTXO execution plus complete losing-suffix removal. |
| R6 | Disconnected upgrade risk remains; no regional reconfiguration shortcut or concealed authority. |
| R7–R8 | Crypto failure/delayed revocation remain explicit limits and independent qualification gates. |
| R9–R11 | Key loss/theft/inheritance, total rollback and data extinction retained; recovery availability does not assert knowledge of destroyed state. |
| R12–R13 | Storage/crypto denial and service funding retained; finite device and economic assumptions disclosed. |
| R15 | Native channels/watchtowers are excluded from version1; offline double-spend exposure remains under C10/O10. No channel qualification claim. |
| R16–R17 | Relay eclipse/false routes and privacy retained; origin/link authentication does not prove path existence or confidentiality. |
| R18–R20 | Clock/entropy/hardware, supply chain and misleading financial claims retained through T05/T11–T13/T19/T22. |
| R21–R22 | In-flight upgrades and invalid compression remain: no credit from missing originals or unvalidated roots. |
| R23–R24 | No hidden compensation authority; claims/maintenance limits and independent requalification remain mandatory. |
| A–B | Preserve identity/authentication and exact work/amount/recovery checks under the new profile. |
| C–D | Preserve independent participants, authentic releases and explicit new genesis/adoption; no fixture balances migrate. |
| E–F | Local/onward/cross-contact transfers tested with conditional settlement. Channels and irreversible regional-finality assertions are not baseline capabilities. |
| G | Independent sustained operation, long history and actual physical-route qualification remain separate. |
| N1–N4 | Preserve purpose-separated identities, progressive discovery, ordinary next-hop relay and durable delayed custody. |
| N5 | Replace full signed path/hop-count claims with immutable origin plus exact per-link authentication O08/O09; no claimed full path proof. Destination tampering still refuses. |
| N6–N7 | Preserve durable idempotence, refusal on capacity and distinct route/contact/custody/ledger/spendability observations. |
| N8 | Replace regional finality/import authority with one selected chain and no relay/region issuance rights. |
| N9–N10 | Preserve actual contact planning, delay/capacity and long-term/independent/physical qualification. |
| P1–P2 | Adoption now selects exact PoW/recovery profile and opt-in release policy, not validator/admission/governance quorums. Independent security review still required. |
| P3 | Suite1 explicit; finite journey limits and future separately specified migration remain required. |
| P4 | Direct-key recovery and explicit rollback-risk policy; no unsupported guardian/channel/fencing claim. |
| P5–P6 | Resource/retention budgets and canonical transfer/selected-chain accounting proof remain required. |
| P7–P8 | Independent release/custody/security review, fresh zero-allocation authenticated monetary genesis and route-specific claims remain mandatory. |

The complete historical numbered set is covered above: I1–I12, S1–S18, R1–R24,
A–G, N1–N10 and P1–P8. “Replaced” means a deliberate change of contract, never
“passed under the old contract.” Legacy stores/genesis/suites remain incompatible.

## Release sequence and gates

1. Freeze the candidate specification and its exact vectors after consistency
   review. Any rule correction changes the specification digest and affected vectors.
2. Reconcile the whitepaper, master plan and acceptance mapping against this exact
   contract. Preserve historic releases and distinguish published claims from goals.
3. Implement a new isolated no-value node/wallet/contact profile; no reuse of old
   monetary state or claim that old candidate tests cover changed bytes/rules.
4. Exercise T01–T22 as applicable, with independent review and explicitly unqualified
   physical/cryptographic/operational domains. Resolve critical correctness issues
   and demonstrate normal user installation/mining/payment/recovery behavior.
5. Consider monetary adoption only after independent consensus-security analysis,
   release/custody evidence, resource horizons and authentic new zero-allocation
   genesis are approved for the actual service being claimed. Unsupported long-range
   routes remain unsupported; a basic launch cannot market them as qualified.

Completing this specification is gate1's design deliverable. It is not completion
of gates2–5, a deployment, or evidence that arbitrary interstellar hardware exists.
The [Bitcoin paper](https://bitcoin.org/bitcoin.pdf) informs work-based conditional
history selection; [RFC9171](https://www.rfc-editor.org/rfc/rfc9171.html) supplies a
possible delayed carriage substrate. Neither source specifies or validates this
profile's emergency difficulty rule, wallet behavior or new acceptance claims.
