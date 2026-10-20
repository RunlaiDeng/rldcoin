# Operator and wallet workflow

No command in this guide was used to create keys or launch a network during the
rebuild. The commands describe future operation of an explicitly approved fresh
network. Read `rld <command> --help` for exact options. Files containing keys,
passwords, custody state, node state or generated proofs belong outside Git.

## Descriptor and key order

1. Build both guest programs and the local prover. Save `rld-prover profile`
   output as the proof profile for the intended build. Compare it to the pinned
   `rld profile` output; different programs must not initialize or open monetary
   state. The source-bound profile update workflow is described in README.
2. Each operator creates a fresh encrypted wallet/identity using `rld key create`.
   The password is prompted locally. Retain its independent latest-head file.
3. `rld domain identity` binds the domain identity key and a fresh nonce. Its
   digest is the domain ID. These identity files contain public data only.
4. `rld currency draft` binds the bootstrap identity, exact bootstrap validator
   identities and compiled proof profile. `--network research` is the default;
   choosing another purpose does not authorize a monetary launch.
5. Each validator uses `rld key validator` with its own identity vault and exact
   currency/domain/epoch binding. Native/controller seeds remain encrypted in
   that validator's vault. Distribute only the public inventory.
6. `rld domain draft` constructs public roots, limits, fee policy and initial
   anchor. Each operator reviews the exact descriptor. Pass `--fee-policy` when drafting
   if the generated one-atom default is unsuitable; changing it requires
   recomputing the initial anchor before admission/attestation;
   defaults are not evidence of economic sustainability.
7. `rld domain admission` produces the private public-inventory proving witness.
   `rld-prover native --input ... --output ...` creates its real admission receipt.
   This may be costly; no fake receipt or skipped inventory is accepted.
8. Both the domain identity owner and the required validator quorum run
   `rld domain attest` over the identical identity and configuration. The
   encrypted identity vault durably refuses a conflicting initial approval for
   the same currency/domain scope.
9. `rld domain assemble` requires the identity owner's signature, validator
   attestations and real inventory admission receipt. `rld node init` then
   initializes a fresh store and a latest-head file outside that store. It
   verifies a zero-issued state. No seed, balance or ledger is migrated.

Each node runs `rld node serve --store ... --latest-head ... --config ...`.
A validator supplies matching `--signer` and `--signer-head` pairs; an observer
omits them. All nodes use a separate encrypted transport identity. HTTPS listener
certificate/key and configured peer pins are operator inputs, not autoprovisioned
trust. Plain HTTP is permitted only on loopback. Peer service configuration is the
typed `rld_node::service::Config`; an empty peer list provides no physical route.
The optional proof executable is the absolute path to the built `rld-prover`.
No global Earth directory is required. Actual contacts are required for delivery.

## Ordinary mining

A user creates their own encrypted wallet, obtains the authenticated intended
currency descriptor and configures a node endpoint (plus its certificate and pin
for HTTPS). `rld mine` requests active grant frontiers and searches Argon2id work
with a bounded number of CPU workers. Each worker requires at least the work
profile's 64 MiB working memory plus process overhead. A found solution is signed
by that user's payout key and submitted. "Queued" is not an earned reward;
certified native inclusion consumes the slot and creates the fixed reward.
Competing or stale frontiers can lose. CPU eligibility does not promise profit,
a fair per-person share or ASIC resistance. Mining does not require an RLD fee.

`rld claim-work` searches proportional work for an explicit placement template.
Its single-key search command signs only the found solution. The core supports
threshold claimant policies through separately combined exact authorizations.
A claim still needs an authenticated source-bound receiving coupon, funded
sponsorship and native inclusion; work alone moves no slots.

## Payments and resources

`rld draft` operates on an exclusively opened, fully replayed local store and a
JSON construction request. `crates/cli/src/builder.rs` defines the strict request
schema. Friendly builders support local payment, prepared payment, prepared
claim, service funding and funded family construction. The simple payment
builder conserves one exact cover; an explicit `native_command` request supports
the full mixed-cover/signed-lift protocol. Amounts are decimal atomic strings.
Drafting never signs or reserves inputs. Do not rebase a reviewed ticket's nonce,
fees, recipient, range or expiry context while collecting owner signatures.

`rld wallet sign` appends one actual owner's authorization to the exact operation.
For threshold/group inputs, each owner reviews and signs independently; the node
requires every actual input owner's policy. `rld node submit` submits the signed
operation. `rld wallet balance` reads a local verified node; `remote-balance`
requires a matching real current execution receipt and quorum. It refuses if the
proving pipeline has not reached that exact state. Displayed storage heads are
not independent freshness proofs.

Before creating a coupon family, derive its ID with `rld family-id`. Sponsors
fund source/controller and destination service contracts binding that ID and
finite capacities. `rld node funding` extracts exact certified contract evidence.
The family builder computes the committed leaf root. `rld node coupon` extracts
a coupon's membership/reservation evidence from an already committed family.
The complete `FamilyFunding` object can be extracted from the family operation's
`command.CreateFamily` field. Neither a Merkle leaf nor a source name replaces
these certificates.

The proof worker separately proves fixed historical controller births and the
prospective Exported relation, then queues a terminal PBFT candidate. Other native
operations continue. A finalized release is carried to the destination, whose
native executor verifies it and permanently imports or rejects it.

For cancellation while the source stays online, `controller cancel-fetch` checks
the direct native birth certificate and inclusions against the retained original
preparation operation; it does not wait for an execution receipt. Local operators
can also use `cancel-draft`. Then `cancel-sign` and `cancel-submit`
construct and authorize the original return statement. It competes with Exported
in that same immutable controller. A finalized Canceled QC authorizes one source
redemption directly; a local timer cannot. After Exported, use a destination
Reject command. Once a covering native receipt exists, the node carries both
its decision and coupon-use witnesses back to the source. `rld node recovery-draft`
constructs the source operation from that retained evidence; the original recovery
owner must sign it. Submit RedeemRejected with the exact release and destination
certificate. Recovery
changes neither the original fees nor the accepted covers.

Unused coupon closure is source-native and use-policy authorized. After that
closure, or after canceled source redemption, `rld node closure` extracts the
source's certified closed delegation. Submit `CloseDestinationCapacity` at the
named destination to record closure there. Reused, delegated or destination-used
coupons refuse. Historical closure evidence remains retained.

## Disconnection, recovery and succession

`rld relay export` packages bounded exact spool objects into a signed one-way
bundle. `rld relay import --pinned-sender ...` verifies its separately configured
sender pin, retains complete bytes and emits a signed custody receipt. Stop the
service before opening its spool with the offline CLI; the exclusive spool lock
refuses a concurrent writer. A new encounter still needs an operator-approved
pin and actual physical carriage. Restarting the node performs ordinary native
verification of retained incoming objects.

Node transactions write immutable event bytes, a pending marker, the manifest
and the independent head before acknowledging. An interrupted node refuses
ordinary operation. `rld node recover` cold-replays exact retained events and can
finish an already prepared publication, including a complete event written before
its pending marker. Corruption or unexplained residue refuses without rewriting
it. Recovery does not invent missing consensus votes or rerun an owner payment.
`rld key recover` reconciles an interrupted encrypted publication against its
separate head; it creates no signature. Keep damaged originals for investigation.

`rld handoff draft`, `attest` (with `--new` for the incoming quorum) and
`assemble` construct the exact succession operation. `rld domain admission`
proves the drafted next configuration's public inventories. Handoff uses
an explicitly drafted next configuration, fresh public inventories,
real inventory admission and exact old/new identity acknowledgments. The old
quorum authorizes the exact committed prestate under `RLD-HANDOFF-AUTHORIZATION`;
the new quorum acknowledges it under `RLD-HANDOFF-ACK`. Supply these through the
typed Handoff native command. Old controller vaults must remain available for
unresolved controllers. Native key exhaustion stops signing; it does not reset
height, money, coupons or import identities.

Do not restore copied signing vaults to concurrent machines, replace an unavailable
authority by copying balances, discard unresolved evidence on timeout, publish
private state, or interpret a transport receipt as recipient spendability.

## Complete event segments

The journal seals eligible old immutable event frames into bounded complete
segments, retaining its exact hash chain and latest-head binding. `rld node
archive` performs the same maintenance on an exclusively opened stopped node.
There is no monetary state migration, pruning of unresolved monetary evidence
or new signing authority. Node cold replay checks segment bounds, every frame,
whole segment hashes and source-head observations before completing interrupted
seals. It then re-executes all protocol events. A sealed segment is storage, not
a proof or a trusted serialized ledger. Damaged packs and unexplained residues
refuse without overwrite. This does not provide an independent off-machine
archive service or solve large-state memory use.

The prelaunch PBFT profile `RLD-ED25519-HEIGHT-POOL-PBFT-SUMMARY-2` refuses old
descriptor profiles. New-view summaries bind ordering evidence; selected complete
payment material remains required before the primary can propose or validators
can prepare/commit. Keep original material available through view changes. A
signed ordering summary is never a replacement execution proof.

## Proving service resources and recovery

When `proof_executable` is configured, `proof_work` must name a dedicated
workspace. Its `WORKSPACE.cbor` binds the exact currency/domain/genesis and its
exclusive lock prevents two worker supervisors sharing it. Legacy unbound
proving directories refuse unchanged; retain them and choose a fresh directory.
The node's authenticated ledger and keys are not migrated by this choice.

`proof_concurrency` is 1–3 (default 3). Birth, controller and current-native lanes
each run at most one job. Three permits allow the three classes to progress
independently when sufficient compute/memory exists; one or two intentionally
serialize some work. `proof_bytes` defaults to 1 GiB of retained workspace files,
with a fixed 16,384-file maximum. These are admission limits, not proof-cost
estimates. They do not bound a prover's RAM or separate SDK scratch space; use
an independently budgeted process/service environment. The supplied production
template still disables the prover until suitable resources are arranged.

`proof_timeout_seconds` defaults to 3600 and accepts 1–604800. Measure actual
intended proving requirements before choosing an operational value. A timeout
requests termination of the isolated Unix prover process group and waits for the
direct child; it neither cancels a controller nor refunds value. Failed targets
back off while other eligible targets rotate. This policy claims no measured
receipt latency or operating capacity.

Each job retains a canonical `native-<input-hash>.input.cbor` or
`controller-<input-hash>.input.cbor`. Prover attempts use unique output names.
Failed/partial attempts and bounded logs remain exact. Only an independently
verified exact image/journal result is renamed to `<kind>-<hash>.receipt.cbor`.
A crash after computation can leave an attempt requiring reproof; it cannot
turn a partial receipt into a cached success. A malformed canonical receipt
refuses without overwrite. Retain it for investigation; use the ordinary verified
certificate/candidate submission path for a separately obtained valid result.

Workspace saturation pauses new proving attempts and reports an error. Existing
settlement and direct-birth-QC cancellation do not depend on proof workspace
space. Retain the saturated directory and its evidence; provision a new dedicated
workspace after stopping the supervisor if more space is needed. Do not delete
unresolved evidence to make room. This remains operator-managed retention, not
an independently replicated or paid archival lifecycle.

## Exact-checkpoint state queries and derived disk material

Every normally served node runs a background derived-state indexer even when its
local prover is disabled. It indexes current state, outstanding controller births
and the latest certified proof base using retained native checkpoints. The private
`state-index/` directory inside the node store contains a network/genesis binding,
complete canonical state chunks, bounded Merkle pages and checkpoint manifests.
Its immutable objects are shared by exact content. All admitted files, including
partial writes, count toward the fixed 2-GiB / 65,536-file derived cache budget.
Full cache capacity stops cache growth; it does not expire money or delete native
history. A snapshot may lag behind the current head. Status reports a retained
`state_index_error` if index construction or reads fail.

The authoritative journal and independently retained latest head are unchanged.
On every cold open the node fully replays the journal before using this cache.
A historical proof input loaded from disk still reconstructs complete native
State, checks invariants and the exact caller-retained checkpoint root. Direct
page queries verify native membership or adjacent-neighbor absence. Missing or
bad query pages fall back to complete verified State. Missing/bad complete State
falls back to native journal replay; bad bytes remain for investigation. They never become balances or signing authority.

`rld node state-witness` uses indexed membership when available and keeps the
existing native fallback. For a running node, `rld node state-proof` accepts the
same pinned endpoint/TLS options as other API reads and additionally requires
`--currency`, `--checkpoint`, `--at`, `--collection`, `--key` and `--output`.
Its target checkpoint must be independently retained. The node must already have
an exact execution receipt for that checkpoint. The client verifies the pinned
currency's real execution receipt, finality QC, exact checkpoint/collection/key
and membership or absence before saving. A valid old result gives no assurance
that an output is currently spendable or that a wallet total is complete.

A malformed index is not overwritten or used to recover a ledger. If a derived
index needs rebuilding, stop the node/indexer and retain the entire old
`state-index/` directory under another private name before using a fresh derived
directory. Keep native events, archive segments, manifest, independent heads,
keys and unresolved monetary evidence intact. Rebuilding a derived index creates
no monetary genesis and copies no balances to another currency. No automatic
pruning or independent archival custody service is supplied by this mechanism.

## Source-bound executable profile

The current host embeds `spec/EXECUTABLE_PROFILE.json`. Its build script hashes
length-prefixed ordered native/proof source paths and complete bytes, dependency
locks and toolchain manifests, and refuses a stale recorded source digest.
`rld profile` reports the compiled binding and expected real proof profile.
This guards against an accidental host/VM mismatch; it does not prove an arbitrary
producer's claimed image or replace independent build/security verification.

`rld currency draft`, currency reads for current monetary commands, node genesis
initialization and the initial event of every cold open require that exact profile.
Mismatch refuses before reference execution or recovery publication; old stores,
keys and heads are not rewritten. A source revision with new image IDs cannot
silently adopt the old descriptor or migrate value. General cryptographic suite
succession preserving an already running RLD identity is still unfinished.

## Counted prefix-root executable revision

The 20 October owner-approved amendment changes native map roots and carried
membership/absence paths. The derived index binding is now
`RLD-STATE-WITNESS-INDEX-2`. Old executable descriptors and old cache bindings
refuse unchanged; do not rewrite their identities or reuse monetary state/keys.
Use the exact rebuilt `rld profile` and real `rld-prover profile` binding. This
prelaunch source revision creates no network or monetary genesis.

Current State wire arrays remain complete sorted records. The host and guest
rebuild private lookup/commitment nodes on decode. Native mutation refuses a map
whose proof depth would exceed 64 branches. Node state queries authenticate
historical records against the caller's exact certified checkpoint; they do not
establish freshness or spendability. A capacity refusal never refunds exports.
