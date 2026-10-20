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
split canonical state chunks, bounded Merkle pages for resident collections and
checkpoint manifests. Six disk map observations are bound through verified history.
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
`RLD-STATE-WITNESS-INDEX-6`. Old executable descriptors and old cache bindings
refuse unchanged; do not rewrite their identities or reuse monetary state/keys.
Use the exact rebuilt `rld profile` and real `rld-prover profile` binding. This
prelaunch source revision creates no network or monetary genesis.

Current State wire arrays remain complete sorted records. The host and guest
rebuild private lookup/commitment nodes on decode. Native mutation refuses a map
whose proof depth would exceed 64 branches. Node state queries authenticate
historical records against the caller's exact certified checkpoint; they do not
establish freshness or spendability. A capacity refusal never refunds exports.

## Disk-resident verified native history

Every local node now maintains a private `history-index/` under its store. Its
`RLD-VERIFIED-HISTORY-INDEX-5` binding fixes currency, domain and genesis. Complete
native committed records and immutable 32-way pages are content-addressed in
256 digest shards. Only the process's verified root/length is adopted. Node open
still validates every authoritative event from the separately retained latest
journal head; it does not resume a ledger from this derived directory.

The shared raw-byte cache retains at most 128 objects / 32 MiB. A complete current
State, decoded records, proof inputs, receipts and other live queues are separate
memory costs. Object publication preserves the existing 1-GiB per-record envelope;
pages are at most 16 KiB. The index admits at most 1 TiB and 4,194,304 retained or
reserved files. `/v1/status.native_history` exposes accounted bytes/files, cache
use and these limits; failed-write reservations can conservatively overcount until
verified reopen. Exhaustion/disk failures refuse unsupported publication without
deleting old records, resetting height or refunding monetary rights.

A missing or corrupted indexed record fails the request/reconciliation; it is
never silently treated as a future or unknown height. Preserve the failed object
and authoritative journal. To rebuild derived material, stop the entire node and
all proof/read workers, retain the whole private `history-index/` directory under
a different private name, then cold-open the unchanged journal with its separately
retained latest head. Never copy a root from the old directory or rewrite the
journal/head, keys, currency or balances. This rebuild path creates no monetary
genesis and does not qualify disaster recovery, independent latest-head custody,
power-loss behavior or long-term archival succession.

Immutable history observations let proof/read workers finish against a fixed
prefix while normal commits append a later prefix. API block pages read outside
the node-wide lock. Proof input construction refuses a span exceeding the guest's
existing 4,096-step bound before collecting it; certify an intermediate checkpoint
first. A counting CBOR writer checks the guest's existing 1-GiB input bound
before retaining an oversized step vector, reserving 128 framing bytes. Complete
State and exact subordinate receipts are still required.

## Indexed operation-log proof input

`rld node witness` and normal proof workers now select an indexed native input
when an exact certified predecessor exists. It carries the complete other native
collections and ordered `RLD-NATIVE-APPLIED-ACCESS-1` membership/absence accesses
instead of every old applied-operation record. The guest binds the initial map
root to that predecessor and computes every update from actual operation bytes.
Input construction continues to enforce the existing 4,096 steps / 1-GiB guest
bounds. Ordinary canonical State snapshots still carry every complete applied
record; an internal partial execution state refuses serialization.

If a new insertion cannot prove the 64-branch bound from neighbor paths alone,
the builder selects full native execution under the original bounds. Indexed
byte-budget exhaustion also selects full input, since path overhead can exceed
a short complete map. A full
input that cannot fit still refuses; no larger bound, guessed height or weaker
proof mode is enabled. Genesis execution always uses complete state. The host operation map and five permanent decision/birth/funding maps now use
private disk storage; other collections remain resident. Proving cost, worst-case fallback availability and
remaining collection scale are not qualified by source compilation.

This changes actual native/controller image IDs. Use only the final rebuilt
`rld profile` / `rld-prover profile` binding from this stage. Preserve incompatible
old stores/descriptors and use their matching old release; do not rewrite a
currency, copy old value/keys or treat this as an in-place monetary upgrade.

## Private disk operation map and split state material

`applied-index/` uses `RLD-APPLIED-DISK-1`, bound to the exact currency, home and
authenticated genesis. It starts empty on every cold replay; no serialized root
initializes a ledger. Committed inserts reconstruct exact native prefix roots.
The private object store admits 1 TiB / 4,194,304 accounted files and caches at most
4,096 raw objects / 16 MiB. Status exposes those limits and conservative accounting
under `applied_storage`; failed-write reservations can overcount until reopen.

Candidate state uses at most 8,192 tentative nodes / 32 MiB. These unpublished
working bytes may be discarded; they are not signed evidence or native decisions.
Queue/proposal validation never flushes them. After native execution and QC checks,
reachable changes are synced before journal/Core publication. Existing exact
objects are checked/synced; failed partials/orphans and all published old versions
remain. Storage failure/exhaustion refuses unsupported publication, never refunds
an export, deletes an operation ID, resets a counter or substitutes a root.

Verified history V8 carries all fifteen sealed disk-map snapshots for each native
record. State-material V9 omits their arrays in private serialized material,
retains their commitments, and combines them with the exact observations from
verified history before whole-checkpoint validation. That partial file is not
standalone State or monetary evidence. Historical membership/absence uses native
paths directly; complete public snapshots and full-witness fallback still stream
all records under their original size bounds and propagate storage errors.

Old history/state-index bindings refuse unchanged. Preserve their directories
and use their matching historical release or a fresh correctly bound private
cache; never rewrite a currency, journal/head, monetary keys or balances. A damaged
applied store must be retained. Stop the node and every proof/read worker, retain
`controller-index/`, `service-index/`, `definition-index/`, `utxo-index/`, `permanent-index/`, `applied-index/`, `history-index/` and
`state-index/` under distinct private names, then cold-rebuild all five from the unchanged valid event journal and separately
retained latest head. The disk map and history observations reference exact physical objects, so do not
combine new disk-map directories with old split roots.
This is derived-data reconstruction, not a monetary genesis or value migration.

Other collections, decoded receipts and queues retain separate memory costs. Physical
object amplification and archive funding/packing still need implementation and
operational evidence. No measured memory, throughput, proof latency, independent
freshness, crash/power-loss custody or mainnet qualification is claimed here.

## Disk-resident verified receipt index

Normal nodes maintain a private `receipt-index/` using
`RLD-VERIFIED-RECEIPT-INDEX-1`, bound to currency/domain/genesis. Opening it does
not load a head. Full authoritative event replay reconstructs receipt observations
only after actual receipt/QC and exact local-history verification. It cannot
replace a missing journal, currency descriptor or independently retained head.

The index retains complete Certified objects (at most the unchanged 16-MiB object
bound) and 4-KiB immutable sequence pages. Its shared raw cache is bounded by
4,096 objects / 16 MiB; decoded responses/proof inputs and other node collections
are separate memory costs. `/v1/status.receipt_storage` exposes accounted usage,
cache use and the 1-TiB / 4,194,304-file admission limits. Failed reservations can
overcount until verified reopen. No published version is deleted on quota or
I/O failure. Unsupported receipt publication refuses without refunding money or
changing a native checkpoint; ordinary settlement still has its separate resources.

Missing or corrupted receipt/page bytes fail lookup, scheduling or reconstruction;
they are never treated as an ungenerated proof. Stop the node and all reader/proof
workers before retaining the whole damaged receipt-index directory under another
private name. Rebuild only this derived receipt index by cold opening the unchanged
valid authoritative journal with its separately retained latest head. Do not merge
old/new roots, change currency/keys/balances or rewrite native history. This is
source-compatible derived-data reconstruction, not a monetary migration.

No native/proof source or actual proof image changes in this host-only stage.
The final full build still compares the actual host and prover profiles. No
runtime memory, long-history throughput, crash/power-loss, paid archive packing
or independent security result is established by that compilation.

## Permanent native decision maps

Normal nodes also open private `permanent-index/` with
`RLD-PERMANENT-DISK-1`, bound to the exact currency/domain/genesis. Births,
destination decisions, redemptions, source resolutions and consumed funding share
its immutable objects and raw 4,096-object / 16-MiB cache. Each map binds its
collection tag independently. `/v1/status.permanent_storage` exposes shared
accounted usage and the existing 1-TiB / 4,194,304-file admission limits.

Each map's unconfirmed working overlay is bounded by 8,192 nodes / 32 MiB; the
five maps together permit up to 160 MiB of these working bytes, independently
of the applied map and other memory. No tentative node is written before full
native execution and exact QC validation. Sealing, verified-history publication
and authoritative event append retain every published old/partial/orphan object.
Capacity/corruption refuses, never recreates an unused funding ID or unresolved
payment, deletes a decision or authorizes a refund.

History V8 now binds a complete fifteen-map storage observation (at most 4 KiB).
State material V9 stores empty placeholders for those fifteen maps and requires the
separate verified-history observations plus exact full native root before use.
Those caches are not standalone ledger snapshots. Default indexed guest input now carries exact accesses for these five maps;
complete input remains the bounded fallback described below.

Old executable/derived bindings refuse unchanged. Do not rewrite currency,
keys, balances or old private stores. If reconstructing damaged derived material
for the same compatible source, stop the node and every proof/read worker;
privately retain all `controller-index/`, `service-index/`, `definition-index/`, `permanent-index/`, `applied-index/`, `history-index/` and
`state-index/` directories together, then cold replay the unchanged valid journal
with its independently retained latest head into fresh derived directories.
Do not combine new object owners with old physical observations. Receipt-index
has independent complete certificate objects; no receipt root can initialize a
ledger. This does not migrate an old program's currency to new programs.

No runtime, memory, latency, daily-capacity or crash/power-loss result is claimed.
Other maps, queues, archive packing/paid replicas and cryptographic succession
remain separate implementation and qualification obligations.

## Indexed proof input for permanent maps

`rld node witness` and ordinary proving now prefer NativeInput tag 3,
`IndexedPermanent`, from a certified predecessor. It carries exact typed native
accesses for the five permanent maps plus applied accesses. Initial count openings
and every current root/count/key/value or absence are checked in the actual guest.
The complete native execution, real receipt verification, QC and journal bindings
remain unchanged; these access objects are not certificates or signing authority.

The builder records actual native replay and enforces one shared 1-GiB canonical
input budget, including base/steps/applied/permanent evidence and framing. Each
permanent map admits at most 2,000,000 unique (root,key) accesses. Those are input
admission bounds, not maximum-RAM/proving-cost assurances. Only typed compact
height-evidence or capture-capacity insufficiency selects the previous
applied-only/full inputs under their original limits. Changed data, context,
read/encoding and replay errors propagate. A full input that cannot fit refuses.
Genesis remains complete execution. Partial execution maps cannot be serialized
as complete snapshots or used for arbitrary membership queries.

Use the final source-bound executable profile; this stage changes actual native
and controller image IDs. Preserve old descriptors/stores under their matching
historical release, and do not rewrite currency or migrate money/keys. No runtime
proof campaign, throughput/latency, memory or independent security result is
established by compilation. Other collections, archive retention and future
cryptographic transitions remain unfinished.

## Disk UTXOs and indexed spend evidence

Normal nodes now maintain private `utxo-index/`, RLD-UTXO-DISK-1. Opening it starts
empty; full anchored native event replay derives all later roots. Typed value
objects (8 KiB maximum) and fixed metadata pages (512 bytes) retain exact native
hashes plus independently checked physical summaries. The shared raw cache is
4,096 objects /16 MiB; status exposes its 1-TiB /4,194,304-file admission under
`utxo_storage`. All old spent objects, partials and orphans remain retained.

Each working UTXO observation bounds reachable encoded objects by 600,000 /512 MiB.
Discarded unpublished intermediate Arc paths may be released; signed/native
published evidence is never pruned. This is a separate new UTXO budget, not a
change to the other maps' existing limits or a maximum-RSS/throughput claim.
Native/QC validation precedes sealing, history and authoritative publication.
Missing/corrupt bytes refuse, never become a spent/missing input or empty balance.

History V8 binds fifteen-map observation V6; state material V9 omits fifteen arrays
and requires verified history plus exact complete native checkpoint root. If
rebuilding compatible derived material, stop every node/proof/read worker and
privately retain `controller-index/`, `service-index/`, `definition-index/`, `utxo-index/`, `permanent-index/`, `applied-index/`, `history-index/`
and `state-index/` together before cold replaying the unchanged valid journal
with its independently retained latest head. Do not combine old physical roots
with new owners or rewrite monetary descriptors, keys, balances or journal heads.

Default native witness construction prefers NativeInput tag 4, IndexedUtxo,
from a certified predecessor. It uses typed reads/absence and checked native
append/spend-root derivation at exact current roots, initial count openings and
complete access-use checks. The same original 1-GiB input /4,096-step bounds,
128 framing bytes and per-typed-map 2,000,000 unique accesses apply; applied
retains its existing 4,096*64 ordered-access bound. Typed compact
insertion-height/capture-capacity insufficiency can use prior tag 3/2/full paths;
authentication, replay, I/O and encoding errors propagate. Genesis remains full.
Other collections still need complete material; proving feasibility is unmeasured.

This revision changes actual proof program/source IDs. Preserve incompatible old
stores with their matching release. No currency/value/key migration or monetary
launch is performed. No runtime proof/payment, measured RAM/latency/volume,
crash/power-loss, paid archival or independent security qualification is claimed.

## Disk Mint facts and slot indexes

Normal nodes open private `mint-index/`, RLD-MINT-FACTS-DISK-1, with currency,
home and genesis binding. Both native event and auxiliary slot roots begin empty
and are rebuilt by complete anchored native/QC event replay. No disk head or peer
auxiliary root grants issuance rights. Selected slot records must match the exact
complete event under the native Mint root; read failures refuse, never mean unused.

The roots share a 4,096-object /16-MiB raw cache and 1-TiB /4,194,304-file admission;
`/v1/status.mint_storage` exposes their shared accounting. Typed event/slot formats
remain distinct; UTXO storage encoding is preserved by the shared typed path engine.
Each root uses the prior 600,000 reachable-object /512-MiB encoded working budget;
two Mint roots and other memory/worker allocations add separate costs. Sealing
follows native/header/QC validation; all published old/partial/orphan objects remain.

History V8 binds fifteen-map observation V6; state material V9 restores the separate
verified-history roots and checks the whole native checkpoint. To rebuild compatible
derived data, stop all node/proof/read workers, privately retain `mint-index/`,
`controller-index/`, `service-index/`, `definition-index/`, `utxo-index/`, `permanent-index/`, `applied-index/`, `history-index/` and `state-index/`
together, then cold replay the unchanged valid journal and separately retained
latest head. Never mix old physical observations with new owners, rewrite heads,
change currency or migrate money/keys to a new program binding.

The bounded full-Mint guest path reconstructs the slot index itself. The later
certified access path below can omit that full array when exact correspondence
evidence is retained. No host-only auxiliary root or relaxed work/cap/fee rule
is accepted. This stage changes native/controller image/source
bindings; preserve incompatible old stores with their matching release. No runtime
proof/payment, maximum-size feasibility, memory/throughput/latency, independent
security or paid archival result is established by compilation.

## Real Mint index correspondence proofs

Configured proving now runs a fourth Mint-index lane alongside native, birth and
controller lanes. The configured concurrency/default three permits and byte/file
limits are unchanged. The first job establishes empty correspondence, followed
by changed local Mint checkpoints. These proofs use the actual native program
with a separate journal purpose; they do not issue coins, authorize work, replace
native QC or prove a payment. Native execution consumes the retained relation
through the separate certified access path described below.

For explicit operation, use node mint-index-witness with --store, --latest-head, --at and fresh --output. Feed that input to rld-prover native --input ...
--output ... . Then node mint-index-certificate uses the same --store/--latest-head, --at,
--receipt and fresh --output to verify/publish the result. Store height zero is
valid only for the canonical empty relation. No key material is uploaded or
monetary genesis generated by these evidence commands.

mint-proof-index binds RLD-MINT-INDEX-CERTIFICATES-1 to exact currency/home/genesis;
it opens empty and replays verified correspondence events, never a disk head.
Complete receipt objects and typed references share a 4,096-object /16-MiB raw
cache and 1-TiB /4,194,304-file admission. Status exposes
mint_correspondence_storage. Corrupt/missing objects refuse; partials/orphans and
all prior verified wrappers remain. If reconstructing this derived catalogue,
stop node and every reader/proof worker, privately retain the entire directory,
and cold replay the unchanged valid event journal/latest head into a fresh one.
Do not change currency, monetary roots/keys/values or independent journal heads.

Only typed compact insertion-height or 4,096-append/shared-byte-capacity
insufficiency selects complete index material under the unchanged 1-GiB input
bound. Other errors propagate. Maximum witness/proof feasibility is unmeasured.
Actual program bindings change and old descriptors refuse; this is not an
in-place cryptographic/value upgrade. No runtime proof/payment, capacity or
independent security result is established by compilation.


## Certified Mint native inputs

The ordinary native proving lane prefers tag-6 IndexedMint input if its actual
certified predecessor event root has a retained verified correspondence. No new
operator switch, extra lane or permit is needed. The existing Mint-index lane may
produce that prerequisite asynchronously. While it is absent, native work keeps
the prior bounded complete-Mint path; settlement is not held for the index lane.
A corrupt catalogue object, invalid receipt or changed claim is an error, not an
unavailable-certificate fallback.

The input carries both root/count openings, typed event and slot access sets,
and the exact real correspondence certificate. The actual native guest and real
prover precheck authenticate every used access and reject unused supplied steps.
The complete State's Mint placeholder is empty; partial maps cannot serialize as
complete state, issue arbitrary membership, export all records or become history
storage. The real native predecessor still authenticates the monetary event root.

The existing 1-GiB counting budget includes the certificate, both metadata sets,
all other maps/material and actual trace steps. Only typed compact insertion-height
or capture-capacity insufficiency selects the prior bounded full-Mint input. A
fallback that cannot fit refuses; no height/byte limit or fee/work/cap rule changes.

Actual program/source bindings change; incompatible descriptors/private stores
remain unchanged and require their historical matching release. No monetary state,
key or balance migration occurs. Compilation does not establish successful proof
production, end-to-end payments, capacity, cost, independently protected custody
or mainnet readiness. Remaining collections and permanent archival obligations
still require work.


## Append-only acceptance and fee definitions

Normal nodes now open definition-index with RLD-DEFINITION-DISK-1 and exact
currency/home/genesis binding. Cover and fee-policy path types have distinct
RLD-COVER-PATH-1 and RLD-FEE-POLICY-PATH-1 node domains. Both start at empty
observations; complete native-validated genesis definitions seed their exact roots.
Cold replay and historical genesis fallback repeat that reconstruction. No root
from a directory, peer or serialized cache grants native authority.

These two paths share a 4,096-object /16-MiB raw cache and 1-TiB /4,194,304-file
admission. Status reports definition_storage with actual accounted usage or an
explicit observation error. Original small path value types and fee policies
retain 8-KiB per-value admission. Covers use the existing 1-GiB complete input
ceiling; the 512-MiB encoded reachable working-tree limit remains and may refuse
sooner. Large records bypass the smaller retained cache and can need substantial
temporary memory. No new wire, capsule, working, total disk or cache limit is raised.

History V8 stores fifteen-map observation V6 (still at most 4 KiB); material V9 omits
all fifteen map arrays. Incompatible old derived formats refuse without rewriting.
For compatible derived reconstruction stop all node/read/proof workers and
privately retain definition-index, mint-index, utxo-index, permanent-index,
applied-index, history-index and state-index together before replaying the exact
valid anchored journal into fresh derived directories. Preserve mint-proof-index
and receipt-index under their existing recovery rules. Do not change the currency,
program binding, money, keys or separately retained latest head.

Default native input tag 7 captures covers/fee policies alongside UTXO/applied/
permanent paths; it can use either certified Mint accesses or complete Mint
material. This mode needs no extra permission, lane or setting. Actual guest and
prover precheck authenticate both initial root/count openings and all touched
records and append absences under the real monetary predecessor. All supplied
steps must be used. These maps expose no replacement/removal API. Auth/read errors
propagate; only typed compact-height/capture-capacity refusals select prior
bounded material paths. The shared 1-GiB input limit remains.

Mining work fetches only covers required by its bounded selected grants. Wallet
payment/claim construction and balance display use checked cover lookup; a missing
definition is an error, not permission to spend. Native acceptance cover, historical
fee authorization and positive owner-authorized miner fee rules remain unchanged.
A compile pass does not establish maximum-input proof feasibility, payment
composition, capacity, independently protected custody or mainnet completion.


## Mutable service/coupon and permanent family state

Normal nodes now open service-index with RLD-SERVICE-STATE-DISK-1 and exact
currency/home/genesis binding. Services, coupon uses and receiving families use
distinct RLD-SERVICE-PATH-1, RLD-COUPON-USE-PATH-1 and RLD-FAMILY-PATH-1 typed
paths. They begin empty at authenticated genesis and reconstruct through ordinary
native/QC replay. No serialized root is adopted. Status service_storage reports
the shared Objects accounting (4,096 objects /16 MiB raw cache; 1 TiB /4,194,304
retained files). Each path keeps 8-KiB values, 600,000 reachable working objects,
512-MiB encoded working bytes and the 64-branch bound. These limits are not a
measured total resident-memory or daily-volume result.

The separate mutable API permits insertion and same-key replacement, never
removal. Replacements authenticate prior membership and keep exact count/topology;
ordinary native owner, renewal payer, custodian, conservation, fee, coupon and
terminal rules still decide whether any update is legal. Family/decision maps
remain append-only. CLI closure and funding evidence use exact keyed records and
retain their existing real receipt/checkpoint requirements.

History V8 binds fifteen-map observation V6; material V9 omits those arrays. The
observation stores sixteen complete root descriptors, including both Mint roots,
with one checked currency/home/genesis context and fixed role inventory. It fully
reconstructs the original typed snapshots before normal historical validation.
There are no external dictionary/peer-cache references or dropped fields; the
encoded observation still refuses above 4 KiB. Old format observations refuse.

Keep service-index together with every other derived native owner during a
stopped compatible reconstruction. The unchanged valid journal and separately
retained head remain authoritative, with full native replay and historical state
root checks. New program bindings do not upgrade incompatible old currency/stores
or migrate money/keys; retain their exact historical release and bytes.

Default NativeInput tag 8 captures all three access sets with the prior ten-map
composition (Mint can use certified access or bounded full material). It needs
no new lane/setting. All metadata/steps share the original 1-GiB input budget;
unused evidence, invalid members, changed keys, missing replacement targets,
changed claims and I/O errors refuse. Only typed compact-capacity insufficiency
selects prior bounded material paths. Actual guest/prover compilation does not
establish successful proof production, payment composition, latency/volume,
protected custody, archival succession or functional completion for mainnet.


## Controller and conflict records

Normal startup opens controller-index with RLD-CONTROLLER-STATE-DISK-1 and exact
currency/home/genesis. RLD-CONTROLLER-PATH-1 and RLD-INCIDENT-PATH-1 distinguish the
immutable typed paths. Both start empty and rebuild by complete native/QC replay,
never by adopting an on-disk head. Status controller_storage reports actual shared
Objects accounting or an unavailable observation. They retain the same 16-MiB /
4,096-object cache, 1-TiB /4,194,304-file admission and per-path reachable working
limits. Large controller/certificate records use the existing 1-GiB complete input
ceiling; working admission can refuse earlier and temporary memory is unmeasured.

Native preparation capacity now uses exact committed creation minus known-terminal
cardinality. Every authenticated cancellation/rejected-export redemption records
its matching resolution, and every resolution verifies the exact local controller.
Identical repeats retain the first record; conflicting outcomes/content refuse.
This fixes missing resolution bookkeeping on rejected recovery; returned amounts,
fees and owner/terminal proofs remain unchanged. Source descriptors/programs and
those resulting roots change; old state refuses unchanged and is never rewritten.
The API unresolved_controllers field still means absence of a locally journaled
controller-terminal QC. Its replay-derived ID index is a different observation
from native funded-capacity resolution, and neither is a signer permission.

Conflict lookups authenticate the original hashed (family,anchor) key and full
record. Complete wire export/fallback preserves tuple ordering and may materialize
that byte-bounded array. Partial maps cannot export complete records or issue
arbitrary membership. Missing/damaged records refuse, never mean no quarantine.

Default NativeInput tag 9 includes controller/conflict accesses plus the prior
composition; Mint access is certified or bounded full material. Initial root/count
openings and every supplied step verify under the real native predecessor. Only
typed compact-height/capture-capacity errors choose prior bounded material paths;
authentication, tuple mismatch, changed evidence and I/O errors propagate.
History V8 binds fifteen-map observation V6 (sixteen roots including auxiliary
Mint); material V9 omits these arrays. The observation remains at most 4 KiB.
Retain controller-index together with all other derived owners before stopped
compatible reconstruction from the unchanged valid anchored journal/head.

Full terminal records, other Core arrays, grant/segment execution, archive
succession, maximum proof feasibility, custody and runtime qualification remain
unfinished. No monetary genesis/keys, migration or mainnet is created here.
