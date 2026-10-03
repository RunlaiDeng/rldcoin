# Same-genesis upgrade contract — P0 candidate

Status: requirements derived from R7.4 §2.2. The V3 birth, scoped runtime
scheduling/activation, durable role authorization and local successor process
recovery are implemented; see the dated evidence in PLAN_STATUS.md.
**A complete E-02 pass is not yet claimed.** Earlier slice descriptions below
record their narrower implementation boundaries, not the aggregate current status.
The master plan remains the execution
route. Existing V2 manifests, signing domains, tags, schemas and vectors remain
unchanged.

## 1. Verified V2 limitation and candidate boundary

`M0NetworkBirthStateV2.allowed_consensus_profile` is immutable and validated as
`NETWORK_HEARTBEAT_ONLY_V1`. `SignedM0GenesisManifest::validate_ledger_identity`
requires the exact original birth binding and zero value. The live node rejects
non-heartbeats; startup rejects the dormant tag28 signer profile. Core/WAL has a
separate authenticated tag28 recovery capability, which is not a live upgrade
authorization. There is no legal V2 command authorizing a new active profile.

A new genesis candidate must therefore use separately versioned declaration,
birth-state and signing bytes (V3 candidate), with its upgrade constitution
committed **before** any permanent ceremony. It must keep the original birth
facts read-only and put active capabilities in a separately rooted successor
state. A V2 candidate cannot silently become V3, import its test identities, or
claim the same permanent identity. No permanent ceremony has been performed.
V2 decoding and exact-genesis replay remain supported without changing bytes.

## 2. Narrow authority

The initial constitution may authorize only reviewed zero-value migrations and
monotonic capability transitions. It fixes currency identity, `10^35 runlai`,
original Admission genesis and mapping, the M0–M5 founder ceiling, and the
separation of fees/rewards from validation eligibility. It contains no generic
script, arbitrary code loader, administrator override, balance rewrite, reserve
withdrawal, history reset or founder-seat restoration operation.

M0a → M0b does not change committee membership or `VALUE_CAP_0`. M0b activation
requires the Admission-aware node/signer/witness path, persisted authorization,
bounded proof transport and authenticated censorship recovery to be implemented
and validated together. Independent external operator evidence is required for
M1, not as a circular prerequisite for first opening the technical work lane.
Membership and M1–M5 authority changes remain their existing separately specified
commands and evidence rules. This limited contract never authorizes value.

## 3. Proposal, scheduling and activation

An upgrade intent must commit to the full network/Zone/currency-genesis/Era
context, unique U128 upgrade sequence, prior active capability commitment,
specification hash, implementation source commitment, migration identifier and
code hash, vector root, required capabilities, exact activation height, prior
finalized upgrade reference and immutable-invariant commitment. It names a
compiled deterministic migration understood by every participating role, not a
URL or executable supplied by the proposer. Platform binary hashes belong to
the corresponding reviewed build manifest; different supported platforms must
execute the same canonical migration.

Scheduling is a distinct finalized command of the currently authorized
committee. It establishes at most one pending intent, its earliest activation
height and a monotonic upgrade sequence. Scheduling neither enables commands
nor clears locks. The allowed delay, exact fields, error order, byte encoding
and fresh tag/schema allocations must be frozen with positive/negative vectors
before runtime adoption. Existing tag28 and all other allocated tags are not
upgrade envelopes.

Activation uses a distinct command and the still-current committee's exact
resolver and quorum. Every role independently verifies the finalized schedule,
context, sequence, required local implementation, exact parent and migration
result before any new signature. The command is mandatory at the scheduled
height; ordinary commands cannot advance past it. Missing software, incomplete
proof or unavailable quorum stops progress. Before activation, a process may
change installed software while retaining the same old active protocol; after
activation it cannot resume the old active state.

The signed activation proposal and finalized certificate bind both complete
pre/post roots, the intent and activation height. To avoid self-referential
hashes, the rooted active state stores the intent ID, prior active commitment,
sequence and resulting capability set; it does not include a certificate that
contains its own post-state root. The certificate is authenticated from the
main-WAL commit chain, as with other finalized transitions. Activation is the
irreversible point; installing a binary or receiving a staging receipt is not.

## 4. Single durable decision and continuity

The main consensus WAL is the only authority deciding activation. The node
computes the full successor on a clone, validates conservation and protected
state, persists the exact vote lock before releasing a vote, and fsyncs the
certified main-WAL record before publishing the new state. Signer and witness
records preserve the same context, activation intent, parent, vote locks and
finality relation; their local records cannot independently activate a protocol.
No second projection WAL may decide whether activation occurred.

Required preserved state includes all coin/pool/escrow/fee/deposit locations,
fixed supply, spent/request/transit Nullifiers, pending service obligations,
reserve reservations, tickets and deferred claims, Admission head/accumulators/
targets/retained proofs, censorship state, committee and responsibility
history, algorithm/owner commitments, finalized commit inventory, and all
existing vote locks and external rollback anchors. Root-excluded bookkeeping
must be compared explicitly; equal state roots alone are insufficient.

Recovery authenticates the original genesis and WAL envelope chain, resolves
dependencies read-only against the commit prefix available at each record,
replays the activation deterministically, reconstructs derived projections,
and advances external monotonic state last. A torn tail does not imply that a
previous signature may be forgotten. Missing proof, rollback, divergent roots
or unknown implementation stops recovery without rewriting the old database.
The first subsequent signature must extend the recovered lock/finalized head.

All heights/sequences in new upgrade objects are U128 with decimal-string JSON;
existing U64 persisted paths need an explicit checked migration and cannot be
silently truncated. A metadata-only height conversion does not satisfy this
contract.

## 5. Required E-02 evidence before the permanent ceremony

- Original-genesis replay reaches identical pre/post state and complete
  bookkeeping; retained supply, Admission genesis, tickets/claims and unpaid
  obligations match across activation.
- Unauthorized, wrong-context, stale, duplicated, reordered, unknown-migration,
  insufficient-quorum and invariant-changing schedules/activations fail before
  durable locks, signing or state replacement.
- A supported old active version and a new installed version agree before
  activation. An implementation unable to execute activation halts at the exact
  boundary. Partition/rejoin and proposer failure cannot produce two legal
  finalized successors or bypass the existing quorum.
- Inject failure before/after each node, signer and witness append/fsync/rename/
  anchor boundary; recover and attempt the first next signature. An already
  released signature remains locked, projections cannot decide activation,
  and retries are exact and idempotent. Logical injection is recorded separately
  from real hardware power loss.
- Complete source/build/spec/vector/command/output artifacts bind each result.
  Independent review, actual operators and production devices remain external
  evidence, never inferred from a local model or multiple processes.

Until the entire path passes, V2 M0a stays heartbeat-only, V3 remains an
unreleased candidate, permanent genesis is blocked, and `VALUE_CAP_0` persists.

## 6. V3 birth slice: exact candidate bytes and current boundary

`rld-genesis create --candidate-v3` creates a fresh candidate. The existing
`create` default still emits V2. `RLD_M0_GENESIS_CANDIDATE_VERSION=3` selects V3
only during fresh bundle initialization; startup and restore derive the version
from the independently pinned manifest, not from that environment variable.
Neither version can replace the other inside a retained WAL history.

The V3 declaration is a separate strict JSON structure with exactly
`format_version`, `network_phase`, `descriptor`, `genesis_state_root`,
`founder_public_key`, `control_group_id`, `admission_genesis` and
`upgrade_constitution`. The outer signed object has exactly `declaration`,
`manifest_sha256` and `founder_signature`. There is no optional field appended
to the frozen V2 declaration. The old declaration, signature and root formulas
remain unchanged.

In the following candidate byte grammar, `text(s) = u64be(len(UTF8(s))) || UTF8(s)`;
`strings(v) = u64be(count(v)) || text(v[0]) || ...`; fixed integers are unsigned
big-endian, and `D(name)` is the exact ASCII name followed by one zero byte.
Lists retain the validated descriptor's existing order. No JSON is hashed for
the new birth, constitution, active-state or manifest-signature bytes.

- Constitution bytes: `D(RLD-M0-UPGRADE-CONSTITUTION-BYTES-V1) ||
  u128be(10^35) || u128be(10^24) || u8(0) ||
  u16be(1000) || u16be(1000) || u16be(750) || u16be(500) || u16be(250) || u16be(0) ||
  u16be(2) || 01 01 00 00 01`.
  The six ceilings correspond to M0..M5; the two-Epoch minimum notice uses the
  already signed height/Epoch mapping when the scheduler is implemented. The
  final five flags require current-committee finality, preserve obligations,
  forbid genesis replacement, forbid founder-weight restoration, and require
  M5 plus the safety case for separate value-policy activation. The `0` cap
  limits bootstrap upgrades, not the later separately authorized value policy.
  Every JSON field must equal this fixed policy; changing a flag/ceiling/amount
  fails rather than selecting a different policy under the same version.
- Birth bytes: `D(RLD-M0-NETWORK-BIRTH-BYTES-V3) ||
  text(RLD-M0-NETWORK-BIRTH-STATE-V3) || text(founder_public_key) ||
  text(control_group_id) || text(NETWORK_HEARTBEAT_ONLY_V1) ||
  admission_genesis_bytes || constitution_bytes`. `admission_genesis_bytes`
  preserves the already specified context, four U256 parameters, three U128
  mapping parameters, raw report digest and raw Admission genesis header; its
  encoding is the existing `append_admission_genesis` grammar.
- Initial active bytes: `D(RLD-M0-ACTIVE-PROTOCOL-BYTES-V1) ||
  SHA256(constitution_bytes)[32] || u128be(0) ||
  text(NETWORK_HEARTBEAT_ONLY_V1) || u16be(1000) || u8(0)`.
  The final zero denotes no activated-upgrade reference. Its `upgrade_sequence`
  JSON is the canonical decimal string `"0"`. Numeric JSON, leading zeros,
  signs and overflow are rejected. Unknown profile, nonzero sequence, changed
  ceiling or an activation reference currently stops validation because there
  is no activation evaluator yet.
- Descriptor V3 signing bytes have the existing explicit descriptor field
  order: zone ID, display name, genesis root, U16 identity version, hash suite,
  network domain, U128 supply, genesis validator and notary string lists,
  currency genesis root, current validator and notary string lists, **U128**
  protocol Era, **U128** crypto Era and U8 testnet flag. Text and list framing
  follows the definitions above. This does not migrate the existing U64 Ledger,
  WAL, descriptor JSON or signer fields; that explicit migration is still open.
- Manifest signing bytes: `D(RLD-M0-GENESIS-MANIFEST-SIGNATURE-V3) ||
  text(RLD-M0-GENESIS-MANIFEST-V3) || text(M0_NETWORK_BIRTH) ||
  descriptor_v3_bytes || text(genesis_state_root) || birth_bytes`.
  `manifest_sha256 = SHA256(signing_bytes)` and the founder signs the exact
  signing bytes with strict Ed25519. Verification also reconstructs the whole
  exact initial Ledger and compares descriptor and genesis root.

The new pre-Admission state root uses the existing length-framed `hash_parts`:
`hash_parts(ASCII(RLD-LEDGER-STATE-ROOT-M0-NETWORK-BIRTH-EXTENSION-V3),
ASCII(existing_stake_root_hex), birth_bytes, initial_active_bytes)`. The domain
argument here has no added zero; each argument receives its u64 length frame.
The existing Admission state extension is then applied unchanged. The pre-
Admission root initializes its censorship-protected asset root, avoiding a
self-reference. New optional persisted fields are omitted entirely in V2 JSON;
V3 requires both `m0_network_birth_v3` and `m0_active_protocol`, and forbids a
simultaneous V2 birth. Audit bundles validate the same pair.

`tools/m0-genesis-v3/verify_manifest.py` independently reconstructs the signing,
birth and constitution bytes and Admission genesis, using the existing Python
standard-library strict Ed25519 implementation. It explicitly does **not**
replay the complete Ledger root or count as an independent full client.

This slice provides a separately rooted constitution at birth and preserves
the heartbeat/WAL/Admission initialization chain. It does not yet implement
scheduling, activation, a U64→U128 durable migration, signer/witness active-state
successors or M0b. No permanent-genesis qualification follows from its tests.

The V3 bundle retains the existing signer configuration and witness policy
schemas. Section 8 adds a separately versioned signer state and pinned certified
heartbeat delivery. Section 9 adds witness semantic state. Both roles'
upgrade-active successors remain unimplemented. Neither role acquires upgrade authority by
observing node status. Reinterpreting the old profile string or editing a
configuration file cannot enable an upgrade.

## 7. Role-local semantic replay dependency

`rld_core::m0_candidate_replay::M0CandidateReplay` now constructs its private
Ledger and Admission history only from an exact signed V2/V3 genesis and a
separately supplied manifest pin. It has no Ledger/snapshot deserializer,
caller-supplied availability/finality boolean or resolver callback. Certified
commits must extend the actual replayed prestate, satisfy the current fixed
committee's exact signature/quorum rules, execute to the signed complete root,
and preserve the protected unrooted commit bookkeeping. Only then can their
commit IDs become anchors for later Admission sources.

The candidate tag28 verifier checks source headers, work, signatures, exact
sidecar bytes, ancestor duplicates, retained confirmation bodies, finalized
anchors, bounded control/checkpoint prestate and the complete resulting Ledger
root. A separately recovered node WAL and the keyless replay agree byte-for-byte
on the full final Ledger for both V2 and V3 in the crash-after-main-WAL-fsync
fixture. All rejection paths stage changes before replacing verified state.
The semantic result has private fields and no deserializer or signing method.

`rld-genesis verify-candidate-history` exposes the keyless checker for local
diagnostics. Its bounded canonical transcript is a new **local interchange**,
not a consensus schema or portable authoritative snapshot. The command requires
both the genesis pin and expected final height/root, rejects torn/noncanonical
frames and missing dependencies, and writes no role state. Raw numeric U128
fields are decoded directly and are covered by a maximum-U128 roundtrip test;
the underlying legacy Ledger/WAL still needs its explicit U128 migration.

This is execution of the same implementation in another process, not an
independent full client. Candidate replay can inspect an already certified
dormant tag28 history, but it cannot legalize that history under the current
live heartbeat-only profile. Section 8 connects the narrower heartbeat path to
one signing role; tag28 still requires both roles' complete retained Admission
history, semantic authorization, censorship recovery and valid activation.
The CLI reports `live_authorization:false` and
`durable_role_state_verified:false`. See the public
[raw transcript fixture](../../vectors/m0-semantic-replay-v1/README.md).

## 8. V3 birth-bound signer state and heartbeat delivery

`check_unsigned_proposal` validates context, deterministic round-zero authority,
parent state, command bytes and the independently executed complete successor
before any proposer signature. It rejects a nonempty signature, false root or
height, changed command commitment and unavailable tag28 dependencies without
changing replay state. Inspecting tag28 here grants no live authorization.

The explicit signer `--m0-genesis-manifest` / `--m0-manifest-sha256` mode creates
`RLD-ISOLATED-SIGNER-STATE-V4`. Its `RLD-M0-SIGNER-SEMANTIC-STATE-V1` field retains
the original verified V3 declaration bytes, pin, canonical certified-heartbeat
JSON and derived final height/root. The complete history is sealed in the same
signed monotonic anchor transaction as proposal locks, witness-request locks,
released votes and signed heads. Existing V3 signer state has no such field;
its serialization is preserved and it is not silently converted. Removing or
changing the birth pin fails before ordinary-state repair, even when that state
file is missing. This explicit fresh-state mode is not a general lock migration.

Only `/v1/m0/certified-heartbeat` accepts history, as bounded exact typed JSON.
Every new commit requires the current 3-of-4 QC, verified ancestry, execution
and post-root, and consistency with all released-signature locks. A repeated
identical certificate does not advance the anchor. The full retained history
is replayed on restart and before new authorization. Head signatures require
the replayed height/root and exact validator-set commitment/quorum. An exact
previously released signature may be returned from its durable lock; a new
signature cannot use an unreplayed parent. Tag28, value and upgrade history
are rejected. No caller snapshot or claimed semantic result is accepted.

The V3 node verifies the signer's separate birth status at startup. Before a
proposal, vote lock or signed-head request it delivers missing locally finalized
heartbeats in order, then requires the exact derived final height/root. Missing
certificates, pin substitution, a conflicting root and a signer ahead of local
recovery stop new signing. This is private local HTTP delivery authenticated by
the embedded consensus certificates, not proof of remote transport security.
The V3 lifecycle supplies both flags automatically and its verifier checks all
four signer semantic heads. V2 lifecycle behavior is preserved.

Local logical crash tests cover failure after anchor persistence but before
ordinary-state persistence: the running signer refuses further authorization,
restart recovers the certified head and every old lock, and its first new
witness-request signature uses the recovered successor. Ordinary-state deletion
is repairable only with the same verified birth pin. This does not simulate
rollback of both files, hardware power loss or independent rollback domains.

Candidate ceilings are 4096 certified heartbeats, 32 MiB aggregate canonical
heartbeat JSON and the existing 512 KiB HTTP body bound. Capacity exhaustion
stops signing; it never prunes history. Replay on each new request is deliberately
conservative and is not production throughput/memory qualification. Other
legacy lock/state limits, U64 counters, authenticated transport, hardware signing,
full Admission semantics, finite schedule/activation and migration remain open.
The same Rust code in separate processes is not an independent full client.


## 9. V3 birth-bound witness authorization and certified delivery

`RLD-M0-WITNESS-VOTE-ENVELOPE-V1` is a separately typed, canonical **local HTTP
wrapper** containing the complete signed proposal and unchanged signed
`VoteWitnessRequest`. The request's proposal/command commitments, context,
proposer, parent and successor must exactly bind the supplied proposal. A bound
witness independently executes that proposal against its own genesis-derived
certified history before releasing a receipt. Only heartbeat tag36 is allowed;
old `/v1/votes/authorize` requests cannot bypass the complete-proposal requirement.
The wrapper does not allocate a consensus tag, alter an existing signature
domain, authorize tag28 or change the current committee/profile.

`RLD-M0-WITNESS-STATE-V1` retains raw verified V3 manifest bytes/pin, policy and
operator identity, and a canonical sequence of certified heartbeats, accepted
checkpoint requests/receipts and complete vote proposals/receipts. Replay
verifies every QC and complete Ledger transition, every publisher/previous
checkpoint quorum and operator receipt, every vote's exact prestate, signatures
and monotonicity. Certificates conflicting with previously released vote locks
are rejected. A checkpoint must match the independently replayed height/root
and eras. Its node-WAL sequence/hash remains a publisher-certified attestation;
this slice does not independently reconstruct that subject's complete WAL.

`RLD-M0-WITNESS-ANCHOR-V1` signs that entire event history with distinct state,
anchor and signature domains. The protected anchor is persisted before the
ordinary state, and a receipt is returned only after both writes complete.
A persistence error poisons the running instance. Restart verifies the exact
birth/policy/operator and complete event history before repairing missing or
older ordinary state from the protected anchor; ahead/conflicting state fails.
Every old vote/checkpoint receipt remains available in the retained history.
No plain legacy store is automatically converted and a missing birth pin cannot
open the default anchor in legacy mode. Existing V1 store/receipt bytes remain
unchanged. An exact latest receipt/certificate retry has no new durable effect.

The new `/v1/m0/semantic-status`, `/v1/m0/certified-heartbeat` and
`/v1/m0/votes/authorize` endpoints retain the 64 KiB HTTP bound. Local retained
events are bounded to 128 KiB each, 16384 events and 64 MiB aggregate event bytes;
the complete store has a 128 MiB read/write ceiling. Core replay still limits
certified heartbeats to 4096 / 32 MiB. Exhaustion stops authorization; there is
no automatic pruning, state reset or history truncation. Full replay on new
operations is deliberately conservative and remains unqualified for production
throughput, memory and sustained-load requirements.

V3 nodes require a quorum of distinct configured witness control domains with
matching birth/policy/authority at startup. Before a node vote lock, they deliver
missing locally finalized heartbeats and require that quorum to reach the exact
local root. Vote delivery then uses the complete proposal wrapper and the
unchanged independent receipt-signature quorum. Missing proposals, weak QCs,
wrong pins and duplicate endpoint identities fail. A fourth unavailable witness
cannot prevent an otherwise valid three-of-four quorum in the local HTTP test.

The node's peer-only `POST /v1/witness/semantic-sync` delivers its own already
finalized history; it accepts no caller-supplied state, changes no node Ledger
or WAL and grants no new command authority. It is explicitly listed in the
security route inventory. V3 lifecycle checkpoint publication calls it before
asking for checkpoint receipts. The V3 observer has a loopback peer listener
for this purpose; it still has no validator signing key. All fifteen witness
semantic heads are checked against the exact final node root. V2 lifecycle
behavior is preserved. Before any publisher signature, V3 lifecycle brackets
history delivery with two node status reads and requires equal descriptor and
durable persistence state. A changed head or vote-lock WAL point causes a fresh
delivery (ten attempts maximum); continued churn fails before publication. This
fixes the observed fault-recovery race where node catch-up advanced immediately
after witness delivery. It does not weaken the exact witness root check or make
concurrent checkpoint publishers atomic; an independently advancing witness may
still refuse a stale checkpoint. No partially published request is regenerated
by this retry loop.

Local fault tests cover a crash after anchor persistence with no receipt
returned, restart recovery of the previous checkpoint and new vote lock, exact
retry, certified progress, the first new post-recovery vote and repair of a
stale ordinary state. The real node HTTP test verifies full-proposal quorum,
wrong/duplicate identities, weak certificates and exact final-head delivery.
These tests do not simulate rollback of both protected copies, physical power
loss or independent operators. The lifecycle's anchors are local files until
real protected failure domains and hardware are qualified. Admission semantics,
authenticated censorship recovery, active-state migration and finite same-genesis
schedule/activation remain prerequisites; this is not M0b or a permanent birth.

## 10. Dormant role-local Admission input replay

V3 signers and witnesses can now retain independently verified Admission inputs
without enabling a new consensus command. A new local source frame is
`M0ASRC01 || u32be(manifest_length) || manifest || sidecar_frames`. The manifest
is exact compact typed JSON, in field order: `format_version` (the literal
`RLD-M0-ADMISSION-SOURCE-V1`), `entries`, `access_work`, `header`, `ledger_anchor`.
Entries have unique ascending entry IDs. Each sidecar is `u64be(length) || raw
payload`, in matching entry order. Unknown, duplicate, reordered/noncanonical
JSON, lengths differing from signed declarations, missing and trailing bytes
are refused. Raw JSON deserialization preserves U128 source fields. This local
format changes no existing Admission/consensus bytes, schema or tag.

Bounds preserve the existing 256-entry, 8 MiB per-sidecar and 64 MiB aggregate
limits. The local JSON manifest ceiling is 2 MiB and the complete frame ceiling
is 69,208,076 bytes. Framing is not semantic validity: each receiving role also
verifies entry signatures, exact sidecars, work, header ancestry and a ledger
anchor derived only from its own already replayed certified commit history.
The caller cannot provide a Ledger, trusted-finality flag or resolver callback.

Each role writes content-addressed public frames under
`<ordinary-state-path>.admission-sources/<sha256>.frame`. The object is fsynced,
linked without replacing an existing object, and its directory is fsynced
before the role appends its existing signed monotonic anchor. That anchor seals
`RLD-M0-ADMISSION-SOURCE-REFERENCE-V1`: exact header ID, raw-frame hash/length and
observed finalized height. The reference contains no filesystem path supplied
by a requester. Unreferenced files after interruption cannot advance replay.
Retries must re-synchronize the archive's parent and any existing matching
object plus its directory; existence after a failed fsync is not durability.
Injected parent/publication fsync failures remain errors on retry until the
pending synchronization succeeds. Bare relative state filenames resolve their
parent to the current directory for signer, witness and archive persistence.
Archive reads reject nonregular files, symlink roots, content changes, unknown
references and missing dependencies before ordinary-state repair or further
authorization. Exact source retries do not advance the anchor. Capacity is
256 MiB / 8192 archive files, including interrupted/unreferenced files; core
replay still caps 4096 headers, 8192 entries and 64 MiB unique sidecars. There is
no automatic GC, authorized pruning or retention reset. Archive copies belong
in recovery backups together with their role anchor and original genesis pin.

The first successful new source append explicitly changes local signer state
from V4 to V5 (`RLD-M0-SIGNER-SEMANTIC-STATE-V2`) and witness event state from V1
to V2. Before that append, their old bytes and empty-source interpretation are
preserved. All old signature/checkpoint/vote locks remain inside the same signed
anchor. Signer source references are replayed at their recorded position among
certified heartbeats; witness source references are chronological events among
all prior receipts and certificates. Old executables refuse these new local
state versions. This is a local evidence-format transition initiated by source
import, not a consensus upgrade, legacy unbound-state conversion or authority
to execute tag28. Local observed-height references still mirror the existing
U64 Ledger; the required durable U128 migration is not supplied by this change.

Actual role services expose local-connection-only
`POST /v1/m0/admission-sources` (raw source frame) and
`POST /v1/m0/candidate-proposal/inspect` (complete signed canonical proposal).
The latter independently computes the full candidate successor using retained
sources; its result explicitly has `signature_authorized:false`. It creates
no signature, vote lock, checkpoint receipt or upgrade authority. Live proposal
and witness-vote endpoints continue to reject tag28. The inspection proposal
ceiling is 4 MiB. A maximum valid 1 MiB wire proof still needs its actual JSON
size and complete staged/live semantic path demonstrated; this local ceiling
is not evidence that every maximum proof has passed. The existing 48 KiB chunk
staging is not reinterpreted here.

The two local routes share one evidence worker, a 10-second body deadline and
256 requests / 128 MiB per-minute ingress budget. Exact Content-Length and
content type are checked before reading bodies; compression, transfer encoding,
oversized framing and non-loopback connections fail early. These are bounded
local candidate routes, not authenticated remote transport or qualified
production memory/throughput isolation. Full replay on new operations remains
unqualified for sustained load.

The node's peer-only `POST /v1/m0/role-admission-sync` accepts only bounded
inventory pagination (`after_sequence`, `limit` 1..8). It delivers its own
already retained headers and raw sidecars after synchronizing certified history
to its signer and a distinct-domain witness quorum. Each receiver verifies and
retains its own inputs. Skipping a required predecessor fails; a supplied cursor
is never a proof. A partial delivery can retain valid inputs at some roles;
exact retry resumes without changing the node's Ledger or either node WAL.
This endpoint grants no command authority and appears in the 50-route security
inventory. Source acknowledgements report configured role identities over local
HTTP; they are not signed quorum certificates. The existing signed vote/receipt
quorum remains required for any consensus authorization. Authenticated censorship
stall/recovery, target/rollover transitions
in role replay, maximum staged proof authorization, finite schedule/activation,
U128 migration and independent external evidence remain required before M0b.

## 11. Censorship recovery state prerequisites

The existing `AdmissionCensorshipGuardV1` is a state-transition primitive, not an
authenticated recovery interface. Its supplied prepared checkpoints, Epochs,
asset roots and `AdmissionLedgerResolutionV1` entry/proof-ID summaries must not
be treated as independently verified facts. The live heartbeat profile still
does not invoke its stop-signing query. That boundary remains closed until
complete observations, inclusion/rejection transitions and a certified path
that can progress while stalled are implemented across all roles.

Before that integration, the primitive now validates its previous state, applies
each operation to a clone and validates the complete result before replacing
the original. A rejected observation, resolution or clock update leaves no
partial pending entry, scope, event or protected-root change. Re-observing the
identical checkpoint cannot reinsert entries already resolved from that
checkpoint. This does not authorize an old or competing checkpoint.

Recovery resolved within Epoch `e` must retain the whole following Epoch `e+1`
as its challenge interval. Since V1 records only the resolution Epoch and not
its block position, clearance is permitted at `e+2` or later, provided no new
overdue work requires a reopened stall. The implementation uses checked
subtraction (`current_epoch - e >= 2`), so the U128 boundary cannot shorten the
interval or wrap into a healthy state. This is a correction of the dormant
candidate's premature next-Epoch clearance, not a migration of a live protocol.

Recovery validation applies the same minimum interval to event history. Even
rehashed events cannot claim premature clearance, a nonempty unresolved scope
at recovery/clearance, or a changed protected root within a stall/recovery
cycle. Pending obligations require a nonzero confirmed position and nonzero
entry IDs. These structural checks do not authenticate a rewritten history;
the original genesis, consensus certificates and protected role anchors remain
necessary. Old states that violate these invariants are refused, not repaired
by silently changing their history.

The new regressions cover actual failures of this primitive and logical Epoch
arithmetic. They do not demonstrate authenticated tag29/30/31 processing, an
complete censorship-policy integration, a late-checkpoint recovery exception, target/rollover
replay, all-role first signatures after recovery, or a safe live activation.
The ordinary tag28 two-Epoch lag bound and all frozen bytes/tags remain unchanged.
The complete certified recovery path must resolve those dependencies before
any new signing-stop rule is enabled.


### 11.1 Verified retained-prefix observation prerequisite

`M0CandidateReplay::observe_admission` now derives a read-only observation
from its private pinned genesis, full-QC Ledger history and Admission log.
The log's shared prefix selector preserves whole-header ordering, the 512-entry
limit, 32 successors and confirmation-work requirements. A short valid history
has no new confirmed prefix. Structural selection no longer needs a fabricated
future committing height to expose an overdue prefix; the ordinary checkpoint
builder still enforces the original two-Epoch lag bound.

Before returning a prefix, the verifier checks its source anchors against its
own certified commits and checks retained raw sidecars for both the selected
batch and its confirming suffix. A cached availability bit is insufficient.
The finalized height must have its own replayed commit, apart from pinned
height-zero birth. Epochs come only from the signed genesis mapping. The report
separates current finalized lag from eligibility at the next block boundary.

The in-process `VerifiedAdmissionObservation` has a private constructor and no
Deserialize implementation. Its serialized display projection is deliberately
not a capability: neither a client-supplied JSON report nor the unsigned HTTP
response authenticates a remote role or forms a quorum certificate. Role
engines reconstruct from their existing signed anchors and source archives on
each request, without a new state format or durable observation cache. Their
local `POST /v1/m0/admission-observation` accepts exactly `{}` under the shared
input gate; the maximum serialized response is 64 KiB. All three source/inspection/observation handlers now use the shared
`run_with_evidence_permit` runner. The worker permit stays owned by verification
even if the HTTP caller disconnects. The old source/inspection pattern held the
permit in the request future, allowing cancellation to admit another worker
while the first blocking job was still alive. A synchronized cancellation
regression fails with that old ownership pattern and checks HTTP-429 admission
until the real worker completes.

This supplies locally verified prefix/clock facts for the next recovery step.
It does not prove contribution eligibility, absence of a valid rejection, or
that a live activated committee censored the entries. The aged synthetic test
entry expires at height 100; observing its original confirmed bytes at 192
makes no claim that the entry is currently eligible. Ordinary heartbeat signing
continues under the existing M0a policy; `live_censorship_policy_active:false`
is not a recovery clearance. Finality-bound per-entry inclusion/rejection,
certified progress while stalled, a full challenge interval, persistent
all-role recovery, finite activation and U128 migration remain required.

### 11.2 Finalized checkpoint membership prerequisite

The keyless candidate verifier now records per-entry membership only after a
complete tag28 command has executed against its exact prestate, its post-root
matches, and the full current 3-of-4 certificate has passed. Proposal inspection,
source arrival, confirmation-header presence and an unsigned prepared checkpoint
do not create membership. The derived index is private, not deserializable or
persisted, limited by the existing 8192-entry replay ceiling, and published in
memory atomically with the accepted Ledger/log/anchor successor. Entries in one
checkpoint share its immutable checkpoint metadata rather than copying the
complete certificate for each entry; full certificates remain in the existing
bounded certified history.

`verified_admission_inclusion(entry_id)` returns a private, non-deserializable
capability borrowing that verifier's history. It exposes the exact entry,
checkpoint and complete certifying commit. Looking up membership also requires
the retained source, raw sidecar, source anchor and certificate. Missing data
fails rather than returning a cached successful proof. Later checkpoints and
heartbeats preserve the original certifying height and commit; restart rebuilds
the index from the original genesis and certified transcript. The node regression
also rebuilds it from actual recovered WAL certificates and disk sidecars after
an injected failure following WAL fsync, without importing the pre-crash index.

The CLI can require up to 64 unique nonzero entry IDs with repeated
`--require-admission-entry` options. These requirements are checked only after
the full transcript reaches the independently expected height/root, and before
any PASS is printed. A source that is present and confirmed but not consumed by
a finalized checkpoint still fails the requirement. An entry in a confirmation
header only becomes included when a subsequent checkpoint consumes its header.

Its JSON projection contains the entry/source header, checkpoint roots and ID,
and certifying commit/height/Epoch/root. The JSON is unsigned; it is not a
standalone portable finality proof and must not replace verification of the
pinned-genesis transcript. `contribution_accepted:false` and
`recovery_authorized:false` explicitly exclude conclusions about contribution
validity, reward/claim issuance, rejection, or clearance of a censorship stall.
This candidate-semantic fact also does not override the live M0a tag28 guard.
The live policy adapter, rejection commands, persistent observation tracking
across checkpoints/reorgs, certified late recovery and activation are
still required before the guard can consume these facts safely. Existing V1
checkpoint roots and guard state are not silently rewritten.

### 11.3 Authenticated observation-to-inclusion reconciliation

`VerifiedAdmissionObservation` now also retains private typed source references,
the observed certified height and the selected entry-to-header mapping. Its
existing unsigned JSON is unchanged and cannot reconstruct that capability.
`M0CandidateReplay::reconcile_admission_observation` requires the originating
genesis pin and exact observed height/commit/root to be in its own certified
history. It rechecks all original source and confirmation dependencies, even
when their branch is no longer canonical, and verifies current source data
before classifying each originally observed entry. A future/competing certified
head, missing certificate or missing sidecar fails the whole read-only query.

The local correlation ID is SHA-256 of the literal bytes
`RLD-LOCAL-ADMISSION-OBLIGATION-V1` followed by a NUL, the 32-byte signed genesis
declaration pin and the 32-byte entry ID. It excludes changing confirmation
counts, observation heights, checkpoint IDs and containing headers. The same
signed entry in overlapping observations or a replacement branch has one local
identity. This is not a new protocol nullifier, consensus schema or ticket.

Each entry has one of three display outcomes: `FINALIZED_CHECKPOINT` with its
original independently replayed inclusion certificate, `UNRESOLVED_CANONICAL`,
or `UNRESOLVED_REORGED`. The last outcome is explicitly unresolved: losing
canonical membership does not prove rejection, forgive an omission or clear a
stall. Reappearance under another header preserves the identity; inclusion is
accepted only after that branch's own full certified checkpoint is executed.
The report separately indicates membership in the next selected confirmed
batch. A confirmation-header entry never becomes finalized by association.

The returned capability borrows both the original observation and the current
verifier. Empty scopes fail; a complete-inclusion result requires every original
entry's finality evidence. All-or-nothing validation leaves both histories
unchanged. Source references retain the existing 4096-header ceiling and the
selected entry set retains the 512-entry ceiling; no new persistent cache is
created. The CLI can capture one observation after a selected transcript record
and reconcile it at the independently expected final head, optionally requiring
complete inclusion before printing PASS. It accepts no observation JSON.

This connects authenticated local observations to finalized membership, but
does not supply the live censorship-policy adapter or its durable first-seen
clock. The correlation ID by itself cannot establish when any remote operator
first received an entry. Persistent observation ordering, authenticated objective
rejections, certified progress through stall and challenge, and all-role policy
activation remain necessary. The V1 guard's changing checkpoint identifier is
not overwritten with this local ID, and no V1 asset or checkpoint root changes.


### 11.4 Node-local Admission receipt ordering and reader floor

Live node ingress and peer pull append a separately verified local receipt with
each new source header. The private `AuthenticatedAdmissionReceipt` capability
can only be captured from `PersistentStore` after exact-genesis full-WAL replay,
a nonzero fully certified head, and an exact height/root match with the executed
Ledger. The main-store mutex remains held until the Admission append completes.
The append callback rechecks the current head, rejecting a stale capability;
recovery instead verifies each historical receipt against the authenticated
commit index before any repair and again after complete semantic Ledger replay.
Canonical nonzero height, commit hash and state root are mandatory. Receipt
heights cannot predate their source anchor or any earlier locally verified
Ledger reference, including an untimed legacy source anchor, target schedule,
activation or rollover reference. The recovery floor is derived from verified
WAL operations, not an additional trusted metadata field.

`AppendObservedHeader` records use local Admission WAL version 3. Before the
first such record, the node atomically replaces and syncs Admission metadata at
version 3, including the directory sync. This reader floor is required because
old version-2 readers can treat an unknown unanchored operation as a torn tail:
they must reject the new metadata before reaching that repair path. Existing
version-2 WAL bytes and the `RLDADW02` framing remain unchanged. New readers
accept a version-2 prefix followed by version-3 records, but refuse unknown or
regressing checksummed versions and unknown version-3 operation/schema input.
A version-3 anchor under rolled-back version-2 metadata is rejected.

A crash after the metadata floor but before the first new WAL record is valid:
recovery preserves the old prefix and never invents receipt times. An old
version-2 rollback anchor is accepted under version-3 metadata only while the
full authenticated WAL replay establishes its actual prefix and successor.
Records synced before an interrupted anchor update retain their original
receipts. Input validation and bounded sidecar persistence precede the floor
change; write failures poison the live store. The first timed append reserves
64 KiB for metadata replacement in addition to existing WAL/anchor/sidecar
limits. Byte-accounting and receipt decoding are checked before their writes.

Exact header retries preserve the original receipt and never add one to legacy
untimed headers. The local receipt is not exported as an authoritative source
field; another node receiving that header records its own current certified
head. Tests exercise different source/destination heights, stale capabilities,
full-QC/root forgeries, reordered valid old receipts, metadata/WAL fault points,
read-only recovery and unknown-version/rollback refusal. The actual-node HTTP
harness uses the exported public fixture to check mixed-prefix recovery,
caller-field rejection, new append, retries and process restart. It starts three
actual witness processes with synthetic temporary operator/publisher keys,
delivers the certified history and publishes a three-signature checkpoint before
requiring healthy node gates. These same-host identities do not prove operator
independence. Its optional old binary check requires refusal without any durable
file mutation.

This local format migration changes neither birth identity, consensus roots,
wire tags nor the live heartbeat-only policy. It provides a validated recorded
head, not an externally protected proof of physical first receipt: rewriting or
rolling back all local disks still requires an external monotonic trust anchor.
Untimed legacy history remains explicitly unknown. Durable confirmed-prefix
obligations, authenticated rejection processing, certified progress through
stall and the entire challenge Epoch, and coordinated all-role activation are
still required. No omission timer, signing-stop hook or recovery clearance is
activated by the presence of a receipt. U128 protocol/storage migration remains
separate from the decimal-string receipt representation.

### 11.5 Reconstructing first confirmed obligations from sealed role order

The private candidate projection retains the first confirmed observation for
each genesis/entry correlation ID. Source append and checkpoint execution build
the complete successor before publishing it; dependency-budget failure leaves
both the source state and observation history unchanged. Entries first exposed
by a later checkpoint are captured at that certified head. Retries, later
confirmation growth and queries do not replace an existing first observation.

An immutable dependency scope is shared by its entries. The retained projection
is bounded to 8192 entries and a separate 16 MiB logical dependency accounting
budget; this is not a physical memory measurement. Pages hold at most 32 entries
and 64 KiB. Every original selected scope is reconciled against verified current
history, including retained off-canonical sources. Disappearance is unresolved;
only a full-QC executed checkpoint establishes final membership. An unsigned
page cannot become an authenticated input capability.

Signer and witness reconstruct this projection from existing signed anchor
histories with each raw source's `after_finalized_height`. Their ordinary state
and signed anchor formats do not change, and there is no new serialized cache.
Anchor-first interrupted writes reconstruct the same first observation after
restart. All original source and confirmation bytes remain necessary. Role
pages declare their sealed-order clock basis; generic offline replay declares
that a durable adapter is required. Neither basis proves external first receipt.

Node receipts alone do not yet provide this projection for mixed legacy history.
Untimed node headers must not be replayed at their source work anchors and then
presented as timed obligations. A deliberate legacy chronology adapter remains
required. Objective rejection, eligibility, certified progress during a stall
and its full following challenge Epoch, and coordinated activation remain open.
The live M0 heartbeat-only policy, all frozen tags, roots and value cap remain
unchanged. HTTP pages cannot authorize a vote, signing stop or recovery.

### 11.6 Node source chronology with explicit legacy uncertainty

The node's private `VerifiedNodeSourceChronology` capability reads the actual
Admission metadata, WAL and sidecars through read-only recovery, using the
current fully executed main store's Admission genesis and authenticated commit
index. It rejects a poisoned store, changed disk head/cache, stale or conflicting
main history, corrupt payloads, and unsupported runtime control transitions.
No Deserialize or public constructor promotes JSON or arbitrary Ledger values
into this capability. Main then Admission mutexes must cover its complete read.

Each source retains its WAL sequence and complete verified body. A V3 receipt
provides an exact source-receipt height. An untimed legacy source instead carries
an inclusive interval: the greatest earlier/current source anchor height is its
lower bound, and the next exact receipt (or current certified head) is its upper
bound. A later source anchor never raises an earlier source's lower bound. Even
a singleton legacy interval stays explicitly legacy; it is not a durable receipt
or the first confirmation time. Retries and restart preserve the stored facts.

This is the source-order input to the node obligation replay adapter, which is
still being implemented. It does not yet merge certified checkpoints with legacy
source prefixes or expose a node obligation endpoint. The future merge must load
only the legacy prefix required by each certified checkpoint before that commit,
keep unknown historical first-confirmation coverage explicit, and never expose
synthetic replay insertion heights as receipt evidence. Node signing, stop hooks,
rejection handling, recovery and value authorization remain unchanged.

The snapshot caps headers/entries/payload copies at the existing candidate
verifier limits (4096/8192/64 MiB), does not repair or write an observation cache,
and rechecks the current main receipt before returning. It does not authenticate
runtime target/rollover control commands that the node cannot yet execute.

### 11.7 Node checkpoint/source merge and bounded read surface

The node now consumes the verified chronology from 11.6 with its privately
retained, fully executed main-WAL commits. It creates a fresh pinned-genesis
candidate verifier and orders precise sources by their exact receipts. Before
each certified checkpoint it loads only the ordered legacy prefix needed for
that checkpoint's batch and confirmation sources. Remaining legacy sources wait
until their next known receipt or current certified head. Every insertion must
satisfy its verified interval; the candidate independently verifies every QC,
source, sidecar and transition, then reproduces the node's height/commit/root.
No arbitrary Ledger injection or alternative persisted observation cache exists.

Legacy scheduling is not historical clock evidence. Every entry ever present in
a legacy source has null first-confirmation/elapsed-lag fields in the node report,
even if an inserted prefix happened to create an observation at an exact height.
Legacy history coverage is explicitly incomplete: unrecorded historical
confirmations on vanished branches cannot be reconstructed merely from receipts
added later. Precise entries introduced after the legacy prefix retain their
verified first clock. A final checkpoint can prove membership independently of
this missing clock; reorg disappearance never establishes rejection or recovery.

The management-only loopback POST endpoint holds a process-wide evidence permit
inside its blocking worker, locks main then Admission state, and uses strict
256-byte input / 32-entry / 64-KiB output limits. Public and peer routers do not
expose it. Reading does not require an already healthy witness gate and must not
be mistaken for establishing that gate. Live M0 remains heartbeat-only and value
zero. Eligibility/rejection, full stall/challenge progress and coordinated
activation are still separate required work.

Before exporting replay commits, node inspection also re-reads main-WAL records,
anchor and checkpoint, matching their hashes/heads against the executed retained
history. Corrupt disk cannot be bypassed using cached commits. Each such durable
file has a local 64-MiB inspection ceiling; it is not a new consensus validity
rule and does not prune history.

## 12. Upgrade intent draft encoding dependency

`genesis::upgrade_intent::UpgradeIntentDraftV1` is an unreleased structural
encoding, not a consensus command, migration registry, schedule or activation.
No command tag or RLDW schema is allocated by this change. Its identifier and
byte domain explicitly contain `DRAFT`; runtime adoption requires final encoding
allocation and positive/negative vectors plus the authority checks in sections3–4.

The byte preimage starts with `RLD-UPGRADE-INTENT-DRAFT-BYTES-V1` followed by NUL.
It then contains, in order: network and Zone as U16 big-endian byte-length UTF-8
strings; currency genesis as32 bytes; protocol Era, crypto Era, sequence and
activation height as16-byte big-endian integers; prior active, specification and
source commitments as32 bytes each; migration identifier as a length-prefixed
string; migration-code hash and vector root as32 bytes each; U16 capability count
and length-prefixed capabilities; predecessor presence byte0/1 and optional32-byte
reference; immutable-invariant commitment as32 bytes. Intent ID is SHA256 of these
bytes. The object version is checked before encoding and selects this exact domain.

Every integer is serialized to JSON as a canonical decimal string. The sequence
and activation height must be nonzero; sequence1 has no predecessor and later
sequences require a nonzero predecessor. This does not prove the predecessor is
finalized or sequential: the future schedule evaluator must resolve it from the
certified current state. Required capabilities number1–32, are strictly sorted
and unique; capability/migration identifiers are1–64 ASCII alphanumeric, underscore,
hyphen or period. Context uses existing Admission domain validation and255-byte
bounds. All hash commitments must be nonzero. There are no executable bytes/URLs.

Caller-provided hashes do not prove implementation support, review or invariants.
The compiled migration registry must match exact commitments, and the certified
schedule must enforce constitution delay, current authority, context, parent,
sequence and protected state before this object can authorize any behavior.

Draft vectors now reside in `vectors/upgrade-intent-draft-v1/vectors.json`.
The separate Python preimage generator checks exact committed vector content;
Rust checks byte/hash equality for first intent, U128 successor and maximum
text/capability cases, plus16 rejection cases. This is cross-language encoding
evidence, not an independent protocol client or authorization test. The existing
CI runs the Python consistency check and includes Rust tests through workspace
tests. No remote CI success is claimed. Draft allocations remain provisional.


### 12.1 Bootstrap parent dependencies

The draft `check_bootstrap_parent` accepts a ledger obtained by authenticated
replay; it does not authenticate caller-constructed ledger data. It validates
V3 birth/active consistency, exact network/Zone/currency/Eras, next upgrade
sequence, prior active commitment and immutable birth commitment. For this
first schedule the latter is SHA256 of the original V3 birth canonical bytes;
the former is SHA256 of the active protocol canonical bytes. Non-birth successors
remain unsupported until the certified activation evaluator is implemented.

The proposed draft delay is two full contribution-Epoch spans starting from the
schedule block: earliest activation = parent height +1 + constitution minimum
Epoch count times the immutable ledger-blocks-per-contribution-Epoch. Arithmetic
uses checked U128; Epoch boundary placement cannot shorten the delay. This is a
draft rule for the future schedule command, not a change to existing commands.
It returns the earliest height without mutating the ledger. It does not check a
pending schedule, certify a parent, approve a migration, persist any object or
release a signature. Those checks still belong to finalized scheduling/activation.


### 12.2 Pinned replay inspection entry point

The raw parent check is crate-private. Public `M0CandidateReplay::inspect_upgrade_intent`
uses its privately replayed ledger and returns a non-deserializable inspection
bound to genesis pin, intent ID, parent height/root, earliest and requested
activation heights. It carries explicit false flags for signature authorization,
migration verification and finalized scheduling; it cannot be consumed as a
schedule certificate. This is candidate-history inspection, not live activation.

`rld-genesis verify-candidate-history --inspect-upgrade-intent <intent.json>`
adds this inspection after existing mandatory genesis-pin and exact expected
final-head verification. All previous history arguments remain mandatory. Intent
input is a regular file bounded to16 KiB and parsed with strict fields. Existing
transcript certificate/quorum and torn-prefix checks apply before inspection.
The actual CLI integration test covers a certified H1 parent, wrong pin/root,
truncated history, insufficient quorum, early activation and oversized intent.

## 13. Reserved schedule and activation command bytes

This is the pre-adoption byte contract, implemented in
`genesis::upgrade_wire`. It does not activate a migration or sign/finalize a
schedule. Tags37/38 and schemas1078/1079 were unused before this allocation.
Existing V2/V3 birth bytes, tag28 and draft-intent vectors stay unchanged.
Draft intent IDs are not these schedule IDs and cannot be relabeled as them.

Objects use the existing RLDW header: `RLDW || u16be(1) || u16be(schema) ||
u16be(field_count)`, followed by strictly increasing field IDs. Each field is
`u16be(id) || u8(kind) || u32be(payload_length) || payload`. Text kind01 is
nonempty NFC UTF-8 without C0/C1 controls; U128 kind05 is exactly16 big-endian
bytes; HASH32 kind06 is exactly32 bytes; BYTES kind09 carries its raw bytes.
No unknown/duplicate/reordered fields, kinds, trailing bytes or alternate
integer widths are accepted. The complete size and field count are checked
before allocating nested structures. JSON integers are canonical decimal
strings; unknown or duplicate fields are rejected.

Shared fields for both objects:

| ID | Field | Kind/bound |
|---:|---|---|
| 1 | network_domain | TEXT, exactly `rldcoin:mainnet:v1` or `rldcoin:testnet:v1`, matching the existing command envelope |
| 2 | zone_id | TEXT, at most255 bytes |
| 3 | currency_genesis | nonzero HASH32 |
| 4 | protocol_era | U128 |
| 5 | crypto_era | U128 |
| 10 | sequence | nonzero U128 |
| 11 | activation_height | nonzero U128 |

Schema1078 `ScheduleUpgradeV1` JSON version is `RLD-SCHEDULE-UPGRADE-V1`.
It adds the following fields and has exactly15 fields for sequence1 or16 for
successors, with a4096-byte whole-object ceiling:

| ID | Field | Kind/bound |
|---:|---|---|
| 12 | prior_active_commitment | nonzero HASH32 |
| 13 | specification_hash | nonzero HASH32 |
| 14 | implementation_source_commitment | nonzero HASH32 |
| 15 | migration_id | TEXT,1–64 ASCII letters/digits/underscore/hyphen/period |
| 16 | migration_code_hash | nonzero HASH32 |
| 17 | vector_root | nonzero HASH32 |
| 18 | required_capabilities | BYTES: u16be(count), then repeated u16be(length)+ASCII |
| 19 | prior_finalized_upgrade | nonzero HASH32; absent exactly for sequence1 |
| 20 | immutable_invariant_commitment | nonzero HASH32 |

Capabilities number1–32, are strictly sorted/unique and each follows the same
1–64-byte identifier rule as migration_id. Counts/lengths are checked before
allocation. JSON requires an explicit `prior_finalized_upgrade` field: null for
sequence1, otherwise the preceding activated intent ID. Its finality and exact
sequence must later be established by the authenticated main-WAL chain, not by
this structural decoder. Other parent/invariant commitments retain §12.1's
bootstrap meaning; actual scheduling must also enforce the constitution delay,
one pending schedule, finite compiled migration and current committee authority.

Schema1079 `ActivateUpgradeV1` JSON version is `RLD-ACTIVATE-UPGRADE-V1`.
It has the seven shared fields plus12 `intent_id: nonzero HASH32`, exactly8
fields and a1024-byte whole-object ceiling. It contains no replacement code or
user-supplied successor state. The future evaluator must resolve the exact
finalized pending schedule, match its context/sequence/height, apply the finite
compiled migration, and verify pre/post roots in the signed consensus proposal.
A structurally valid activation reference is never authorization by itself.

The schedule intent ID is
`SHA256(ASCII(RLD-SUBJECT-HASH-PREIMAGE-V1) || 00 || complete_schema1078_wire)`.
Activation subject hashes use the same domain and their distinct schema wire.
Command tags37/38 use the existing RLDP bytes-node payload and schema0500
CommandCommitment envelope; command hashes retain its existing subject rule.
The outer network is derived from the object, so candidate builders cannot
supply a second conflicting network argument.

`vectors/upgrade-command-v1/vectors.json` contains5 positive objects/commands
(first/successor/maximal bounded schedule and first/U128 activation) and33 binary
rejections. `tools/upgrade-command-wire/vectors.py` encodes and decodes these
without executing or importing Rust; Rust checks identical JSON, bytes, IDs and
command hashes, every truncated prefix, malformed binary cases and ambiguous
JSON. These are codec/compatibility checks, not an independent full client.
Runtime envelope decoding and ConsensusCommand JSON still reject both tags.

No activation evaluator, pending Ledger state, migration registry, committee
certificate, main-WAL transition or role-local upgrade persistence is supplied
by this codec. U128 object support does not migrate the existing U64 consensus
proposal/height/persistence paths. Those remain required before runtime adoption;
no permanent ceremony or live M0b/value gate is cleared by these vectors.

## 14. Build-embedded implementation source identity (read-only dependency)

`RLD-RUST-IMPLEMENTATION-SOURCE-V1` names a bounded source-set commitment.
The core build script captures `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
and recursively `crates`, `vectors`, `spec`, `docs/spec`. Within directories it
excludes dot-prefixed names, `target`, `node_modules`, `__pycache__`, and `.pyc`
suffixes. Included symlinks and nonregular files are rejected; names must be UTF-8
without backslashes or Unicode control characters. Relative paths use `/`, sorted
by UTF-8 lexical order. Limits: 8192 files, 4096 path bytes, 128 MiB per file,
512 MiB total, serialized build manifest strictly below 4 MiB.

The SHA-256 preimage is the format string's UTF-8 bytes, NUL, file count as
u32 big-endian, then for each file: u32 big-endian path byte length, path bytes,
u64 big-endian content length, and raw 32-byte SHA-256 of its content. Absolute
location, timestamps and permission bits are absent. The JSON inventory exposes
these paths, sizes, hashes and the aggregate commitment. Cargo watches included
files/directories; `rld-genesis implementation-source` returns the embedded
inventory. `tools/implementation-source/verify.py` independently recomputes it
against an explicitly selected expected commitment. Build from a frozen snapshot
and verify the output against that snapshot to detect source drift.

This is a named implementation-source identity, distinct from the broader P0
source-evidence snapshot hash. It excludes tools, deployment/UI files, status
logs, compiler binaries, dependencies' downloaded contents, build flags, external
configuration and environment. It is not a hermetic build or binary attestation:
a malicious executable can lie about its inventory. Signed release provenance,
reproducible builds and independent review remain separate requirements. The
core constant and this CLI do not yet bind any runtime upgrade authorization;
registry, finalized scheduling and activation must check the selected identity
before adoption. No upgrade, permanent release or value gate is opened here.

## 15. Reserved schedule inspection against authenticated candidate history

`rld-genesis verify-candidate-history --inspect-upgrade-schedule <schedule.json>`
checks the §13 schedule object only after pinned genesis reconstruction and
history replay reach the caller's exact expected final height/root. This flag
is mutually exclusive with the legacy `--inspect-upgrade-intent` draft flag.
The schedule file must be regular, at most 16 KiB, with strict typed JSON; its
canonical RLDW representation retains the 4096-byte bound. The parent checks
share the draft's V3 context, sequence, active/birth commitment and complete
constitution delay checks. IDs and hashes are derived from the new object's
bytes, never from the draft's format or preimage.

The report includes object format, reserved tag37, raw object and command
SHA-256, subject intent ID, authenticated parent height/root and earliest/requested
activation height. `signature_authorized`, `migration_verified` and
`schedule_finalized` remain false even when these checks pass. A caller-supplied
migration/spec/source/vector hash is not validated merely because it appears in
a well-formed command. Only the initial V3 active state is supported here;
successor scheduling requires the still-unimplemented activation evaluator.
This read-only report neither persists a pending schedule nor advances consensus
height. Actual finalized scheduling, registry checks and activation remain required.

## 16. Pending schedule state and ordinary-height barrier (preview dependency)

The optional `m0_pending_upgrade` field is omitted when absent in Ledger and
AuditProofBundle; existing V2 and initial V3 bytes/roots remain unchanged. Its
strict object has exactly `format_version=RLD-PENDING-UPGRADE-V1`, canonical
U128 decimal-string `scheduled_height`, nonzero `scheduled_parent_root` and the
§13 `schedule` object. Canonical bytes are
`D(RLD-PENDING-UPGRADE-BYTES-V1) || u128be(scheduled_height) ||
raw32(scheduled_parent_root) || u32be(schedule_wire_length) || schedule_wire`.
The total state root when present is the existing length-framed
`hash_parts(ASCII(RLD-LEDGER-STATE-ROOT-PENDING-UPGRADE-V1),
ASCII(previous_complete_Admission_extended_root_hex), pending_bytes)`.
The pending record is not added to the separate pre-Admission asset-root domain.

`Ledger::preview_upgrade_schedule` computes on a clone: validate the exact V3
parent and unchanged VALUE_CAP_0 policy, reject an existing pending item, bind
the current full parent root, advance height once, add the pending record and
validate the complete resulting root. All other serialized fields, including
root-excluded bookkeeping, remain byte-equivalent after normalizing those two
permitted differences. The CLI schedule inspection now exposes the proposed
schedule height/root without replacing its authenticated current Ledger.

Structural restoration requires immutable context and active/birth commitments,
first sequence/no predecessor, scheduled height no later than retained height,
full constitution delay measured from scheduled height, and retained height
strictly before activation. This is not evidence that the recorded parent hash
was finalized: certified main-WAL replay must authenticate that relationship.
The U128 objects remain unchanged, but this evaluator explicitly rejects an
activation height beyond U64 because the current Ledger has not migrated its
height storage. It never narrows by truncation.

Consensus command prechecks, counter headroom and ordinary `advance` refuse to
reach or cross the pending activation height. The tag28 proposal-plan minting
entry and shared proposal authority/prestate validation enforce this same barrier
before returning a pre-signing context, rather than relying on later execution
to fail. A valid proposal signature does not bypass the scheduled boundary. Heartbeats can advance only up to
its predecessor; serialization/restoration preserves the same barrier. There is
no activation exception yet. Runtime tags37/38 remain rejected, no migration
registry is trusted and no API persists this preview as an authorized schedule.
Node/signer/witness certified scheduling, durable locks and activation are still
required before live use. Pending-state serialization is not a main-WAL or
hardware crash-recovery test, and no E-02 or value gate is passed here.

## 17. Exact activation/current-build preflight (no migration authority)

`Ledger::inspect_upgrade_activation_for_current_build` validates the reserved
§13 activation against the structurally valid pending state: network, Zone,
currency genesis, both Eras, sequence, scheduled height and exact schedule
subject ID must match. The next checked U64 Ledger height must equal activation
height, and the scheduled implementation source commitment must equal this
build's embedded named commitment (§14). Missing pending state, early/late
activation, substitutions, value-policy changes and a different build fail.

The immutable report binds parent height/root, activation height, intent ID,
activation command SHA-256, pending-state SHA-256 and the matching source
commitment. It provides no successor Ledger and no conversion into authority.
`migration_verified`, `schedule_finality_verified` and `signature_authorized`
are false. A matching source self-report does not attest the binary; a local
pending record does not authenticate its schedule. The preflight never clears
pending state, advances height, changes active capabilities or releases a lock.
The ordinary-height barrier remains in force after a successful preflight.

This check targets a live activation attempt by the selected installed build.
It is deliberately not a historical replay compatibility resolver: future
software may replay an older activation only through a separately validated
compiled migration/compatibility registry. Reusing this exact-source comparison
as that resolver would incorrectly reject compatible successors. The registry,
complete successor-state migration, committee finality and node/signer/witness
persistence remain required; no activation route or release/value gate opens.

## 18. First compiled migration preview (local model, runtime still closed)

The local descriptor `M0_HEARTBEAT_TO_ADMISSION_CHECKPOINT_V1` selects one
compiled function, not an interpreter or an arbitrary code path. The read-only
`rld-genesis upgrade-descriptor` command exposes these artifact bindings and the
current named source commitment, with runtime/signature flags explicitly false. Its artifact
bindings are SHA-256 of the exact `genesis/upgrade_migration.rs` module, this
specification file, and `vectors/upgrade-migration-v1/vectors.json`; the required
capability list is exactly `[NETWORK_HEARTBEAT_AND_ADMISSION_CHECKPOINT_V1]`.
The source binding remains the complete named implementation commitment, so
code in shared modules is also covered. The vector file verifies active-state
bytes only, not the entire migration or multi-role qualification. These hashes
are artifact identity, not independent review or authorization.

`preview_first_upgrade_activation` first requires §17 preflight and conservation,
then exact compiled descriptor equality. It clones the Ledger, advances once to
the scheduled height, removes pending state and replaces only the active state.
The new active JSON uses `RLD-M0-ACTIVE-PROTOCOL-V2`, sequence1, the target profile,
unchanged constitution/1000 founder ceiling, the exact activated intent ID and
`prior_active_commitment=SHA256(original_active_V1_bytes)`. The Rust state
carrier handles both versions, but V1 canonical validation forbids a predecessor
field; absent predecessors are omitted and explicit null is rejected. Original
V1 birth bytes are unchanged.

V2 active bytes are `D(RLD-M0-ACTIVE-PROTOCOL-BYTES-V2) || raw32(constitution) ||
u128be(1) || text(NETWORK_HEARTBEAT_AND_ADMISSION_CHECKPOINT_V1) || u16be(1000) ||
raw32(prior_active_commitment) || raw32(activated_intent_id)`. Only this first
successor shape is supported. Structural validation rebinds its constitution and
predecessor to the immutable birth. Finalized ancestry must still be proven by
main-WAL replay, not inferred from a well-formed active object.

After conservation and state-root checks, the evaluator compares the entire
serialized Ledger against the parent, normalizing only height, active state and
pending state. Any other change, including root-excluded locks/bookkeeping,
fails. Thus genesis, amounts, membership, Admission/censorship data, nullifiers,
obligations, tickets, deferred claims and existing locks are retained. The output
is a local successor preview; ordinary heartbeats can be evaluated on that
preview, but no certified transition has installed it in a live network.

This does not qualify M0b: V3 manifest runtime admission explicitly rejects
nonzero active upgrade sequences while they are preview-only. A structurally
valid migrated Ledger therefore cannot satisfy runtime manifest admission.
Tags37/38 remain unroutable; node/signer/witness live
profile checks and permanent/value gates remain closed. The single descriptor
is not a historical migration compatibility registry. No certified scheduling,
main-WAL activation, role-local durable authorization or second upgrade is
implemented. The earlier sections' birth-only/codec-only descriptions describe
those individual slices; §18 adds only this explicitly local successor model.

## 19. Core certified schedule adoption (live services/WAL still closed)

Core `ConsensusCommand::ScheduleUpgrade` now adopts tag37 with exactly the §13
frozen RLDW bytes; activation tag38 remains unrecognized. The outer network must
match the object. The infallible legacy command-hash accessor uses the canonical
wire hash for a valid schedule; malformed inputs produce only an invalid-domain
sentinel and remain rejected by the wire/signature validation path.

Core command execution first matches this build's source and the exact finite
migration artifacts/capabilities, then applies the existing successor evaluator.
Its outcome contains the pending record. Proposal validation computes the exact
successor, and authenticated candidate replay uses existing signatures, current
committee quorum, parent height/root and commit inventory. Insufficient quorum,
unsupported migration and conflicting signed successors are rejected without
state changes; exact repeated certified records retain existing idempotence.
This does not create a separate schedule-authority store.

This is core adoption, not a live scheduling release. Node M0 HTTP command guards
and isolated signer profiles (including the general canonical profile) still
reject schedules; the witness additionally
rejects them explicitly before its live proposal check. Existing main-WAL M0
mutation admission remains closed to tag37. Core candidate replay can therefore
exercise certified test schedules, but no live service can yet authorize and
persist the full operation through its normal pipeline. Compatibility across
source builds, main-WAL scheduling/recovery, boundary retry behavior and eventual
activation remain required. Current exact-build artifact checks may halt replay
of a schedule made by an older source build; no historical compatibility pass
is claimed. Earlier codec-only labels are retained as historical byte fixtures.

## 20. Schedule records in the existing main WAL (live services still closed)

The M0 main-WAL admission and ordinary durable replay path now recognize
ScheduleUpgrade vote locks and certified commits alongside heartbeats. They
reuse existing proposal/certificate authentication, current committee, exact
parent/successor checks, append/fsync, rollback anchor and checkpoint machinery.
The separate authenticated tag28 evidence path is unchanged. No secondary WAL
or independent activation decision is introduced.

Local tests bind a disposable V3 genesis and a correctly signed schedule from
three of its four validators. A durable schedule vote lock precedes the commit.
Fault injection before WAL append, after WAL fsync, before/after anchor rename/
sync and before/after checkpoint rename/sync recovers the exact old locked state
or complete committed pending state. Recovery uses the original exact genesis;
the first subsequent heartbeat vote lock is persisted and recovered again.
Insufficient quorum and a substituted supplied successor are rejected without
changing WAL, anchor, checkpoint or migration files. This is real local file
I/O with logical fault injection, not hardware power-loss evidence.

Node HTTP, isolated signer and live witness schedule guards remain closed.
Activation/tag38, role-local scheduling authorization, same-genesis historical
compatibility and full multi-process recovery still require implementation.
Current schedule replay requires the same compiled source/artifact set; these
checks do not establish recovery across source upgrades. Section19's closed-WAL
statement describes the earlier core-only slice and is superseded by §20.

## 21. Exact committed retries at the activation boundary

An existing authenticated commit is a read of its recorded outcome, not a new
height transition. Core commit application validates the M0 state/profile and
the stored certificate before returning an existing outcome. The next-height
upgrade barrier applies only after this retry branch, to new commits. Proposal
and vote-lock validation retain their barriers. A schedule retry reconstructs
its original pending-record outcome from the stored certified proposal; it does
not overwrite current pending state or re-run migration artifact selection.

The local WAL regression progresses a signed disposable V3 chain to exactly
activation-height minus one. Before and after exact-genesis recovery, schedule
and last-heartbeat retries must preserve the entire serialized Ledger, WAL,
anchor, checkpoint and sequence. A newly signed heartbeat proposal and quorum
certificate at that same boundary must fail without writes. This does not enable
activation, live scheduling, cross-build replay or any release/value gate.

## 22. Finite historical schedule compatibility

Schedule execution accepts the exact current-build tuple or a complete tuple in
the compiled `upgrade_compatibility.rs` registry. The first historical entry is
source `b8e145ea…`, backed by an unchanged old signed transcript, original source
snapshot and original verifier binary. Source, migration ID/code, specification,
vectors and ordered required capabilities must all match one entry. A known
source with a substituted component is not a compatible implementation. There
is no runtime file, network service or installer flag that can add authority.

Compatibility means the compiled schedule transition preserves that version's
certified pending state and root. It does not load or execute archived source.
The normal certificate, committee, parent, successor and invariant checks still
apply. Core semantic replay and main-WAL replay share this transition, including
when validating a proposed schedule; this registry is not a bypass available
only to a privileged restoration caller. Unknown tuples fail closed.

The historical fixture must keep its original signatures and fixed height/root.
Local regression covers replay, repeat certificates, complete-tuple rejection,
main-WAL recovery, a following heartbeat lock/commit and recovery again. Each
future entry needs its own retained-version evidence; accepting one entry is
not a general cross-version recovery guarantee.

This registry deliberately grants no activation compatibility. Live-build
activation still requires the exact scheduled installed source and migration
artifacts. An updated build can reconstruct this supported pending prefix but
must stop before activation unless separately qualified activation support is
implemented. Node HTTP, signer and live witness remain closed to scheduling;
tag38, permanent release and value gates remain closed. Sections19–21 describe
earlier slices; their lack of all historical schedule support is superseded only
for the finite entry covered here, not for activation or arbitrary source builds.

## 23. Certified candidate activation in core and main WAL

Core command tag38 adopts the frozen ActivateUpgrade bytes. Its command and
outer network must agree. The ordinary height barrier admits only an activation
that passes the exact pending-intent/current-build preflight at the next
scheduled height. Every other height-changing command still stops at the
boundary. The compiled finite migration then checks all scheduled artifacts,
conservation, successor commitment and whole-Ledger preservation. Committee,
leader, signature, parent and expected successor checks use the existing
consensus machinery; an activation does not supply its own authority.

The existing main-WAL lock/commit path supports this exact-build transition.
Activation removes pending state, creates the V2 active successor and advances
one height. Consensus bookkeeping is completed by the existing certified-commit
path. An exact repeated activation returns its retained active outcome without
reapplying the migration. Historical schedule compatibility from §22 does not
weaken activation's exact-source/artifact requirements.

The private-state candidate replay engine can reconstruct a certified active
successor from original pinned genesis. Its internal structural identity check
is deliberately separate from public runtime snapshot admission. Public
manifest validation still rejects every upgraded active state: candidate replay
and main-WAL support alone do not qualify node, isolated signer or live witness
startup. Both upgrade commands remain explicitly rejected by live signer and
witness policies, including the general canonical signer profile.

Local testing uses a disposable signed V3 schedule at height1, heartbeats through
height128, activation at129 and a following heartbeat at130. It checks incorrect
height/intent/sequence and insufficient quorum, then six logical file-I/O fault
boundaries around a durable activation vote lock and commit. Recovery must
return exactly the old locked or complete activated Ledger. After recovery the
next heartbeat lock/commit and second recovery must preserve the complete
state, and certified candidate replay must agree from the original genesis.
This is not hardware power-loss or multi-process/mixed-version qualification.

Live role authorization, historical activation replay, version distribution,
multi-role restart and production qualification remain outstanding. Permanent
release and VALUE_CAP_0 boundaries remain unchanged. Earlier reserved-tag38 and
preview-only descriptions are superseded only for this certified local path.

## 24. Historical activation semantics and exact live preflight

The compiled compatibility registry now distinguishes schedule-only entries
from entries with evidenced activation semantics. The `1c944737…` tuple includes
an unchanged old signed130-block transcript and132-record WAL/checkpoint/anchor;
it supports both phases. The older `b8e145ea…` tuple remains schedule-only.
Every source/code/specification/vector/migration/capability component must match
one complete entry. Unknown or mixed components cannot inherit activation
support from a recognized source identifier.

Consensus execution, candidate replay and main-WAL recovery select either the
exact current tuple or a compiled compatible activation tuple. Both paths share
the exact pending intent, birth/context, next-height and zero-value checks and
the deterministic first-migration successor/preservation algorithm. Historical
code is never loaded. Certificates, committee, leader, prestate and expected
successor are still authenticated through the ordinary consensus path.

The public `inspect_upgrade_activation_for_current_build` and
`preview_first_upgrade_activation` retain strict installed-source matching.
Semantic compatibility alone is not permission to issue a new live signature:
future role activation must additionally enforce installed-build preflight and
its durable role policy. All current live upgrade guards and public upgraded
snapshot admission remain closed.

Regression uses the old signatures unchanged, reproduces the old final root,
rejects insufficient quorum and re-signed wrong intent/successor, and confirms
that strict installed-build preflight rejects this historical source. Original
WAL, anchor and checkpoint bytes must remain unchanged during recovery. A new
heartbeat can then be committed and recovered through the same original
genesis. This proves one finite cross-build recovery case; it does not prove
arbitrary versions, independent clients/operators, hardware faults, live mixed
deployment or production activation. Section23's lack of historical activation
support is superseded only for this evidenced tuple.

## 25. Signer observation of already-certified upgrade history

The birth-bound signer has a separate local evidence endpoint,
`POST /v1/m0/certified-upgrade-history`. It accepts an exact canonical JSON array
of certified heartbeats, schedules and activations containing at least one
upgrade record. The existing512KiB request bound, loopback-only evidence gate,
exact framing, byte/rate budget and one blocking-worker permit apply. Signature
and policy authorization endpoints are unchanged; tag28/value commands are not
admitted through this importer.

Every certificate replays from the signer's own sealed genesis/history and is
checked against all existing proposal locks, vote locks, parent roots and signed
heads. The valid prefix of a bad batch is never published. Fresh records append
in one existing state/anchor transaction; exact duplicates cause no write.
No second WAL or independent authority flag is introduced. The same anchor-first
failure semantics restore the complete accepted batch if ordinary-state writing
fails after the anchor becomes durable.

The first accepted upgrade record changes the outer signer state to V6 and
semantic history to V3. The legacy `certified_heartbeat_json` storage field name
is retained, with the new strict version permitting the three record kinds.
V4/V5 history remains heartbeat-only; a V3 history with no upgrade is invalid.
Existing Admission source references survive the conversion, and subsequent
source ingestion cannot downgrade the new version.

Status V2 reports heartbeat count, certified upgrade-record count and observed
upgrade sequence separately. `upgrade_runtime_active` still means permission to
sign upgrade commands and remains false. The configured signing profile remains
heartbeat-only. Importing finality evidence cannot grant new signing permission.

Local tests deliver the retained130-block history through an actual loopback
HTTP server, verify restart and byte-idempotent retry, reject a late bad quorum
without prefix writes, preserve a conflicting released-signature lock, and
recover an anchor advanced before an injected ordinary-state write failure.
This is one role's certified-history persistence, not complete multi-role live
upgrade authorization, production hardware failure evidence or release approval.

## 26. Witness observation of already-certified upgrade history

The birth-bound witness exposes the separate local evidence endpoint
`POST /v1/m0/certified-upgrade-history`. The shared loopback-only input gate
requires canonical framing, application/json, a maximum 512KiB batch and the
existing rate, byte and blocking-worker limits. Each canonical commit remains
bounded by the existing 64KiB certificate limit. The array must contain at least
one schedule or activation and may otherwise contain only certified heartbeats.

Witness state V3 adds the explicit CertifiedUpgrade event. Heartbeat events retain
their heartbeat-only meaning, including in V3. V1/V2 cannot contain upgrade
observations; V3 must contain one. Replay verifies the entire original receipt
history, every certificate and existing vote locks before one anchor-first
transaction publishes the batch. Existing checkpoint/vote receipts are retained
byte-for-byte. The sequence counts events, so a batch can advance it by more than
one. Existing exact-prefix recovery restores the complete signed anchor after an
ordinary-state write failure. Duplicate certificates append no events. A bad
suffix publishes no valid prefix. Admission-source appends preserve V3.

Status V2 separates heartbeat count, certified upgrade-record count and observed
activation sequence. The allowed live consensus profile remains heartbeat-only
and upgrade_runtime_active remains false. Neither an observation nor a state
version transition grants permission to authorize upgrade votes. These local
software checks supply no external-operator, hardware, audit or value-gate proof.

## 27. Admission observations after certified activation

Admission observation and obligation queries use the identity validator for the
private certified replay state. The general manifest runtime/snapshot validator
continues to reject active successors. The observation engine cannot be created
from a supplied successor snapshot: it reconstructs the pinned birth and verifies
all transitions, retained source dependencies and finalized clock certificates.
Using the general runtime gate here incorrectly made role histories readable in
status but unusable by the Admission observation/obligation interfaces.

Queries after activation must preserve the same finalized height/root and remain
unsigned. A missing finalized clock certificate or substituted birth identity is
an error. Confirmed sources anchored to a certified post-activation block can
establish a local first-observation obligation; this does not establish accepted
contribution eligibility, authorize signatures/recovery, or activate censorship
policy. Signer and witness queries reconstruct their own sealed histories on
every request and after restart. No node startup or live upgrade gate is relaxed.

## 28. Exact installed-build preflight before role signatures

The private replay engine provides separate signed and unsigned local
pre-authorization checks. For ScheduleUpgrade these require the exact current
implementation source, migration ID/code, specification, vectors and capability
set. For ActivateUpgrade they require the current installed-build activation
check and finite migration preview from the authenticated pending state. They
then apply the full existing proposal checks: current authority, canonical wire,
parent, signed/unsigned envelope and exact resulting height/root.

Signer new-proposal/new-vote semantic checks and witness vote semantic checks
use these strict entry points. Historical certificate replay and candidate
inspection retain their finite compatibility behavior. Accepting an old
certificate cannot make a new signature pass the installed-build requirement.
Success is a precondition only: explicit live policy, durable vote/proposal locks
and the other role checks remain mandatory. Existing upgrade guards are unchanged.

Tests distinguish retained historical schedule/activation certificates from new
local authorization, exercise both signed and unsigned proposals for the current
compiled schedule and activation after certified intervening heartbeats, and
reject false roots and signatures without mutating the authenticated parent.

## 29. Sealed local bootstrap proposal policy (votes still closed)

An M0 signer can locally install `RLD-M0-UPGRADE-PROPOSAL-POLICY-V1`, containing
its exact birth pin and one complete unsigned ScheduleUpgrade proposal. The
canonical typed JSON is limited to64KiB. Installation requires the heartbeat
base profile, the signer's own proposer key/context, first-upgrade sequence1,
exact current-build semantic preflight and no conflict with an existing released
proposal/vote/head or parent-root lock. A policy cannot change the genesis or
configured witness policy. There is no HTTP policy installation route.

Signer state V7 seals the policy in the existing signed monotonic anchor. Once
installed it cannot be replaced; an identical installation is idempotent. This
state version also retains V1/V2/V3 semantic histories, source references and
all existing locks. Admission or certified-upgrade history ingestion preserves
V7. Recovery restores the exact policy and locks from the protected anchor after
an ordinary-state write failure. Removing the startup policy file does not
revoke a policy already sealed in durable state.

Only proposal signing receives this explicit exception to the heartbeat base
profile. The scheduled proposal must be byte-exact. An activation proposal must
refer to that schedule's exact intent, context, sequence and height, and every
new signature additionally passes the strict current-build, authenticated-parent
and migration/root checks. The existing proposal-lock transaction precedes
release. Exact retries return the retained signature; they cannot sign another
root. The proposal policy is local consent, not committee finality.

Witness-request signing, consensus-vote signing, witness upgrade authorization
and node upgrade ingress remain closed. `GET /v1/status` exposes the optional
`m0_upgrade_proposal_policy_hash` separately from the base profile. The M0
semantic status changes to V3 and reports `upgrade_runtime_active:true` with
`upgrade_proposal_signing_enabled:true` and `upgrade_vote_signing_enabled:false`.
This explicitly reports local signing permission, not an observed activation or
a complete live upgrade. Existing node admission has not been qualified for this
status/profile combination. Default
instances without a sealed policy continue rejecting both upgrade commands.

The optional signer startup argument `--m0-upgrade-proposal-policy` requires both
M0 birth arguments and installs the bounded local file before serving. Tests use
disposable keys, real proposal signatures and loopback HTTP, then verify policy
and activation-signature anchor-first failure recovery. These checks do not
qualify production signing, multi-role finalization, independent operators,
audits, release or value activation.

## 30. Independent sealed upgrade vote policy and witness quorums

`RLD-M0-UPGRADE-VOTE-POLICY-V1` is separate from the proposal policy. It binds the
original manifest pin, exact witness-policy hash, local validator subject and
one complete unsigned first-upgrade schedule. The local validator need not be
the proposer, but must be a current committee member. Installation verifies the
exact current-build unsigned proposal and existing locks. The policy cannot be
replaced; identical installation is idempotent. Proposal and vote policies on a
single signer must name the same schedule. Voting consent does not grant
proposal signing, and proposal consent does not grant voting.

Signer state V8 retains the independent vote policy alongside all original
locks and any proposal policy. A scoped upgrade first uses the existing signed
witness-request lock, then the exact existing witness quorum, then the existing
vote-signature transaction. The full current-build semantic checks run before
new request/vote signatures. Two receipts cannot satisfy a three-of-four policy.
Existing signature retries remain exact and durable; policy/request/vote writes
recover through the same protected anchor after ordinary-state write failure.

Witness state V4 records its immutable vote policy as an ordered signed-history
event. V2 upgrade envelopes bind the full signed proposal to the existing signed
request; V1 envelopes remain heartbeat-only. Default/unbound witnesses cannot
authorize upgrade-tag requests. Live authorization checks the exact policy and
current-build successor; replay checks already-released receipts against their
ordered policy and historical semantics, not a retroactive new-signature grant.
Source/certificate ingestion preserves V4. Policy and receipt append failures
recover from the signed anchor without authorizing conflicting votes.

Both roles accept an explicit local `--m0-upgrade-vote-policy` file, bounded to
64KiB with exact typed canonical JSON and requiring the M0 birth arguments.
There is no HTTP policy installation route. Signer semantic status V4 separates
proposal/vote permission and reports the vote-policy hash; witness semantic
status V3 reports its policy hash and enabled local upgrade authorization.
Neither status qualifies the current node's startup or upgrade ingress.

Local tests exercise three configured validator identities and three receipts
from each four-operator witness policy for schedule and activation certificates.
They exercise real role signatures and persistent role state, but use synthetic
node-record hashes and fixture-signed intervening heartbeats. They therefore do
not prove main-node WAL ordering, live network operation, independent control,
production hardware, audit or release/value readiness. Those qualifications remain
unproven; release/value gates, node upgrade ingress and general successor startup
remain closed.
