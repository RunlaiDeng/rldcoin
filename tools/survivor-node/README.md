# Survivor native candidate

This isolated Rust library implements the exact `RLD-SURVIVOR-1` consensus
contract in `docs/protocol/survivor-v1`. It accepts only explicitly pinned no-value
genesis manifests. It cannot activate monetary networks, import legacy stores or
migrate fixture value. No generated keys, ledgers or backups belong in this tree.

`kernel::Ledger` starts from decoded genesis and executes complete canonical
blocks. Its fields are private: a peer snapshot, root or claimed work cannot create
a ledger. It retains one UTXO map and 144 timing observations; archive retention
is a separate responsibility. `execute` stages checks before mutation. Local clock
eligibility is separate from intrinsic replay. The caller must suspend activation
on an untrusted/backward clock and durably commit before acknowledging any change.
`MiningJob` preserves its nonce cursor and accepts a finite attempt budget.

Supply, ownership, strict signatures, parent-only input execution, reward maturity,
base-target adjustment, recovery work, ordered state commitments and tip comparison
follow C01-C11. The local coin budget refuses without changing the tip. The
kernel clones the current UTXO map per candidate and rebuilds its ordered root;
large-owner throughput and cold-history resources require measurement. There is no
consensus height checkpoint or history-length cap. Missing history remains a wait.

C09 commitment construction streams exact fixed-width records through a bounded
binary frontier. Folding smaller right subtrees first preserves the specified
largest-power-of-two split, including unbalanced counts. The transient frontier
has at most `usize::BITS` entries; it does not retain an encoded copy of every coin.
Domain hashing consumes the exact same prefix and message bytes in parts. No hash
cache, persistent frontier or peer state initializes ledger authority. Every root
still hashes every current record, and complete cold replay still executes every
block. The retained recursive test reference checks binary boundaries and ordered
insert/delete/value edits; public-vector agreement remains same-author evidence.

The arithmetic and cryptographic codec are adapted from the same-author public
vector oracle. Differential fixture agreement is useful engineering evidence, not
an independent validator, security audit, durability or full-node qualification.
The kernel alone does not supply the full O01-O13 lifecycle. The native storage,
wallet, control and contact entries below preserve its authority boundary.
Actual interstellar adapters, long-horizon custody and monetary adoption remain
separate mandatory gates in the acceptance plan.

Contact block-syntax checks may reuse one process-local witness of a completely
validated intrinsic block. Reuse requires the same chain and identical complete
bytes under this executable's fixed suite and bounds; at most 262,144 block bytes
are retained. Allocation/lock failure, different bytes or eviction performs the
complete check instead. No witness is serialized. Every packet/frame signature,
connection challenge and role binding remains independently checked. The witness
does not validate a parent, timing, ownership, maturity, balances or state root;
ordinary native ledger execution still checks all those conditions. Repeated
intrinsically well-formed but semantically invalid bodies cannot acquire value
from custody or reuse. Distinct expensive bodies and sustained adversarial load
remain separate resource obligations.

```sh
cargo test --locked --manifest-path tools/survivor-node/Cargo.toml
cargo clippy --locked --manifest-path tools/survivor-node/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path tools/survivor-node/Cargo.toml -- --check
```

Tests consume the frozen public **NO-VALUE** fixtures, replay competing histories,
check exact roots/work/issuance and exercise malformed-input atomicity, pinning,
capacity refusal, payment maturity and native mining. Never use published fixture
signing material to protect assets.

## Durable native entry

`cargo run --locked --manifest-path tools/survivor-node/Cargo.toml -- serve
PRIVATE_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID [CONTACT_CONFIG] [--operating-policy LOCAL_FILE]`
opens one private no-value store.
Supply the exact 85-byte test genesis and its independently chosen pin. No genesis
is obtained from a directory service. Control requests are bounded JSON lines on
native stdin and responses are JSON on stdout. This is an engineering CLI, not a
consumer download or a public HTTP signing service. All API integers are decimal
strings and byte fields are lowercase hex. Do not put passwords in shell arguments,
command history, environment variables or logs; only secure local stdin integration
may supply the password field. Key files are encrypted and created at fresh paths.

The entry exposes `node_status`, `get_object` (genesis, transfers and blocks), `accept_block`,
`accept_history` (an exact bounded consecutive extension),
`submit_transaction`, `review_transfer` (exact `unsigned_hex`), `sign_review`,
`operation_status`, `wallet_state`, `waive_reservation`, `changes_since`,
`set_mining` and `create_key`. Start with mining disabled; explicitly enable it with
a valid public reward key. Optional mining uses actual local time and the normal
validator with no peer-count prerequisite. Unknown revision cursors require resync.
The stdin control stream must remain open while the process runs.

Responses distinguish clock observation from storage readiness. `storage_state`
is READY or RESTART_REQUIRED; an unavailable/backward clock keeps `observed_at`
null without inventing a time. Read-only status/recovery and disabling mining
remain available without a trusted clock. Enabling mining and new monetary
authorization still require the normal clock and storage checks. `mining_enabled`
records the operator choice separately from current clock/storage eligibility.

Optional `--operating-policy LOCAL_FILE` selects a bounded, strictly typed local
`RLD-SURVIVOR-OPERATING-POLICY-1` document. Its fields are `format`, exact lowercase
`chain_id`, and canonical decimal strings `ledger_database_bytes`, `ledger_coins`,
`carriage_database_bytes`, `carriage_packets` and `mining_trials_per_tick`. Unknown,
duplicate, wrong-chain, malformed and unsupported values refuse before creating
node state or keys. Ledger/custody database budgets are 128 KiB through
17,592,186,036,224 bytes; positive counts must fit the current machine; trial budget
is 1 through 1,000,000 per main-loop iteration. Actual SQLite, CPU, RAM, disk and
replay requirements still need provisioning and qualification. Defaults remain
256 MiB/1,000,000 coins, 256 MiB/4,096 custody packets and 4,096 trials.

Budgets are chosen at each local startup. Reuse the intended policy file for
`serve` and `restore`; omitting the option selects these published defaults. A
packet, peer advertisement or backup manifest cannot increase them. After capacity
refusal, stop the node and explicitly provision a larger budget, then reopen the
same intact store. Full native replay and exact pending-operation recovery remain
mandatory; expansion never deletes history, changes genesis or mints value.
`node_status` reports the effective policy and its local source. Its optional
process-only mining observation counts actual header-hash calls, including an
early successful trial. Nonces are distinct within one job; recreating a job can
repeat inputs, so the counter is not a global distinct-work or income claim.
Overflow reports an unknown count without stopping mining. Trial budget is not a
hash-rate or completion-time guarantee, and no counter is serialized as authority.

The native executable also provides `new-test-genesis FRESH_FILE`. It creates a
randomly distinguished zero-allocation **no-value** genesis and prints its chain
pin. Share that exact public file/pin explicitly with participants; creating a
different file creates a different network. `propose_transfer` accepts an owner,
explicit input outpoints, ordered owner/amount outputs, fee and optional height
expiry, all amounts as decimal strings. It returns a readable exact review and
digest; `sign_review` remains a separate explicit operation. This convenience
entry never silently changes or signs a transfer.

The store uses an exclusive OS writer lease and SQLite rollback journaling with
`synchronous=EXTRA` and macOS `fullfsync=ON`. Complete object/intent commit precedes
selected-head/operation-result commit and response release. Cold open executes
selected transitions from pinned genesis; alternative history is replayed under
its own parents. An uncommitted operation retains its exact prior binding and can
finish only on an explicit exact retry while that prior remains selected. Ambiguous
ledger write failure suspends mutation until reopen. Storage synchronization relies
on the OS/filesystem/device honoring it; process interruption is not physical
power-loss qualification. See SQLite's [synchronization contract](https://www.sqlite.org/pragma.html#pragma_synchronous).

The default database ceiling is 256 MiB and the current UTXO ceiling is 1,000,000
entries. The rollback journal and filesystem need additional space, potentially
another database-size allocation. Kernel candidates clone UTXOs; cold replay keeps
an ordered revision index; alternative-branch replay and historical wallet checks
can be costly. These are explicit local limits, not consensus checkpoints. Never
raise them silently, prune selected history or label capacity refusal as success.

Wallet reviews and reservations are synchronized before signature release. Exact
signed bytes are synchronized before return. Read-only recovery does not first-sign.
Reservations are derived from retained intents, so a restored selected input is
reserved again unless explicitly waived. O13 key encryption uses fixed scrypt and
AES-256-GCM with independent OS-generated salt/nonce. Direct-key loss has no reset.
The bounded pool keeps original signed bytes and selects parent-valid disjoint
inputs by fee/byte then ID. Submission never changes monetary state.
The submission acknowledgment reports `submission: RETAINED` and `ledger: null`;
retaining signed bytes is not itself a selected-history observation. Use
`operation_status` for actual inclusion/readiness, even when resubmitting a payment
that is already included.
Template construction and transaction status use the same local ready set before
block count/byte limits. Retained intents that lose an input to that policy report
CONFLICTED with `conflict_source: LOCAL_POOL`; selected-history input spending uses
SELECTED_HISTORY. Local preference cannot revoke a signature or invalidate a block
that includes another otherwise valid intent. Fee/byte comparison uses exact cross
products, with lower transaction ID breaking ties. Status reads do not reoffer,
sign or mutate the pool. Retained pool identity/signature corruption refuses and
suspends mutation pending full cold verification.

Wallet signing, recovery, status and reservation paths recompute the exact review
binding and verify any retained signature against its original unsigned bytes.
Signing also compares the caller's review digest and revalidates current inputs.
A successful wallet write must affect its exact row and read back the exact retained
intent/signature before any new signature or review receipt is returned. Corrupt
bindings, altered recovery bytes or unconfirmed writes suspend mutation until
full cold verification. During cold replay, wallet context indexes locate one
bounded record at a time at its actual selected head. Each original review must
match both head and revision; each retained signature must validate at a selected
head no earlier than that review. Complete native block/outcome/change verification
precedes these checks. Unresolved, intermediate batch or mismatched contexts refuse.
The indexes remain inside the database budget and never create a ledger or replace
signature, owner, value, maturity or expiry checks. Historical records remain valid
in their original contexts after inclusion or branch replacement. This avoids a
separate genesis replay per wallet record; it does not qualify growing wallet
journals, independent freshness or restored signing custody.
Missing arbitrary peer objects do not freeze a healthy
node; a detected corrupt retained body or missing known selected history does.

Transfer output observations expose current local reservation and retain a known
selected maturity height after spending. Local intent and observed public inclusion
remain separate: a reviewed intent may already appear in retained signed public
bytes, without this wallet having released a signature. `signature_source` states
LOCAL_WALLET or RETAINED_PUBLIC_BYTES, or null when no signed bytes are observed.
`reviewed_tip` and `reviewed_revision` retain the original review context. A query
never converts public observation into local first signing or edits the journal.

Ordinary startup creates a separate contact identity, retained TLS material and
bounded custody database. Without configuration it listens on an ephemeral loopback
port and has no neighbors. Optional contact configuration supplies a literal `listen`
address and `neighbors` entries with exact `key`, literal `endpoint` and
`certificate_sha256`. Obtain these values from each node's local status and admit
them independently; advertisements never replace pins. No private contact material
belongs in a shared configuration or public repository.

The native lifecycle exchanges signed HEAD/LOCATOR/inventory and complete blocks,
replays missing dependencies and forwards canonical transactions. TLS 1.3 uses
mutual pins, fresh application challenges and bounded worker sockets. Custody is
committed by the main loop before acknowledgment; socket workers hold no ledger
lock. The connection-pressure fixture uses an intact common history, bounded
unauthenticated loopback connections and a sole surviving ordinary process. Local
mining/payment and complete cold replay remain separate from transport-worker
availability; this does not promise delivery under arbitrary sustained overload.
The original fresh-install/mining fixture remains a separate required check.
An unavailable listening socket leaves the verified adapter in `LISTEN_WAIT`.
`listen` stays null; `configured_listen` retains the exact admitted literal address.
Normal ticks retry only the socket, at least five seconds between attempts, using
the same cached pins, TLS material, contact identity and durable carriage. They do
not reload configuration, regenerate keys or clear obligations. Successful binding
publishes the actual address and `ACTIVE_GROUND_ADAPTER`; scheduling/verification
time remains separate from the retry interval. Outgoing and admitted offline work
continue during the wait. The two inbound-worker slots remain shared across
acceptor lifetimes. Invalid configuration or cryptographic material still refuses;
it is never treated as a recoverable socket wait.
Persistent neighbor/class/object rotation and temporary unavailable-neighbor
backoff allow alternate admitted neighbors. Receipt observations survive restart;
hop acknowledgment never discharges a destination obligation. Returned destination
receipts may traverse a relay that lacks the original packet. The native receive
path checks exact retained bytes and retained origin/sequence conflicts
before every packet-kind handler, including RETURN_RECEIPT. A conflicting wrapper
is recorded/refused before applying its nested receipt; the same authentic receipt
remains usable under a valid new wrapper. Exact retry and lower, previously unseen
sequences remain eligible, without receipt-of-receipt promises or ledger authority.
The default custody budget is 4096 packets/256 MiB including metadata. At most 256 recently completed,
processed packets remain as transport history; older copies can be collected only
after rechecking their exact destination receipt. Kind-9 control copies carry no
new custody promise and share this finite cache. Collection never removes ledger
or wallet evidence. A missing old observation is unavailable transport history,
not evidence that delivery did not occur. Live obligations are never collected;
exhaustion refuses new custody.
Ground certificates expire after 90 days and need explicit independently pinned
renewal. This is not a qualified physical interstellar adapter.
Expired retained ground credentials do not disable independently admitted file
carriage. Live TLS still rejects expired certificates, even with a matching pin.

An optional `offline_peers` list independently admits public keys for one-way file
carriage. `offline_export(peer_key)` returns bounded exact frame bytes after durable
preparation; retries retain the original nonce and packet. `offline_import` reads
one bounded `frame_file` for that admitted peer and returns its signed receipt.
The receipt may be imported later at the original sender, where its exact retained
delivery/nonces must match. Normal TLS never accepts an offline zero challenge.
Every re-emission fully authenticates the retained delivery's sender, receiver,
offline challenge and nonce, then compares the complete packet bytes with the
requested durable packet. A valid signature on another packet or frame cannot
substitute for that exact outgoing record; invalid retained rows refuse unchanged.
Packet lookup also authenticates the decoded ID, origin, sequence and kind against
the requested row before returning bytes or reacknowledging duplicate custody.
Receipt import repeats the retained-delivery and complete packet checks before
writing any destination or hop observation. A signature on a mismatched outgoing
record cannot suppress a real obligation, even if a later check would refuse it.
`discovery_candidates` exposes signed peer introductions without granting endpoint
or certificate authority. Complete pending block bytes suppress redundant fetches
but cannot advance the ledger before native ancestor/state execution.
Each neighbor has its own durable class and object cursors, avoiding synchronized
neighbor/class cycles. For a finite admitted eligible workload of P packets in a
class and N available neighbors, each neighbor visits the class within at most
5*N scheduling turns and offers its packets within at most 5*N*ceil(P/16) turns,
excluding explicit suppression until the next probe. Local verification and
physical contact time are separate costs; sustained overload has no delivery bound.
`withdraw_transport` requires explicit acknowledgment that undelivered data may be
lost. It durably abandons only the named carriage obligation, cannot revoke a
signature or undo a ledger entry, and cannot reacknowledge the abandoned packet.

Selected changes commit exact attached/detached block and transaction IDs together
with changed output observations. Cold replay checks those notifications against
native execution. `changes_since` returns at most 128 revisions/1 MiB; larger gaps
explicitly require a fresh snapshot. Wallet operation status distinguishes inclusion,
detachment, conflict, readiness and historical transport receipts. Detached original
signatures have persistent reoffer references; pool pressure cannot disable mining.
Recent transaction observations use at most 256 process-local witnesses and 8192
input-watch references. Only fully executed, durably selected native changes seed
or update them. Cold startup still executes complete retained history and compares
the complete original change events before rebuilding these observations. Nothing
is serialized or accepted as a ledger initializer, balance, signature or proof from
a peer. Delta preparation is bounded by 64 changed blocks and 1 MiB of complete
block bytes; a larger valid transition discards the optional observations and still
uses normal consensus/reorganization execution. It does not impose a history cap.
Eviction, a missing/stale witness or an older historical query uses the complete
retained-history path. That path can still be expensive and is separately measured.
The deep-reorganization fixture exercises that fallback with a missing ancestor,
losing reward/payment descendants and original wallet contexts. Reoffering retains
the exact old signatures and input IDs; another available coin cannot silently
replace a disappeared input. New winning-chain payments require their own explicit
reviews. Complete cold replay checks the resulting state and original signatures;
the fixture does not establish arbitrary long-fork throughput or independent custody.
Each retained observation binds the exact unsigned transaction, selected tip and
revision. Queries recheck the retained head/inclusion/input-spend proof objects;
missing or corrupt known evidence suspends mutation. Output state, reservations,
pool preference, clock and transport observations are read from current native
state, never cached as a combined payment status. Reorgs remove losing inclusion
and input-spend effects while preserving the historical meaning of detachment.
The local storage format is now `RLD-SURVIVOR-STORE-4`; earlier candidate stores
refuse, with no automatic migration or test-value continuity.

Alternate-branch replay may reuse one process-local prefix that this Store has
already completely native-executed under its immutable genesis and resource
binding. Every retained prefix block is read and compared byte-for-byte before
reuse; missing or changed known material suspends mutation. A different branch
or a cold start executes from pinned genesis. No witness is serialized. Retention
is limited to 4 MiB of complete block bytes and 4,096 current coins; exceeding
these optional bounds discards reuse and still returns the fully executed valid
ledger. These are not block acceptance, history or reorganization depth limits.
Cold verification preserves revision/selection/commit ordering, using the canonical
header height only to schedule nonselecting rows within an otherwise equal group.
Every operation's actual parent, execution, selected head and exact outcome remain
independently checked. This reuse does not qualify arbitrary fork costs or T18/T19.

Ordinary history synchronization can install up to 32 consecutive blocks as one
selected transition. It validates every complete block against its own fully
executed predecessor, durably commits the exact ordered member list and all objects
with its intent, then atomically commits the final tip and complete change event.
No intermediate tip or member success is released before that commit. The single
revision includes every attached block, transaction and reward; wallets observe the
final selected state. An invalid group installs no partial prefix. Ordinary bounded
single-object processing remains available for competing, missing or invalid paths.
Cold startup verifies the group membership and executes every member from native
genesis/predecessor state. The member index supplies no ledger authority.
After that execution, cold change reconstruction uses the exact contiguous member
list and its native predecessor state. It compares the complete attached/reward/
output event with the retained original instead of repeatedly searching the old
prefix for an already authenticated extension. Ordinary fork/reorganization
handling keeps its complete ancestry checks. No block or signature is skipped.
`accept_history` takes `operation_id` and ordered block hex strings in `blocks`;
the existing 2-MiB native request limit remains in force. Exact retry must retain
the same complete member list. Pending operation status exposes member IDs and the
recovery method; `get_object` retrieves the retained complete block bytes.

The separate `rld-survivor-history FRESH_DIRECTORY BLOCKS BUDGET_SECONDS [GROUP_SIZE] [WORKLOAD] [with-backup]`
measurement tool exercises actual nonce search, ordinary storage and full cold
replay at unchanged default limits. Group size is explicitly 1..32; its bounded
observation budget is 1..3600 seconds. It uses logical 600-second chain timestamps
and 256 deliberately public no-value reward owners, reporting that clock model
separately from real elapsed time. It preserves incomplete fixtures, refuses an
existing target directory and never claims a simulated clock proves real-time
survivor recovery, sustained adversarial traffic or independent qualification.
The default `growing-rewards` workload retains unspent rewards. A separate
`consolidating-payments` workload starts real signed payments at height 101, then
spends the next mature reward together with the preceding payment output. Its
256 public fixture owners rotate actual transfer authorization. This keeps 101
unspent outputs while complete signed/spent history grows; it does not replace
the growing-UTXO workload. Cold replay checks the complete selected history and
counts the retained transfers again. Fixture-direct signing does not qualify
wallet intent, independent key custody or ordinary consumer use.

Optional `with-backup` requires at least 100 blocks and includes the complete
encrypted-backup lifecycle in that same declared observation budget. After initial
cold replay it reviews, reserves, signs and submits one exact pending fixture
transfer through the native wallet; encrypts its explicitly listed fixture key;
creates a whole-node image; closes the source; restores to a fresh directory; and
opens the restored ordinary store. It compares complete selected state, pending
signature, reservation/balance, encrypted key, local pool and ledger/contact head.
Creation, native restore and ordinary reopen costs are measured separately. The
retained provided head is on the same host, never an independent freshness witness.
This mode uses a deliberately public NO-VALUE fixture passphrase. Generated keys,
images and node/contact state remain private test artifacts and must never be
published, even encrypted. No physical power-loss or independent custody claim
follows. An earlier history-only result cannot qualify this additional lifecycle.

`state_head` exports an exact local ledger/intent/custody and communication-material
commitment to retain independently. `BACKUP-HEAD-2` binds the ledger and custody
heads plus purpose-separated hashes of the exact contact key, TLS material and
admitted configuration. Changed retained contact/TLS files refuse source backup;
no key or pin is silently regenerated. A backup head alone never authorizes money.

`create_backup` takes a fresh destination, native-input password and explicit
`wallet_key_files` inventory. It snapshots complete SQLite databases through the
native backup API. Staging stays private; interrupted builds retain `BUILDING` and
residue. Explicitly listed keys retain separate O13 encryption. Their fixed format
is checked; their inner chain, owner and authentication still require the wallet
password during native decryption. Unlisted keys are not implicitly included.

Local format `RLD-SURVIVOR-BACKUP-2` uses bounded encrypted chunks. Its 126-byte
record header is magic `RLDSBKP2`, chain[32], random bundle[32], kind:u16,
plaintext-length:u64, fixed chunk-size:u32=1048576, salt[32] and nonce-prefix[8].
All integers are big-endian. Fixed scrypt N=32768/r=8/p=1 derives AES-256-GCM.
Each chunk is ciphertext followed by its full 16-byte tag. Its nonce is the
record's nonce-prefix followed by its u32 index; associated data is the complete
header, that index and the chunk's plaintext length:u32. At most 2^32 chunks are
possible, and an empty file still authenticates one empty chunk. Exact length,
order, role and bundle are mandatory; extra, omitted or substituted bytes refuse.
The buffer is fixed at one chunk plus tag and is zeroized on all exits.

Kinds 1..5 are ledger, custody, contact key, TLS material and admitted configuration;
100..163 are the listed encrypted keys, and 0 is the bounded inventory/genesis/head
manifest. Paths and chunk sizes are never archive-selected. Database image totals
must fit the locally provisioned budgets, 256 MiB each by default; metadata/key
bounds remain separate. The record format does not load a complete image into a
plaintext/ciphertext Vec. KDF, SQLite, full native state/replay, staging disk and
whole-node resources remain separate costs. Historical V1 images refuse unchanged;
there is no automatic conversion or monetary migration.

`rld-survivor-node restore FRESH_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID BACKUP_DIRECTORY
[--operating-policy LOCAL_FILE]` reads one bounded native JSON request with
`password` and optional independently retained `latest_state_head`. Only the
caller's local policy admits image sizes; an image cannot enlarge it. Every chunk,
complete inventory, full native ledger/custody state, contact/TLS key binding and
admitted configuration are verified before clearing RESTORING. Validation opens
no sockets and generates no replacement keys. Existing/interrupted destinations
never overwrite or resume. With no supplied head the restored wallet
reports FRESHNESS_UNKNOWN and refuses first signing, while exact signed recovery
and mining remain possible. `acknowledge_restore_risk` requires the current
`intent_head` and explicit acknowledgment of possible conflicting signatures.
This records accepted risk, not independent freshness. Restore policy never creates
a mandatory witness for an intact surviving node.

The allowlisted Rust packager creates a deterministic tar container with the native
executable, protocol documents, license and SHA-256 inventory. CI builds separate
Linux/macOS artifacts after checks. Hashes detect byte changes; they are not an
owner-signed monetary release or evidence of independently reproducible binaries.
No keys, databases, live configurations or generated genesis are packaged.
Every allowlisted input remains a regular file of at most 64 MiB; oversized inputs
refuse before creating an archive. Test builds use debug-information level 1 while
retaining optimization level 1, debug assertions and overflow checks, so embedded
development symbols need not consume the package's finite file budget. Distribution
checks still extract and execute the exact compiled native candidate.

Process interruption probes cover validation, durable intent and durable committed
ledger boundaries, including response-loss recovery. Independent power-loss,
all-state rollback/cross-device custody, sustained ordinary history beyond an
issuance era, independent security/validator review, complete consumer qualification
and physical interstellar adapters remain distinct unqualified gates.
`ACTIVE_GROUND_ADAPTER`
reports local adapter operation, never an assertion of an interstellar connection.
