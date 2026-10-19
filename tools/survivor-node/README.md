# Survivor native candidate

## Interactive native wallet

Build the native executables together and keep `rld-fast-wallet` beside
`rld-fast-payment-session`. The interactive client uses the existing private
serialized node; it does not maintain another ledger or signing engine.

```text
rld-fast-wallet init ROOT GENESIS PIN CALLER_HEAD_FILE
rld-fast-wallet open ROOT GENESIS PIN CALLER_HEAD_FILE
rld-fast-wallet open ROOT GENESIS PIN CALLER_HEAD_FILE PEER_ROOT PEER_HEAD_FILE
rld-fast-wallet recover ROOT GENESIS PIN CALLER_HEAD_FILE
```

Genesis and its exact pin come from the intended network's authenticated release.
`init` creates fresh local session state, not a currency or monetary genesis.
`open` retains exclusive caller/native ownership; optional already-pinned peer
state enables automatic native/signature carriage. The node continues its normal
sync/mining work while the menu waits for input. Closing the menu stops this local
node. Another process must not open these same stores concurrently.

The menu creates/selects encrypted wallets, shows ordinary balances, starts or
stops public-reward-key mining, prepares ordinary payments, resumes retained
payments and creates/exports funding-miner receipt-service delegation. Amounts
use exact decimal RLD with up to24 places. Input selection uses actual mature,
locally unreserved native output pages and at most32 inputs; change returns to
the same selected owner. A new transfer expires at observed height+144. The
complete native review displays ordered recipients, amounts, fee and expiry;
signing requires the actual selected owner and explicit typed YES before another
password prompt. Queueing is reported separately from inclusion.

Passwords are read only from `/dev/tty` with terminal echo disabled through the
native system `stty`, restored on normal completion/error. There is no visible
password or argv/environment/HTTP fallback. Secret buffers and serialized private
requests are zeroized. The sibling node receives passwords only through its
private stdin; raw key material is never displayed or imported by this client.

Resume reads the node's actual retained transfer intent, preserves all original
terms and expiry and displays its first native preparation time. An existing
signature is requeued only after explicit confirmation; an unsigned exact intent
gets a new current native review without releasing its old reservations. A
transport timeout or broken reply poisons the client stream: it stops rather than
matching a late signature reply to another request. `recover` uses the normal
keyless trusted-head recovery and displays retained request/certificate references.
It cannot first-sign or clear included/reserved value. Expired conflicting intent
is not silently replaced.

The client bounds private frames to1 MiB and responses to120 seconds. An
interrupted operation remains pending until normal native recovery; these client
limits change no protocol clock or ledger capacity. The fast-channel submenu
exposes explicit owner/retainer payment, joint opening, native exit and bounded
fee-monitor workflows described below. The current operator menu still requires
manual coordination and selection of retained public requests and packets.
This client and current distribution retain the node's NO_VALUE_ONLY status.

The explicit package option includes the three wallet/peer executables and their
allowlisted interfaces, with no wallet/key/peer state:

```text
rld-survivor-package REPOSITORY_ROOT NATIVE_BINARY FRESH_TAR_PATH --wallet-binaries BINARY_DIRECTORY
```

This produces the normal checksum-bound archive with an explicit no-value wallet
profile. Default packaging remains the baseline native distribution. Neither
archive creates a monetary network or establishes runtime qualification.

## Interactive fast-channel workflow

The fast-payment submenu uses the same private native backend. It lists only
locally registered channel roles, configured neighbor identities and received
packets of the required protocol kind. These lists supply data selection, not
signing authority. The selected encrypted wallet must equal the actual owner or
retainer in the native review before its key can be loaded. A changed native
selection refuses the old approval; the menu never automatically retries signing.

1. Agree both ordered owners, exact native inputs, principal, payment-slot limits,
   positive per-payment rates and opening fees. Create a joint opening proposal.
   Native execution computes own change and checks all input owners and sums.
   Each owner independently prepares, reviews and signs its own inputs. Send the
   retained proposal/partial to the configured other node, combine its exact
   received partial and queue the complete native operation. Queueing remains
   distinct from own-template mining and recipient native admission.
2. After actual selected native inclusion, obtain the funding miner's explicit
   receipt-service delegation. Register the separate owner/retainer roles using
   that exact certificate. Mining itself still needs only a public reward key.
3. The payer creates a positive fast-payment proposal and explicitly approves its
   native review. Send the retained invoice to the other owner. That owner chooses
   the received invoice, independently reviews and signs, then both exchange their
   retained partials. A local partial or transport receipt cannot complete payment.
4. Combine the two exact owner signatures and send the complete receipt to the
   delegated receipt service. Its actual key independently approves durable full
   receipt custody. Send its retained acknowledgment separately to both owners.
5. Each owner selects the counterparty partial and delegated acknowledgment and
   retains the complete proofs. Inspect the actual owner state: historical balance,
   original pending age, native backing, fee-slot use and conditional onward
   usability remain distinct. A missing acknowledgment or unavailable backing
   cannot be relabeled as completed usable funds. Pending reviews and already
   retained own signatures can be resumed without changing their original clock.

The menu also exposes native close, principal challenge, independent miner-fee
claim and settlement using actual retained complete evidence. An explicitly chosen
initial close uses no later certificate; settlement does not pretend an unused
channel already has a complete payment. Fee-paying ordinary inputs are selected
from the actual mature, locally unreserved wallet and get a fresh native review
and explicit input-owner signature. Fixed native windows, consensus, actual fee
beneficiary and reward maturity remain unchanged; a queued action is not payout.

A separate fee-wallet consent menu displays exact root inputs, caller/currency,
channel, operation/total fee ceilings, count and absolute height/time expiry before
explicit approval. Only that actual input owner's key signs the bounded policy.
Local monitoring can then unlock that exact policy; it cannot approve channel
principal or replace the miner delegation. Stop/restart drops the in-memory unlock
and requires explicit reactivation of the existing retained policy. Runtime status
reports actual monitor/native/carriage observations and diagnostics.

Save the displayed preparation, review and own signing request identifiers for
manual opening coordination. The native-preparation resumption entry reads the
actual authenticated retained request and displays its historical terms and time.
An existing complete native authorization is requeued only after confirmation;
existing delegation certificates are exported keylessly. Re-review of an opening
or unsigned native action preserves all original inputs, outputs, fees, nonce and
expiry, changing only the prospective evaluation time and selected native tip.
It creates a new persisted review and still requires explicit actual-owner consent.
No expired or conflicting reservation is silently released or allocated anew.

These interfaces implement operator steps. Automatic peer provisioning, routine
payment choreography, long-running storage lifecycle and monetary activation
remain separate product work. Source availability and compilation do not establish
local latency, daily payment volume, uninterrupted monitoring or runtime outcomes.

## Native protocol and service interfaces

The explicit [append-only caller-head profile](../../docs/protocol/FAST_SESSION_HEAD_LOG_V1.md)
uses `create-log-control`, `serve-log-control` and `recover-log-control` with
`ROOT GENESIS PIN TRUSTED_HEAD_FILE`. It retains exact canonical request digests
before caller/child work and complete audited responses before advancing the
trusted head. File and directory synchronization, full prefix/identity checks
and the original1048651-byte control-file bound remain mandatory. Both records
are reserved before a request, limiting a fresh log to2896 complete requests.
It refuses torn/full/mixed state without repair, migration or automatic rotation.
Snapshot controls retain their original entries and refuse this format.
The local latest-head file is trusted; independent freshness/custody and scalable
archival remain separate obligations. Both explicit profiles can select the
[automatic native/signature carriage](../../docs/protocol/FAST_NATIVE_AUTOMATIC_CARRIAGE_V1.md)
mode with pinned peer/head arguments and `--auto-sync`.

The private `native_coin` observation accepts the current session head and one
34-byte output reference. It reads only the actual authenticated selected native
ledger and returns owner/value/maturity or absence, with its exact tip/time.
It does not append requests, authorize spending or resolve wallet reservations.
Cold session startup retains full native/caller/actor replay, allowing a wallet
to inspect that same validated session before ordinary own-template spending.

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

Successful contact startup durably retains the complete locally admitted listen
address, neighbor keys/endpoints/certificate pins and offline peers. Restart may
omit the optional contact file; both the CLI and library reopen that exact retained
configuration. An explicit valid local file may replace it after complete adapter
validation. Advertisements never perform this replacement. Atomic publication
uses a private synchronized `contact/config.next`, rename and directory sync before
opening a socket. Interrupted residue, missing retained configuration, malformed
data and configuration symlinks refuse the adapter instead of selecting defaults.
Keep damaged/interrupted bytes for diagnosis; no automatic repair is performed.
Backups refuse changed or interrupted admission rather than exporting stale
in-memory settings. This local persistence contract is not independent freshness,
power-loss or physical-link qualification.

The ordinary `offline_payment_process.rs` check uses only forward frame files
from a source to a relay and then to a fresh recipient. The source mines and
signs through the ordinary CLI, then exits while the recipient is still at
genesis. The relay reopens retained native history and admission without a
configuration argument before carrying the payment onward. After the relay also
exits, the recipient independently signs and includes a payment spending the
exact received output, then cold-reopens without repeating its configuration.
Complete native replay checks both original signatures and monetary conservation;
no controller-created ledger or reverse receipt supplies value. Generated fixture
keys, frame archives and stopped stores remain private. This finite same-host
check does not qualify a physical route or independent custody/security.
The separate four-node case requires two successive relays: the source exits
before the second leg, the first relay exits after downstream native custody,
and the downstream relay reopens without a configuration argument before final
delivery. Recipient inclusion, actual onward spending and full cold conservation
remain mandatory. Selecting an offline export peer preserves the complete locally
admitted neighbor set for direct routing; traffic for another admitted direct
destination stays retained for that destination. Unknown destinations can still
transit through a willing selected peer. This scheduling rule grants no delivery
receipt and never deletes an unresolved obligation.

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
Ordinary ticks proactively offer complete selected-history blocks to explicitly
admitted offline peers, starting at genesis and using the existing BLOCK format.
Only one peer and at most 16 block offers are scheduled per tick. Each progress
advance follows durable retention of that exact packet. Restart rechecks scheduling
hints; a retained former-branch cursor restarts the prefix offer. Missing or
malformed scheduling targets refuse instead of being treated as remote history.
The destination still executes every dependency through the normal native kernel.
No reverse request or receipt is needed to carry the prefix. The sender retains
all unacknowledged obligations and cannot report destination receipt from a local
cursor. Capacity exhaustion refuses more work, preserving the earlier packets.
Walking selected ancestry still costs full-history reads; bounded batches do not
qualify long-history performance or any physical route.
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

## Portable signed-intent capsules

The file codec in [PAYMENT_CAPSULE_V1.md](../../docs/protocol/PAYMENT_CAPSULE_V1.md)
binds exact signed C04 bytes to a complete streamed genesis-rooted history. It
changes no consensus transaction or contact-packet kind. The native local API adds:

- `capsule_export`: `transaction_hex`, fresh private `capsule_file` output path.
- `capsule_refresh`: `prior_capsule_file`, fresh `capsule_file`; verifies the prior
  container and preserves every original transaction/signature byte while exporting
  the current source history. It never signs or restores an orphaned input.
- `capsule_verify`: `capsule_file` and optional full `expected_transaction_hex`.
  It fully executes carried history without changing local head or balances.
  `carried_tip`, `clock_eligible` and `local_ledger_acceptance:false` are separate
  from the recipient's actual selected state; freshness remains unknown.
- `capsule_import`: the same input fields; complete initial verification precedes
  ordinary native block acceptance and pool retention. The response binds both
  carried and actual selected tips, original X and the current native transaction
  observation. `complete_import:true` is not a promise of an included/spendable
  payment: missing, spent or immature inputs retain their normal meanings.

The file byte budget is the locally chosen ledger database budget. Blocks remain
bounded at 262,144 bytes and are streamed rather than decoded into a trusted peer
ledger. The original grouped interface remains limited to 32 blocks. Initial bad
or incomplete capsules cannot change monetary state; a later I/O/capacity failure
can retain only individually native-validated prefix transitions, without a complete
import acknowledgment. Exact retry verifies the whole file again. Export refuses
existing paths and retains failed partial output. There is no public HTTP file/key
upload endpoint and no implicit capsule transport registry or physical-route claim.

The published public no-value vectors bind exact encoding, lengths and digest.
Native checks separately cover invalid evidence before mutation, changed bytes
after verification, evidence refresh and ordinary owner-authorized onward payment.
These engineering checks do not establish independent security/custody, arbitrary
history resources, fast-layer capacity or monetary adoption.

## Separate native escrow candidate

The [no-value escrow profile](../../docs/protocol/NATIVE_FAST_ESCROW_V1.md) has its
own113-byte genesis and version2 work-bound blocks. `kernel::fast::Ledger` executes
actual mature funding inputs, ordinary transfers, separate principal/fee challenges,
fixed height AND time windows, exact refunds and100-block-mature miner payouts.
It never initializes value from a fee-component view or a decoded balance table.
The ordinary Survivor-1 node refuses its genesis/blocks and has no automatic upgrade.

Build its separate read-only archive command with
`cargo build --locked --manifest-path tools/survivor-node/Cargo.toml --bin rld-fast-escrow-candidate`.
Invoke `rld-fast-escrow-candidate GENESIS_FILE EXPECTED_CHAIN_HEX BLOCK_ARCHIVE`.
Every archive record is a big-endian u32 length and a complete native block.
The command reconstructs the entire branch with actual local future-clock checks;
it exposes no signing, operator endpoint, live ledger or mainnet activation.
Its reported tip is that replayed branch, not proof of the strongest unseen work.

This engine does not complete the fast product. Durable owner requests/backups,
independent fee-retainer delegation and acknowledgment, complete fast payment
transitions, normal network lifecycle, hostile exit capacity and composed daily
performance remain required. Logical-time native tests are not an elapsed dispute
window, power-loss/cross-device custody or independent security qualification.

## Funded invoice and fee-retainer custody components

[FAST_PAYMENT_RETENTION_V1](../../docs/protocol/FAST_PAYMENT_RETENTION_V1.md)
specifies the complete invoice, amount, fee and exact old/new state authorization.
`fast_payment::Payment` verifies both owners' state and invoice signatures against
an opaque native-derived funding origin. Its partial assembler combines existing
signatures only. A supplied context or hash cannot initialize that native origin.

`fast_retainer::Journal` is a Unix private-file component with explicit miner
delegation, full native funding-prefix replay, exclusive lock, separate caller
latest-head/native-head inputs and bounded complete receipt retention. Preparing
a receipt never signs; acknowledgment loads its delegated key only after complete
review/current-view checks and releases the signature only after durable retention.
Explicit recovery returns an existing signature or an unsigned pending receipt;
it never loads a key or first-signs. Capacity reservation includes both records.
Cold startup verifies every receipt/signature; warm writes compare the complete
authenticated retained prefix and actual file identity. No failed tail is repaired.

These are library interfaces, not a live fast-payment endpoint or owner wallet.
The separate `rld-fast-retainer-recover JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD RECEIPT_ID`
command performs only native keyless historical recovery. It accepts no key or
password, appends no new custody record and reports current backing as unknown.
Independent native monitoring, owner signing journals, operating fee liquidity,
cross-device/power-loss custody and composed daily performance remain unqualified.
A retained acknowledgment alone does not establish usable money or fast completion.

The separate [owner authorization journal](../../docs/protocol/FAST_OWNER_AUTHORIZATION_V1.md)
adds `Invoice::propose` for unsigned exact payment construction and
`fast_owner::Journal` for each owner's explicit review, durable pre-key reservation,
own partial signing and complete receipt/retainer proof retention. Key loading
occurs after native/head/review checks; signatures return only after file/directory
sync. Pending slots cannot be canceled or released by timeout. Identical already
signed requests use keyless retrieval; they never load a key or sign again.
Latest complete exit proof remains readable during a later pending payment.
Creation/cold startup replay full native funding and authenticate every retained
invoice, own partial, complete receipt and delegated acknowledgment. Caller latest
heads, full prefix and Unix file identity remain mandatory. Per-file/prefix limits
are at most256 MiB; unsupported file-identity platforms refuse.

`rld-fast-owner-recover partial|complete JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD INVOICE_OR_RECEIPT_ID`
recovers only an exact authenticated next tail under the caller's retained prior
head. It accepts no key/password, signs/appends nothing and reports current
backing unknown and fast completion false. The owner component is a library and
historical recovery tool, without a frontend authorization/caller-head service,
live native selector, network endpoint or independent custody/monitoring. Distinct
test keys and same-host process interruption do not qualify independent operators,
copied-key concurrency, common rollback, power-loss or composed daily performance.

The [native fast-node selector](../../docs/protocol/FAST_NATIVE_NODE_V1.md) adds
`fast_store::Store` and separate `rld-fast-node` local control. It stores every
accepted complete branch in an exclusive private bounded journal, chooses the
greatest native work/smaller-ID tip, and reexecutes all admitted branches from the
independently pinned genesis on every cold open. Explicit expected storage and
selected heads precede admission/current-view borrows. `Store::current` supplies
the serialized selected native view for owner/retainer library checks; a historical
funding origin cannot survive a stronger branch merely through an old receipt.

```
rld-fast-node create JOURNAL GENESIS_FILE PINNED_CHAIN
rld-fast-node serve JOURNAL GENESIS_FILE PINNED_CHAIN EXPECTED_LATEST_HEAD
rld-fast-node recover JOURNAL GENESIS_FILE PINNED_CHAIN PRIOR_HEAD BLOCK_ID
```

The parent directory must already be private. Create refuses an existing path;
serve requires an independently retained latest head; keyless recovery admits no
new block and requires the exact immediate predecessor/last block. Local typed
JSON lines are bounded by2 MiB. `status`, `accept_block`, `funding_origin` and `mine`
each require `head`/`tip`; see the contract for exact fields. Mining builds its
own native template, performs at most4096 header hashes per request and retains
only an exact template-bound nonce cursor. No key/password, injected ledger or
clock override is accepted. Journal/prefix is at most256 MiB, block count262144,
default native coin limit100000 (local maximum1000000), with separate index/ledger
memory costs. Unknown/corrupt/torn data refuse unchanged; no repair/pruning or
value migration is provided. This is local native operation, not live peer
synchronization, owner/caller session control, continuous fee-solvent monitoring,
independent latest-state custody, ordinary-hardware or composed fast qualification.

The [serialized payment session](../../docs/protocol/FAST_PAYMENT_SESSION_V1.md)
adds `fast_session::Session` and a separate local executable:

```
rld-fast-payment-session create ROOT GENESIS_FILE PINNED_CHAIN
rld-fast-payment-session serve ROOT GENESIS_FILE PINNED_CHAIN LATEST_SESSION_HEAD
rld-fast-payment-session recover ROOT GENESIS_FILE PINNED_CHAIN PRIOR_SESSION_HEAD REQUEST_ID REQUEST_DIGEST
```

It owns one native selector plus a bounded key-free caller journal and private
owner/retainer actor files. Exact requests precede child mutation; verified child
heads and review digests precede response. Every cold open reexecutes native
history, authenticates complete actor custody and audits caller-to-child steps.
`wallet_create_key {head, name, password}` creates a private O13 encrypted key
using native entropy and returns its public owner address and saved path. Existing
names refuse; `wallet_key_info` authenticates an existing complete file after
restart or a lost reply. Names use1..64 lowercase ASCII letters, digits, hyphens
or underscores; at most64 entries live in the session's private `keys/` directory.
Passwords use bounded private native stdin. Neither command signs, exports a seed
or grants funds, and key-file custody does not replace latest wallet-state custody.

The private `native_wallet {head, owner, after, limit}` read lists actual ordinary
outputs for the owner's public key, up to16 per page. It returns complete-owner
native, maturity and local-reservation totals, plus input candidates for explicit
transfer/opening review. `after` is null or the previous exclusive reference;
every page needs the exact current caller head. Local preparation and signed
fee-policy reservations remain held, including after expiry or reorganization.
Other wallets' reservations are unknown. The read neither loads keys nor adds
fast-channel claims to ordinary funds. See the [session interface](../../docs/protocol/FAST_PAYMENT_SESSION_V1.md#ordinary-wallet-input-discovery).

The private `owner_state` read takes the exact session head and owner actor.
It separates retained principal and fee evidence, original pending preparation,
and conditional onward principal under actual selected native backing. Pending
invoices, closing backing and exhausted fee slots do not display a usable
principal. Reads load no wallet key, approve no spend, and preserve original
reservations and clocks. See the [owner-state contract](../../docs/protocol/FAST_OWNER_STATE_VIEW_V1.md)
for the exact observations and their local trust and availability limits.

Miner receipt-service delegation uses `delegation_prepare {tip, channel,
retainer}` followed by the normal persisted-review `onchain_sign`. Only the
funding miner's encrypted key can sign this exact current context. The reply's
`delegation.delegation_hex` can initialize the normal owner/retainer actors;
`retained_delegation {head, sign_request}` exports an existing proof after restart
without a key. Delegation does not sign principal payments or spend fee inputs,
and cannot be submitted to the native value pool.

Unsigned proposals come from the node's own native/retained owner state. Explicit
signing requires a persisted exact review reference, approved=true and a private
O13 encrypted key file; passwords are zeroized bounded native stdin inputs, never
argv/environment/HTTP/journal/log material. No raw key or serialized ledger input
is accepted. Signatures are retained before release, and keyless recovery never
first-signs or releases an owner reservation. A recovered native step retains its
actual selected branch. Caller/actor files are at most32 MiB, at most16 actors and
65536 requests; native limits remain separate. Interrupted initialization is kept
under CREATING; corrupt/torn/unknown tails refuse without repair or migration.

Control commands are `status`, `pending`, `propose` and typed `execute`; the contract
fixes their exact fields and canonical key-free action/digest bytes. The caller
must independently retain latest session heads and pending request/digest bindings.
This is local control and scoped process composition, without authenticated peer
transport, a consumer approval UI, fee-solvent continuous challenge monitoring,
independent latest-state custody, power-loss/scalable archival or composed G1-G11
qualification. Every response keeps fast completion false; existing proof alone
does not establish unseen work, current remote backing or mature miner payout.

The separate [direct peer adapter](../../docs/protocol/FAST_PEER_NETWORK_V1.md)
adds actual pinned mutual TLS1.3 data transport to that session lifecycle:

```
rld-fast-peer init PEER_ROOT PINNED_CHAIN
rld-fast-peer bind PEER_ROOT CONFIG_FILE
rld-fast-payment-session serve ROOT GENESIS_FILE PINNED_CHAIN LATEST_SESSION_HEAD --peer-root PEER_ROOT --peer-head LATEST_PEER_HEAD
rld-fast-peer recover PEER_ROOT PINNED_CHAIN PRIOR_PEER_HEAD PACKET_OR_MESSAGE_ID
```

Provision separate private transport material and explicitly admitted literal
neighbor endpoints/data keys/certificate pins; never publish generated material,
configuration or custody state. Network workers carry bounded native blocks,
invoices, existing partials, complete receipts and retainer proofs. They have no
wallet key/password or signing/approval command. Fresh signed connection binding
precedes full packet checks; durable destination custody precedes a scoped data
response, which the sender retains before suppressing retry. The bounded32-MiB
box reserves response space, retains all2048 maximum packet identities and never
prunes pending obligations or resets original queue age.

Local `peer_*` commands import received blocks through full native validation,
prepare received invoices/receipts, combine existing actual owner partials and
retain the exact existing retainer proof. Explicit owner/retainer reviews and
encrypted local signing remain separate. Consult the contract for typed commands
and public wire vectors. A last missed data head can be reconciled only from its
exact predecessor and known last packet/message identity, without new signing or
repair. Normal startup still requires the independently retained current head.
Multiple unknown transitions and all-state rollback remain unqualified. Nested
peer status accompanies local responses, including errors after a partial data
queue; multi-destination queuing is not atomic and deterministic exact retries
retain already queued bytes. Native/caller and peer heads remain separate.

For unattended data receipt, explicitly choose a fresh version2 custody store and
a private trusted head file under the [head-control contract](../../docs/protocol/FAST_PEER_HEAD_CONTROL_V1.md):

```
rld-fast-peer bind-control PEER_ROOT CONFIG_FILE TRUSTED_HEAD_FILE
rld-fast-payment-session serve ROOT GENESIS_FILE PINNED_CHAIN LATEST_SESSION_HEAD --peer-root PEER_ROOT --peer-head-file TRUSTED_HEAD_FILE
rld-fast-peer recover-control PEER_ROOT PINNED_CHAIN TRUSTED_HEAD_FILE
```

Every queue, receive and response records its exact pending transition before
journal mutation and its completed head before acknowledgment. Normal startup
fully replays the journal against that explicitly trusted input. Recovery can
finish only the already retained, fully authenticated exact transition; it never
truncates a damaged tail, resets queue age or signs a payment. The head file's
integrity/latest-state remains an explicit local trust assumption, without
independent freshness or all-state rollback protection. Legacy literal-head and
controlled storage refuse each other; no state/value conversion is provided.
Caller/native heads, approvals and monitored fee service remain separate.

The [trusted caller-control profile](../../docs/protocol/FAST_SESSION_HEAD_CONTROL_V1.md)
additionally supports fresh version2 caller state and explicitly selected
block-only background import:

```
rld-fast-payment-session create-control ROOT GENESIS_FILE PINNED_CHAIN CALLER_HEAD_FILE
rld-fast-payment-session serve-control ROOT GENESIS_FILE PINNED_CHAIN CALLER_HEAD_FILE --peer-root PEER_ROOT --peer-head-file PEER_HEAD_FILE --auto-import-blocks
rld-fast-payment-session recover-control ROOT GENESIS_FILE PINNED_CHAIN CALLER_HEAD_FILE
```

Both files are private, explicitly trusted local inputs. Exact key-free intent
preparation precedes every caller/child action, and durable audited completion
precedes response. Recovery can return a retained original signature without its
key, or resolve absence without first-executing. Incoming blocks undergo complete
native prevalidation and independent normal admission; missing parents remain for
later rounds. Other packet kinds cannot approve or sign a payment. Native changes
can invalidate pending reviews, which must never be rebased. No legacy store is
converted, and this mode supplies no independent freshness or funded fee monitor.

The [bounded fee-wallet policy](../../docs/protocol/FAST_FEE_WALLET_POLICY_V1.md)
adds explicit consent from the actual ordinary-input owner for kinds3/4/5.
fee_policy_approve retains a separate signed policy; fee_policy_prepare and
fee_policy_sign still require exact current native reviews and preserve existing
signatures, quotas and input reservations. Only named initial inputs and actual
policy-authorized change can pay fees; policy/caller/currency/channel, per-signature
and total fees, count and expiry are fixed. A retainer receipt cannot authorize
those spends. fee_policy_status {head, policy_request} distinguishes retained
signature liabilities from native inclusion/spendability. Existing proof can be
reproduced without its key and without another quota debit. Losing branches do
not refund an allowance. Policy approval starts no automatic signing or service.

The separately enabled [automatic carriage mode](../../docs/protocol/FAST_NATIVE_AUTOMATIC_CARRIAGE_V1.md)
uses `serve-control ROOT GENESIS PIN CALLER_HEAD_FILE --peer-root PEER_ROOT
--peer-head-file PEER_HEAD_FILE --auto-sync`. It carries exact already-verified
native history in bounded complete-block batches and existing signed pool data,
then independently prevalidates/adopts incoming blocks and queues signatures.
Sender-specific complete-byte knowledge avoids redundant new return carriage;
it does not acknowledge an outstanding packet or grant ledger/value rights. All
existing permanent capacities and clocks remain. `automatic_carriage` and
`automatic_native_import` status distinguish data coverage and deferred work;
complete finite service/hostile-load, independent, resource and G1-G11 qualification
remain separate. Existing `--auto-import-blocks` stays block-only.

The explicitly activated [local monitor](../../docs/protocol/FAST_LOCAL_MONITOR_V1.md)
uses `monitor_start {head, config, password}` with config `{policy_request,
key_file, operation_fee}`. A missing password selects locked observation and
keyless handling of retained eligible signatures. It protects acknowledged and
pending complete joint certificates through actual native policy preparation,
signing and pool submission. `monitor_stop {}` drops its memory-only unlock without
freeing any liability. `mining_start {head, reward}` independently enables ordinary
own-template CPU mining without actors, balances, fee policy or spending keys;
`mining_stop {}` halts it. `runtime_status {}` observes the controlled caller's
current head and both runtime states. Both services start disabled after restart;
recovery never first-signs. Local service claims/settlement remain conditional on
native inclusion and history. Automatic new-operation/block carriage, physical-
time continuity, hostile load, independent custody and composed gates remain open.

This direct ground transport does not qualify autonomous native/head coordination,
discovery or multi-hop routing, consumer consent UI, continuous funded fee claims,
independent operators/latest-state protection, physical routes, scalable archival,
mass exit or actual local latency/daily100M payment campaigns. The base consensus,
ordinary CPU mining, asynchronous interstellar carriage and all G1-G11 obligations
remain unchanged; no monetary genesis, migration or mainnet is provided.

The [native escrow action authorization](../../docs/protocol/FAST_NATIVE_ACTION_AUTHORIZATION_V1.md)
extends the same private session with `onchain_prepare` and `onchain_sign` execute
actions. Explicit ordered ordinary inputs pay close/challenge/claim/settlement
operation fees. Full native review computes change, authenticates the certificate
and checks ownership, maturity and unchanged windows before key loading. A stored
review reserves those inputs; signing requires that exact review, selected tip,
approved=true and the spending owner's O13 encrypted key. Miner-retainer delegation
alone cannot spend ordinary inputs. A complete signed operation is retained in
the caller response before release; exact keyless recovery cannot first-sign.

`exit_evidence` obtains a retained complete owner/retainer certificate without a
key, including after native close/reorganization; it grants no current backing.
`mining_candidate` takes exact current head, miner, complete operation hex strings,
canonical timestamp and attempts1..4096, builds its own current native template
and returns a candidate only. Normal native execution and peer carriage remain
separate explicit steps. All actual inclusion still verifies complete signatures,
work, state, funding, fixed2016-block/172800-second windows and h+100 miner maturity.
Cold opening replays all authorization history; process-local reuse of an already
audited immutable prefix never initializes a ledger or independent latest state.
No timeout releases pending fee inputs. Continuous funded monitoring, timely
claims/inclusion, independent custody/approval, archival/mass-exit capacity and
the original composed performance gates remain required.

The [signed native operation pool](../../docs/protocol/FAST_NATIVE_OPERATION_POOL_V1.md)
adds private `submit_authorized`, `pool_status`, `pool_operation`, `mine_pool` and
`admit_candidate` commands. Existing complete signatures are retained within a
permanent512-operation/2-MiB pool inside the caller journal. `peer_operation`
carries them as explicitly versioned kind6 data; `peer_pool_submit` is a separate
local retention decision, and `peer_block` sends exact retained native evidence.
Peers cannot approve owners or choose a trusted caller head.

Own-template mining checks complete native rules for each selected operation.
Missing dependencies/conflicts are deferred without deleting data or resetting
local age. A candidate is not admission; its exact digest supports ordinary
native-request recovery after a lost response. Selected inclusion is conditional
and can disappear on reorganization. Restart fully checks native/caller history;
pending pool recovery only retains existing signatures and never loads keys.
All current journal/capacity/window/maturity bounds and composed qualification
requirements remain unchanged. This is no-value component functionality, not an
automatic monitored payment service or an achieved throughput/latency claim.

The [ordinary native transfer control](../../docs/protocol/FAST_NATIVE_TRANSFER_AUTHORIZATION_V1.md)
adds a typed `transfer_prepare` execute action with exact selected tip, owner,
ordered inputs and outputs, fee, expiry and evaluation timestamp. It fully checks
the actual native ledger before returning a review; outputs include explicit
change. Normal `onchain_sign` then requires that persisted review, approved=true
and the spending owner's encrypted key. C04 bytes and signature domains remain
unchanged. `submit_authorized` can retain the existing signature for pool mining
and peer carriage. These steps never bypass native admission.

Transfer and escrow preparations reserve the same ordinary inputs against each
other, including across failed approval, restart and reorganization. Keyless
recovery cannot first-sign. A genuine ordinary transfer can fund a retainer's own
claim fees, which still require its own spending authorization; delegation alone
cannot spend user/miner funds. This does not provide joint funding, continuous
solvent monitoring, independent custody/operations or composed capacity claims.

The [joint opening controls](../../docs/protocol/FAST_NATIVE_OPENING_AUTHORIZATION_V1.md)
construct the existing kind1 escrow from ordinary native funds. `opening_proposal`
uses typed owners, amounts, rates/slots, fees, expiry and actual input references.
It computes change and returns exact unsigned bytes without signing/reserving.
Each party separately executes `open_prepare` with its own index and timestamp,
reviews both sides and reserves only its own inputs. Normal explicit
`onchain_sign` retains its65-byte partial before release; neither party supplies
the other's key. Ordinary transfer and escrow reservations still exclude reuse.

`peer_opening` carries the retained proposal/partial as versioned data.
`peer_open_prepare` is an explicit local review, and `peer_open_combine` requires
the received proposal to match the local one before combining existing signatures.
Equivalent private `open_combine` execution is key-free. A short durable reply
binds its complete retained proposal/signature closure, so a maximum64-input
opening needs no larger caller reply. `submit_authorized` accepts that verified
complete closure and refuses a single partial. Normal pool mining and native
admission still authenticate both owners and all current value rules.

Exact recovery cannot first-sign or free inputs. Cold startup replays native and
caller histories and checks every own/partner signature. A completed historical
opening is data, while current backing remains conditional on selected history.
These interfaces supply no continuous solvent monitor, autonomous latest-head
custody, consumer consent UI, independent operations/security, scalable archival/
mass exit or composed local-latency/daily100M qualification.

The [first-use composition](../../docs/protocol/FAST_NATIVE_OPENING_AUTHORIZATION_V1.md#first-use-composition)
connects these interfaces from mature ordinary inputs through actual funding
transfer consent, independently signed joint opening, own-template native mining
and automatic peer import, then owner/retainer registration and fast forward/
onward payment. The live-payment reproducer starts its first-use case with empty
PoW blocks only; funding/opening signatures are produced through the private CLI.
Initial setup and native inclusion have separate clocks from funded fast use.
Scripted no-value consent and logical mining history do not qualify consumer UX,
physical-time maturity, independent operation or full payment/fee service.
