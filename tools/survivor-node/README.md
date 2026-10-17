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
follow C01-C11. The local coin budget refuses without changing the tip. This initial
kernel clones the current UTXO map per candidate and rebuilds its ordered root;
large-owner throughput and cold-history resources require measurement. There is no
consensus height checkpoint or history-length cap. Missing history remains a wait.

The arithmetic and cryptographic codec are adapted from the same-author public
vector oracle. Differential fixture agreement is useful engineering evidence, not
an independent validator, security audit, durability or full-node qualification.
The kernel alone does not supply the full O01-O13 lifecycle. The native storage,
wallet, control and contact entries below preserve its authority boundary.
Actual interstellar adapters, long-horizon custody and monetary adoption remain
separate mandatory gates in the acceptance plan.

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
PRIVATE_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID [CONTACT_CONFIG]` opens one private no-value store.
Supply the exact 85-byte test genesis and its independently chosen pin. No genesis
is obtained from a directory service. Control requests are bounded JSON lines on
native stdin and responses are JSON on stdout. This is an engineering CLI, not a
consumer download or a public HTTP signing service. All API integers are decimal
strings and byte fields are lowercase hex. Do not put passwords in shell arguments,
command history, environment variables or logs; only secure local stdin integration
may supply the password field. Key files are encrypted and created at fresh paths.

The entry exposes `node_status`, `get_object` (genesis, transfers and blocks), `accept_block`,
`submit_transaction`, `review_transfer` (exact `unsigned_hex`), `sign_review`,
`operation_status`, `wallet_state`, `waive_reservation`, `changes_since`,
`set_mining` and `create_key`. Start with mining disabled; explicitly enable it with
a valid public reward key. Optional mining uses actual local time and the normal
validator with no peer-count prerequisite. Unknown revision cursors require resync.
The stdin control stream must remain open while the process runs.

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
lock. Persistent neighbor/class/object rotation and temporary unavailable-neighbor
backoff allow alternate admitted neighbors. Receipt observations survive restart;
hop acknowledgment never discharges a destination obligation. Returned destination
receipts may traverse a relay that lacks the original packet. The default custody
budget is 4096 packets/256 MiB including metadata. At most 256 recently completed,
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
The local storage format is now `RLD-SURVIVOR-STORE-3`; earlier candidate stores
refuse, with no automatic migration or test-value continuity.

`state_head` exports an exact local ledger/intent/custody commitment to retain
independently. `create_backup` takes a fresh destination, native-input password and
explicit `wallet_key_files` inventory. It copies complete SQLite snapshots through
the database backup API and encrypts each record, including contact/TLS secrets.
Unlisted wallet key files are not magically included. Keys retain their separate
O13 encryption. Backup staging is private; interrupted builds retain `BUILDING` and
residue. A complete snapshot uses local format `RLD-SURVIVOR-BACKUP-1`: each sealed
record binds magic `RLDSBKP1`, chain[32], random bundle[32], record-kind u16, salt[32],
nonce[12] and plaintext-length u64 as AEAD associated data, all integers big-endian.
Fixed scrypt N=32768/r=8/p=1 derives AES-256-GCM with a full 16-byte tag. Record kinds
1..5 are ledger, custody, contact key, TLS material and admitted configuration;
100..163 are explicitly listed encrypted wallet keys; kind 0 is the authenticated
complete inventory/genesis/head manifest. There are no archive-controlled paths.
Each record is at most 256 MiB; allow 1 GiB transient backup/restore working memory,
additional private staging disk and the encrypted image's full size.

`rld-survivor-node restore FRESH_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID BACKUP_DIRECTORY`
reads one bounded native JSON request with `password` and optional independently
retained `latest_state_head`. It verifies encrypted records and full native replay
before clearing RESTORING. Existing/interrupted destinations never overwrite or
resume. Without a matching supplied head the restored wallet reports
FRESHNESS_UNKNOWN and refuses first signing, while exact signed recovery and mining
remain possible. `acknowledge_restore_risk` requires the current `intent_head` and
explicit acknowledgment of possible conflicting signatures. This records accepted
risk; it does not establish independent freshness. Restore policy is separate from
consensus and never creates a mandatory witness for an intact surviving node.

The allowlisted Rust packager creates a deterministic tar container with the native
executable, protocol documents, license and SHA-256 inventory. CI builds separate
Linux/macOS artifacts after checks. Hashes detect byte changes; they are not an
owner-signed monetary release or evidence of independently reproducible binaries.
No keys, databases, live configurations or generated genesis are packaged.

Process interruption probes cover validation, durable intent and durable committed
ledger boundaries, including response-loss recovery. Independent power-loss,
all-state rollback/cross-device custody, sustained ordinary history beyond an
issuance era, independent security/validator review, complete consumer qualification
and physical interstellar adapters remain distinct unqualified gates.
`ACTIVE_GROUND_ADAPTER`
reports local adapter operation, never an assertion of an interstellar connection.
