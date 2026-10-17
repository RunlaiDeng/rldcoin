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
wallet and control entry below preserve its authority boundary; relay and remaining
operations require further integration.
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
PRIVATE_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID` opens one private no-value store.
Supply the exact 85-byte test genesis and its independently chosen pin. No genesis
is obtained from a directory service. Control requests are bounded JSON lines on
native stdin and responses are JSON on stdout. This is an engineering CLI, not a
consumer download or a public HTTP signing service. All API integers are decimal
strings and byte fields are lowercase hex. Do not put passwords in shell arguments,
command history, environment variables or logs; only secure local stdin integration
may supply the password field. Key files are encrypted and created at fresh paths.

The entry exposes `node_status`, `get_object` (blocks), `accept_block`,
`submit_transaction`, `review_transfer` (exact `unsigned_hex`), `sign_review`,
`operation_status`, `wallet_state`, `waive_reservation`, `changes_since`,
`set_mining` and `create_key`. Start with mining disabled; explicitly enable it with
a valid public reward key. Optional mining uses actual local time and the normal
validator with no peer-count prerequisite. Unknown revision cursors require resync.
The stdin control stream must remain open while the process runs.

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

This stage does **not** yet satisfy the complete operations contract: ordinary
contact synchronization/relay, full transport receipts, complete inclusion/reorg
status history, detached-transaction reoffering, whole-wallet backup/restore with
freshness policy, fault injection at every publication boundary, consumer packaging
and independent/physical qualification remain required. `relay: NOT_IMPLEMENTED`
is an explicit status, never an assertion of an active interstellar connection.
