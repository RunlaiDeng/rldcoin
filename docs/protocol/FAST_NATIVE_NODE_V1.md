# Native fast-node selection and local control V1

This is a separate NO_VALUE_ONLY node-storage/control candidate for
[RLD-FAST-ESCROW-1](NATIVE_FAST_ESCROW_V1.md). It does not upgrade Survivor-1,
migrate old stores/value, provide a monetary genesis or adopt a fast consensus
extension. All original native rules and G1-G11 remain mandatory. Owner/retainer
journals remain separate; a local native selector is necessary for, not a complete
implementation of, a continuously monitored fast-payment service.

## Selected native authority

Create only a new private journal from an independently supplied113-byte native
no-value genesis and its independently pinned chain ID. Normal cold open requires
that genesis/chain and an independently retained exact latest storage head.
Never adopt a head read from the same potentially rolled-back file as freshness.
The exact native genesis, every complete stored block and all branch transitions
are replayed from genesis on cold open. No decoded ledger, index, serialized tip,
state root, storage hash or selected-head assertion initializes native authority.

Admission requires an already fully verified retained parent. Missing parents
wait unchanged; no header-only or orphan block becomes selected. Every new block
executes all native header/PoW/body/signature/owner/value/issuance/resource checks.
The greatest eligible cumulative-work branch wins; equal work selects the smaller
native tip ID, using the same shared native `Tip::preferred_to` rule. Retain all
accepted losing branches, exact bodies and the original order of their admission.
A new receipt never reinstates losing rewards, escrows or owner fee rights.

The process retains one selected fully executed ledger, exact admitted block
bytes and native-derived per-block tips. Extending the selected tip may clone that
already fully verified selected ledger. Other parents are fully replayed from the
pinned genesis through retained exact blocks; no arbitrary cached ledger starts a
branch. Cold opening executes the same ordered admissions, validates every stored
selected-tip/revision result, and must reconstruct the same selected state.
Block IDs locate bytes only. A byte-identical duplicate is synchronized and returns
already_known without a new record; different bytes with the same header ID refuse.
No later envelope is authenticated by a body/header deduplication result.

Every mutating/current-state request supplies both exact expected storage head
and expected selected tip. Prefix/path/clock checks precede native execution or
mining. A single exclusive writer serializes admission and any current-state
borrow for owner/retainer use. `current` exposes that selected ledger only after
those checks. External callers can still misuse a historical raw library ledger;
they cannot qualify a current service that way. A stale or losing funded origin
must fail against this selector's own current ledger.

## Bounded private storage

Integers are unsigned big-endian. Header:

```
ASCII("RLDFSEL1")8 || version:u16=1 || suite:u16=1
chain32 || genesis113 || created_at:u64
```

Header is165 bytes; head is SHA256(`ASCII("RLD-FAST-NODE-1/HEADER") || 0x00 ||
exact_header`). Record:

```
length:u32 || index:u64 || previous_storage_head32 || admitted_at:u64
block_length:u32 || exact_complete_block || selected_native_tip32
selected_revision:u128 || record_hash32
```

Length counts bytes after itself and equals132+block_length (402..262276).
Index starts at1. Record hash/head is SHA256(`ASCII("RLD-FAST-NODE-1/RECORD") ||
0x00 || index || previous_storage_head || admitted_at || block_length ||
exact_complete_block || selected_native_tip || selected_revision`). Revision starts
at0 and advances by1 only when selection changes. These bytes are storage checks,
not substitute native authorization. Both known accepted branches and nonwinning
branches remain in the same durable hash chain. Admission times are nondecreasing
and cannot exceed the actual opening clock. Full native execution checks each
block's future eligibility under its original stored admission time.

Before accepting work, compare the entire authenticated retained prefix, length
and Unix device/inode. File and directory are private, regular/non-symlink and
protected by an exclusive OS file lock. Unsupported file-identity platforms refuse.
An actual prefix, identity or custody-read failure poisons further current-state
authority until full cold verification; a stale caller-supplied head alone does
not poison healthy storage. Append and synchronize file plus parent directory before releasing a new head or
selecting the process ledger. An incomplete/failed/ambiguous write poisons further
mutation; preserve bytes unchanged. No tail truncation, pruning, overwrite,
automatic repair/migration, or rolling back to a passing old branch is provided.

Caller limits are fixed for that open instance: journal/prefix maximum256 MiB,
accepted block count maximum262144, native coin entries maximum1000000. The exact
block index may retain another copy of admitted bodies (up to the same byte bound),
and native-derived tip/index/ledger memory is separate. A full limit refuses before
append without releasing existing obligations; a peer cannot enlarge it. Full
prefix comparisons and replay have real costs; this is not ordinary-hardware,
long-history or daily-capacity qualification.

Keyless `recover` handles exactly one ambiguous appended block: caller supplies
the independently retained immediate predecessor storage head and exact expected
full-block ID. Full cold replay must find precisely that final record. It returns
the already retained selected tip/revision and new storage head after sync, never
first-admits another block or selects a caller-supplied branch. Missing/truncated
records refuse unchanged. Common/all-state rollback and independent latest-head
custody still require separate qualification.

## Serialized local node

The separate `rld-fast-node` executable has these entry points:

```
rld-fast-node create JOURNAL GENESIS_FILE PINNED_CHAIN
rld-fast-node serve JOURNAL GENESIS_FILE PINNED_CHAIN EXPECTED_LATEST_HEAD
rld-fast-node recover JOURNAL GENESIS_FILE PINNED_CHAIN PRIOR_HEAD BLOCK_ID
```

All use the actual local system clock and accept only a fresh no-value native
genesis. `create` refuses an existing path; `serve` retains the exclusive writer
through its bounded local stdin/stdout lifecycle; `recover` is keyless and appends
nothing. The control channel is local, not a public network/signing socket.
Every newline-delimited JSON request is at most2 MiB and has a typed method and
explicit expected storage/selected heads. The node accepts no keys, passwords,
wall-clock override, serialized balances or injected ledger state.

Methods are `status`, `accept_block`, `funding_origin` and `mine`. Hex values are
lowercase. Fields `head` and `tip` are32-byte hashes on every request.
`accept_block` adds `block` (complete hex). `funding_origin` adds `channel`.
`mine` adds `miner`, `operations` (at most128 complete operation hex strings),
`timestamp` (canonical unsigned decimal string) and `attempts` (1..4096). It builds
a native template, retains only an exact selected-tip/miner/operations/time-bound
process-local nonce cursor and executes actual CPU header hashes. Timestamp is a
proposed block timestamp subject to unchanged native rules, never a local clock
override. Bounded search returns SEARCH_PENDING or a fully executed durably
admitted block. There is no remote template provider, account or starting balance
requirement. No progress/operation completion is inferred from a hash count.

Responses bind selected tip/root/work, revision, storage head, actual observation
clock and explicit errors. Funding queries derive the current native context from
that selected ledger; historical origins do not become current after a reorg.
A storage/native-head mismatch suspends the requested action; no silent rebase.
No local result claims unseen global work, irreversible finality, current remote
receipt, monitoring coverage, native claim inclusion or miner payout. Live peer
synchronization, durable owner/caller sessions, fee-solvent timely monitoring,
ordinary-hardware/independent custody, mass exit and composed G9-G11 campaigns
remain required for a complete fast-payment product. Ordinary Survivor-1 mining
and asynchronous stellar carriage remain separate and unchanged.
