# Explicit append-only trusted caller-head profile

This local NO_VALUE_ONLY storage profile is an explicit alternative to the
[snapshot caller control](FAST_SESSION_HEAD_CONTROL_V1.md). It preserves that
control's local latest-state trust assumption, complete caller/native/actor
authentication, original request clocks, file and directory synchronization,
and maximum trusted-file size. It grants no independent freshness, key custody,
consensus authority, monetary adoption or throughput qualification.

## Canonical bytes and bounds

All integers are big-endian. The108-byte header is magic RLDFCLG1 (8 bytes),
version:u16=1, suite:u16=1, caller_header_hash32, initial_caller_head32 and
header_hash32. The caller binding is the complete229-byte version2 RLDFSES1
header hash, including its unique random instance. Zero bindings/heads refuse.
Header hash is SHA256 of RLD-FAST-SESSION-1/CONTROL-LOG-HEADER, a NUL byte, then
the preceding76 header bytes. This checksum is local metadata, never ledger
initialization or a substitute for independently retained latest state.

Each record is a4-byte length177 followed by kind:u8, index:u64,
previous_record_hash32, caller_head32, request_id32, original_at:u64,
canonical_intent_digest32 and record_hash32. The first record's predecessor is
the header hash. Record hash uses the same domain prefix with CONTROL-LOG-RECORD,
then the preceding145 record-body bytes. The intent digest uses
CONTROL-LOG-INTENT over the existing typed canonical Intent JSON (id, action,
at). The complete Action includes its exact public key-file path but never a
password or raw key. Canonical intent remains bounded by1048507 bytes. IDs and
digests are nonzero; clocks cannot decrease, indices advance exactly once and
every predecessor/record digest must match. Unknown versions, kinds, lengths,
extra bytes and incomplete records refuse unchanged.

Kind1 prepares one exact request while retaining the committed caller head.
Kind2 completes that same ID, time and digest, with its fully audited caller
head. There is at most one pending request. A second preparation or unmatched
completion refuses. An unused preparation may complete at the unchanged head
only after full unchanged-state audit; a checksum alone cannot justify this.

The file retains all records and has the same1048651-byte maximum as snapshot
control. Each complete request consumes two181-byte records. Before any caller
intent or child action, admission reserves both records. A fresh log therefore
holds at most2896 complete requests, including native admissions, policy steps
and unsuccessful requests that receive durable replies. At capacity, new
preparation refuses without changing the log or caller. There is no compaction,
truncation, automatic rotation or conversion. This finite operating horizon is
not sufficient for indefinite service or a daily100M claim; scalable archival
and safe latest-state succession remain separate engineering obligations.

## Durability, execution and recovery

The private file and its separate32-byte path.lock binding are held under
exclusive actual-file locks. Every operation checks private paths, current
device/inode identity and length, the complete retained prefix and lease bytes.
Any path.next residue refuses rather than being interpreted as this format.
Cold startup checks the whole log; process-local prefix knowledge never
initializes native money. Same-byte replacement of a live inode violates the
lease, while a cold open alone cannot detect rollback of all trusted state.

Preparation is appended and both file and parent directory are synchronized
before caller.begin. After the complete caller intent is durable, its canonical
digest, ID, clock and prior head are checked against the preparation again
before any child work or key load. Ordinary execution retains the actual native
or actor effect and reply. Completion then appends and synchronizes file and
directory before response release. Both pairs of existing control-observation
boundaries correspond to their respective durable append; no .next rename is
performed by this format. Failed writes/synchronization suspend the live writer.
Torn tails refuse on restart and are never repaired or discarded.

Normal opening requires a completed log and full native/caller/registered-actor
replay. Recovery holds the log lease, verifies the binding and original clock,
then distinguishes an unchanged caller from exactly one retained prepared
request. An unchanged caller must pass its ordinary complete audit before
clearing only unused preparation; an extra unprepared native effect refuses.
A retained request must match the trusted canonical digest, ID, prior and time
before ordinary keyless recovery. A durable child is audited; missing work is
resolved without first execution, first signature, key loading, replacement
owner intent or release of a reservation. Only a fully audited recovered caller
head may complete the pending log. Existing signed-operation liabilities,
native2016-block AND172800-second dispute windows and h+100 miner-fee maturity
remain unchanged.

## Explicit interfaces

The library exposes Session::create_log_controlled, open_log_controlled and
recover_log_controlled with the same arguments as their snapshot counterparts.
The CLI entry points are:

```text
create-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE
serve-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE
recover-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE
```

Serving optionally accepts the existing pinned peer/head arguments and
--auto-import-blocks or [--auto-sync](FAST_NATIVE_AUTOMATIC_CARRIAGE_V1.md).
Status identifies caller_head_control=TRUSTED_FILE and
caller_head_storage=APPEND_ONLY. Snapshot control identifies storage=SNAPSHOT;
its explicit entries refuse log files and log entries refuse snapshot files.
Neither interface converts legacy state or changes a caller identity. Use
fresh no-value roots rather than migrating value or failed fixture state.

Full product security, cross-device/power-loss custody, independent latest-state
protection, long-history/resources, mass exit and composed G1-G11 remain open
requirements independently of this storage mechanism.
