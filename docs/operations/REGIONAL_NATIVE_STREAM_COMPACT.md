# Compact read-only native stream archive candidate

The separate `RLD-NATIVE-STREAM-COMPACT-V1` disk codec omits only repeated
currency/region fields from complete block headers and owner intents. Its first
canonical record binds the exact caller-pinned, natively verified currency,
region and complete admission trust binding. Every later record reconstructs
the original native block and ordered owner approvals before the existing
genesis-derived stream cursor executes it. Header work, parents, command/state
roots, owner signatures, conservation, maturity, permanent imports, checkpoint
and dependency authentication remain mandatory. Packing is not validation.

Evidence stays complete. There is no ledger/cache initialization, predecessor
inference, peer dictionary, compression library or omitted signature. The old
complete-record archive and compact archive refuse each other's formats; no
fallback or ordinary-store conversion exists. Compact and expanded records both
remain below 8 MiB; the private, singly linked archive remains at most 256 MiB.
The shared file reader retains bounded line allocation, complete-tail validation,
read-only file checks and the caller's separately retained exact head. Noncanonical
records, extra fields, repeated/missing bindings and domain changes refuse.
Unix opening additionally refuses replacement symlinks and uses nonblocking open
before checking the actual regular-file identity, avoiding a substituted FIFO
wait between initial metadata inspection and opening. Normal private file reads
remain complete and read-only.

`history-stream-compact-check` runs before ordinary Store opening and reports the
same explicit limitations as `history-stream-check`: no ledger adoption,
wallet/signing custody restoration, incident/quarantine reconciliation,
independent latest-state assurance or ordinary-node upgrade. Initial unanimous
PoW only; BFT and local epoch handoff refuse. Active observations stay at 256,
exact verified checkpoint anchors at 64 and permanent maps at 4,096. Full native
replay CPU remains required. No bound is raised or evidence pruned.

This changed native source needs a fresh signed no-value fixture genesis/currency
and new private directories. Prior successful and failed sources, value,
caller heads and custody remain untouched. Native regression/strict checks and
actual beyond-era owner-payment/late-import archive replay are pending. Codec
implementation alone does not qualify I10, ordinary long history, BFT recovery,
independent operations, cryptographic horizons or physical interstellar routes.

`stream-fixture --bootstrap <fresh-public-fixture> --root <new-private-root>
--payments <1..200000>` constructs an exact new no-value sample with native
owner signatures and per-transition conservation. Early ordinary unanimous
checkpoints authorize Earth export and Proxima's new return; the stream records
hold the return unimported during the requested local payments, then natively
import, mature and actually pay it. This is a generated read-only archive,
not ordinary node lifecycle, late onward-export authority or issuance-era rules.
The helper never reads private wallets/keys or opens signer custody. An interrupted
root and its GENERATING marker are retained and cannot be reused. Private head
and construction report appear only after full construction and archive fsync;
the directory is synced before completion. Separate complete cold replay and
separately retained head binding are mandatory and are not claimed by generation.

The initial 376-file freeze is retained without execution. A separate 376-file
retry1 freeze adds the complete expanded-capacity regression and Unix safe-open
checks: source set `14e769a2bf116fffc191d4e7d4406c980f36937bd514ccc1e30a01e13c88e594`,
Native implementation `add6b34954bee1bbf0d8e2c94e87f056181535a63771a28fed7551f3a9a094da`.
Exact driver build passed in 39.198 seconds, scoped formatting in 0.097,
full strict checks in 13.912 and all 178 Native cases in 240.159 seconds.
All five new codec cases passed, including complete record identity, binding,
altered signatures/tails, compact/expanded bounds and BFT refusal. Core and Python
companion bytes are unchanged; Native tests were actually rerun. The full 454
process checks, three actual custody cases, small actual CLI sample and long
archive sample remain pending. This new source does not qualify revision-45's
failed ordinary fault state or migrate its old currency/custody.

The complete checker then passed: all 454 process cases in 262.813 seconds,
three actual Runtime custody cases in 3.209 and the actual small CLI sequence in
0.558. Frozen checks（历史证据保留于本地归档）
bind driver `4a2c9673394522186b1f2c7abbce2413c1553f71418a391323212dde80dc790e`
and fresh no-value currency
`b43f54f541b17036ff4b7b45044f42761219128478a1cd1b3e866b578ce26cde`.
The actual small CLI sample（历史证据保留于本地归档）
generated 33 owner payments/41 native blocks in 0.419 seconds, a 52,095-byte
archive, then completely cold-replayed genesis/every block in 0.018 seconds.
Wrong head, old codec, truncated tail and existing root all refused. Private
bytes/permissions stayed unchanged and the requested ordinary Store directory
was never created. This is a small generated read-only fixture only.

The separate 200,000-payment construction and complete cold sequence has now
actually started with this exact source/binary and a fresh private fixture.
Its final height/bytes/payment/conservation result remains pending; neither
generation progress nor the small sample establishes beyond-era or ordinary
long-history qualification. No generated archive/head/state is a public artifact.

The actual long sequence（历史证据保留于本地归档）
then passed: 200,001 owner payments and 200,009 Earth native blocks, construction
261.850 seconds and separate complete genesis/every-block cold 44.249 seconds.
The earlier Proxima new return imported at 200,006 and its mature net 59 was
actually paid at 200,009. Original debit remains spent, duplicate return import
refuses, every Native transition conserves value and final issuance 300 equals
liquid 300 with pending zero. The private archive is 192,930,821 bytes, below
the unchanged 268,435,456-byte bound. All original private files/permissions stayed
unchanged and no ordinary Store was created. These are historical nonsigning
observations, not independent freshness or recovered custody.

[Revision 46](https://github.com/RunlaiDeng/rldcoin-genesis/tree/ddedf8468f81a92d03c026d473893eb6df7fc73f/research/2026-10-04/regional-native-stream-compact-v46)
is published: all 13 reviewed remote files match exact bytes（历史证据保留于本地归档）,
including all 376 exact source-archive members. Only source and sanitized ground
reports/logs are public; the generated private archive, custody-head files,
wallet/signer/caller/transport/TLS state, keys and backups are excluded. Public
cold logs contain nonsigning historical hash observations, not private custody.
The sample crosses height 200,000 with cap exhausted in its first three blocks;
issuance-era rules, epoch/BFT/ordinary long history, late onward finality,
incident reconciliation, independent custody and physical horizons remain open.
It cannot qualify or migrate the older revision-45 failed full fault profile.
