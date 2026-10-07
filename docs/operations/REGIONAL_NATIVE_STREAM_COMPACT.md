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
