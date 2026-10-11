# Native BFT companion archive custody

The ordinary and complete-origin companions delegate existing archive reads and
publication to Rust. The disk contract remains
`RLD-REGIONAL-BFT-RETENTION-V2`: a typed runtime index and shared exact snapshot
bytes. Python still prepares its in-memory mapping and drives scheduling,
lifecycle and transport. Joint-epoch and role-slot workflows remain separate;
native refusal never invokes a fallback writer for the migrated profiles.

## Bounds and exact bytes

The combined archive remains at most 32 MiB, with 512 messages and at most 64
ordered references per envelope, including at most four origin-history proofs.
Every complete expanded envelope remains within the existing 3 MiB wire bound.
Every pool entry binds its exact complete canonical bytes by SHA256. Multiple
references and their order remain intact; no pool entry can be missing, changed
or orphaned. Body identity, whole-envelope digest, size, value metadata and local
carriage flag remain separately retained. Rust reconstructs one bounded envelope
at a time. Stored JSON uses the existing sorted ASCII encoding, including float
and Unicode rules. Legacy inline archives refuse without conversion.

Only the dedicated private companion archive reader/encoder uses the existing
32 MiB archive bound. Ordinary native JSON, ledger/evidence operations and wallet
caller files retain their 8 MiB bound; transport capacity does not increase.
The archive directory also counts all retained filesystem objects, including
interrupted publication residue and active input files, under 4,096 objects /
256 MiB. Admission reserves the complete new temporary file before writing.
Links and special objects refuse; over-capacity state remains retained without
pruning. A structural byte check never makes a snapshot or decoded object ledger authority.

## Read and publication interfaces

`bft-runtime-archive-read --state-dir PATH --expected-key KEY --runtime-format
FORMAT` validates existing private bytes under the companion archive lock and
returns a bounded byte receipt. It checks currency/region/key/runtime binding and
that the retained height/tip names a fully native executed prefix. The receipt
requires full cold authentication; it does not declare the archive's messages
cryptographically accepted. The companion binds its local read to the returned
whole digest before performing the original complete native cold checks on every
reconstructed envelope. A changed read, incomplete proof or bad later envelope
refuses before signing or adopting a runtime.

`bft-runtime-archive-store` additionally takes `--file PATH` and, for an existing
archive, `--expected-state-sha256 HASH`. The input contains one complete proposed
wrapper. The expected digest must match actual retained bytes under the lock.
Fresh initialization requires an absent archive and explicit empty state; a
missing head is not inferred from an observed archive. Existing envelopes,
shared bytes and value metadata cannot be replaced or deleted. A local carriage
flag may only advance from false to true. Height observations cannot roll back.
Each added envelope or local promotion undergoes complete normal native evidence
and body authentication before publication, including its value metadata.

The native ledger opens through inspection without incident reconciliation.
Private files and locks use current-owner private permissions, no-follow access
and single-link state/lock files. The archive directory remains separate from
the native ledger; the companion configuration also retains separate signer and
caller directories. Publication writes and fsyncs a private temporary file,
renames it and fsyncs the archive directory before returning. Failed publication
residue remains unadopted. The original native signer response and independent
caller outbox remain available after archive failure or response loss; restart
fully rechecks them and retains the exact original message before clearing the
outbox. No archive acknowledgment is a transport, recipient or finality receipt.

## Qualification limits

The independent Python codec and public no-value native fixtures remain available
for byte comparison and refusal/recovery checks. The archive contains no decoded
ledger, private key, signer lock or caller head that can initialize native state.
Its receipts carry neither ledger mutation nor signing authority, and always
require whole cold authentication. Archive custody does not qualify independent
freshness, all-state rollback protection, copied-key custody, power loss,
long history, sustained faults, reconfiguration, physical routes or mainnet.
A changed native source requires fresh signed no-value fixtures; the unchanged
encoding never authorizes reopening a historical failed fixture or migrating value.
