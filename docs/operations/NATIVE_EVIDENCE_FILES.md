# Native evidence files and queue

Ordinary safe reads, directory creation, exclusive writes, exact retained writes,
queue receive and queue carry use `RLD-NATIVE-EVIDENCE-FILES-V1`. The original
Python syscall implementation remains an explicit independent test oracle in
`interstellar_file_reference.py`; native refusal never chooses it as a fallback.

## Bounds and frame checks

The typed `rld_evidence_files` ABI uses canonical controls up to 8,192 bytes and
separate input/output byte buffers. Generic files stay within the existing 64-MiB
state/file ceiling. Each read retains its smaller caller limit and detects growth
past that limit. This local interface does not increase any transport, payload,
ledger, archive or queue capacity.

The evidence queue retains 4,096 files and 256 MiB. Frames remain at 4 MiB plus
4,096 bytes, with at most 3 MiB of payload. Smaller caller bounds only refuse more.
Receive and carry share the same complete native opaque frame inspection as the
[frame interface](NATIVE_CONTACT_FRAME.md), including exact routes and regional
control-envelope bindings. Every later input is checked before queue success;
queue existence or a filename never authenticates a frame.

## Descriptors, admission and failures

Operations retain no-follow directory/file descriptors. Reads require regular
files and use nonblocking opens before metadata checks so a FIFO cannot substitute
for a file. Directory symlinks refuse. Missing paths and OS failures remain typed
IO errors; malformed or unsafe input refuses without granting rights.

Receive validates the complete incoming frame before creating a queue or taking
its regular no-follow `.lock`. The original exclusive OS queue lock is retained
until the descriptor closes on every return/error. It holds no mesh or socket lock.
Inventory admits only `.lock` and lowercase message-ID `.json` names, counts all
retained files, and never removes unknown, corrupt or interrupted evidence.

Exclusive publication keeps the original direct public-name visibility model.
It writes complete bytes, synchronizes the file using native `File::sync_all`,
then synchronizes the retained parent directory. Stronger Apple flushing remains.
Every failure leaves its existing zero, partial or complete target in place;
there is no unconditional cleanup, overwrite, rollback, refund or acknowledgment.

An exact duplicate receive compares every actual retained byte before retained
file/directory synchronization. It remains eligible at a smaller caller capacity
without admitting another file. Corrupt same-ID bytes refuse unchanged. Exclusive
carry outputs cannot replace existing files. A lost result can leave installed
bytes; later recovery must recheck them, never infer absence or retry by replacement.

## Receipt and authority

Controls bind whole input size/SHA-256; receipts bind the exact control and current
native implementation. Returned bytes additionally bind their complete size and
SHA-256. The bridge validates those bindings before returning data or the checked
frame dictionary. Release both unchanged native buffers exactly once, including
empty results and failure payloads. Oversized input pointers refuse without reads.

Results report `ledger_authority: false` and `custody_acknowledgment: false`.
File/queue success is local byte IO, not a destination transport receipt, native
evidence authentication, finality, maturity, spendability or independent custody.
Normal native ledger/BFT/owner checks remain mandatory. Test-only failure and
process-interruption observers do not exist in production controls.

Python mesh/service scheduling, ABI assembly and remaining wallet functions still
require migration. Same-host process tests do not qualify power-loss, independent
latest-state protection, cross-device custody, full faults/load, long history,
cryptographic adoption, physical routes or mainnet. Changed native source requires
fresh signed no-value fixtures, never old-value or stopped-failure migration.
