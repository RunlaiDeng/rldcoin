# Native ground archive publication and synchronization

The ordinary contact mesh uses `RLD-NATIVE-CONTACT-STORAGE-V1` for immutable
archive file publication, mutable state/index file publication and retained
file/directory synchronization. Rust owns these filesystem operations; Python
continues to authenticate complete mesh state and select bounded archive
admission. The [native shared-frame codec](NATIVE_CONTACT_STATE_CODEC.md) checks
packing and reconstruction before ordinary `Node.save` supplies complete canonical index bytes to
native publication; its callers retain their existing complete authentication.
`interstellar_storage_reference.py` retains the independent Python syscall
implementation for explicit tests. Native failures never select it as a fallback.

## Bytes, bindings and bounds

The typed local `rld_contact_storage` ABI carries canonical control JSON and a
separate immutable payload pointer. Archive control binds the independently
configured absolute path, exact payload length and whole SHA-256. Rust compares
the actual bytes before writing. Payloads retain the existing 64-MiB mesh-file
ceiling; they are not base64-expanded through JSON. Control is separately bounded
by 3 MiB. Every returned buffer is freed exactly once by the existing native
buffer release function. The library and node implementation identities must
match. A rejected payload does not cause an oversized pointer to be read.

One synchronization call admits at most 520 distinct retained paths, the original
`2 * (256 messages + 4 packet batch)` bound. Files keep dependency-before-wrapper
order. Each distinct file is synchronized, then every distinct parent directory;
there is no cross-call synchronization witness. The caller still checks the
4,096-file/256-MiB archive inventory, staging headroom and complete signed bytes.
This interface does not raise state, transport, archive or ledger capacity.

Synchronization retains Rust `File::sync_all` for files and directories. On
Apple targets, [Rust's implementation](https://github.com/rust-lang/rust/blob/1.98.0/library/std/src/sys/fs/unix.rs#L1325)
uses `F_FULLFSYNC`; it is not interchangeable with the Python oracle's `fsync`
timing. Stronger platform flushing remains in the native path. Neither a syscall
result nor a same-host interruption test establishes independent power-loss
custody qualification.

## Publication and failure custody

New parent directories use `0700`; new staging files use exclusive creation and
`0600`. Parent directories are opened with no-follow, directory and close-on-exec
flags. File operations use their retained directory descriptor, reject symlink
files and require regular files. A random `.archive-write-` staging file receives
the complete bytes, followed by file and directory synchronization. A hard link
publishes the immutable target without overwriting it. An existing target must
contain the exact complete bytes; its inode is retained.

The retained target and directory are synchronized before success. Disposable
staging is then removed and the directory synchronized again. Cleanup failure
also refuses success; when both operation and cleanup fail, both are reported.
Published targets are never removed by cleanup. Process interruption retains the
prepared file or published target and staging residue, which continue to consume
the original archive inventory. An orphan never authenticates the index or
authorizes progress. Every receipt still depends on actual complete authentication
and successful local custody in the ordinary caller.

Missing files, collisions, unsafe paths, write/link/synchronization errors and
malformed or lost native responses prevent a custody acknowledgment. A lost
response may leave exact durable bytes; later complete authentication and actual
synchronization are required again. Digest equality, file availability and native
operation results grant no ledger, signing, finality, maturity, spendability,
refund or independent freshness rights.

## Mutable state and index publication

`AtomicWrite` binds the independently configured absolute target, complete bytes,
length, SHA-256 and caller byte limit. The native limit cannot exceed the existing
64-MiB ceiling. Ordinary nodes use the full existing limit; an explicitly smaller
caller bound can only refuse more bytes and cannot change ledger/profile rules.
The caller's OS lock still serializes complete state validation and publication.
Temporary `.write-` files use exclusive creation and `0600`; new parents use
`0700`. The file and directory are synchronized before replacing the configured
target directory entry, then the directory is synchronized before success.
Replacement does not write through a final symlink to another file.

A pre-replacement failure leaves the old target. A post-replacement failure or
lost result reports failure and retains the installed target; it never rolls
back the index or acknowledges custody. Cleanup touches only this call's
disposable temporary file, never a retained target or old interrupted residue.
An interrupted temporary file cannot authorize state; cold startup still requires
complete authentication of the selected index and every referenced archive.
The production ABI exposes no interruption hook. Explicit tests retain Python
publication probes and separately compiled native test-process boundaries.

## Remaining migration and qualification

Contact-spool publication and inventory use the [native spool interface](NATIVE_CONTACT_SPOOL.md).
Complete mesh authentication, spool encoding,
deferred intake, outgoing scheduling, service orchestration and remaining wallet
flows still require migration. Python tests retain the syscall oracle and explicit
reference interruption probes. Native unit tests inject failures or terminate a
test child at selected boundaries; the production ABI has no fault or crash knob.

Same-host process tests do not establish power-loss, cross-device or independent
custody. Long history, sustained full fault profiles, cryptographic adoption,
physical routes and mainnet remain separate gates. Changed native source requires
a fresh signed no-value genesis; old value, custody and stopped failure stores
are never migrated or reopened for replacement qualification.
