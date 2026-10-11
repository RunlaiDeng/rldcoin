# Native ground archive publication and synchronization

The ordinary contact mesh uses `RLD-NATIVE-CONTACT-STORAGE-V1` for immutable
archive file publication and retained-file/directory synchronization. Rust owns
these filesystem operations; Python continues to pack and authenticate complete
mesh state, select bounded archive admission and commit the signed index.
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

## Remaining migration and qualification

Mesh state packing/replay, signed index publication, contact-spool publication,
deferred intake, outgoing scheduling, service orchestration and remaining wallet
flows still require migration. Python tests retain the syscall oracle and explicit
reference interruption probes. Native unit tests inject failures or terminate a
test child at selected boundaries; the production ABI has no fault or crash knob.

Same-host process tests do not establish power-loss, cross-device or independent
custody. Long history, sustained full fault profiles, cryptographic adoption,
physical routes and mainnet remain separate gates. Changed native source requires
a fresh signed no-value genesis; old value, custody and stopped failure stores
are never migrated or reopened for replacement qualification.
