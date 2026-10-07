# Operation-scoped retained archive custody synchronization

Candidate for Python ordinary contact scheduling; Native/Core, signatures,
archive files, bounds, ledger and signing custody are unchanged. Existing failed
fixtures remain stopped and unchanged. A new exact compiled default driver and
fresh private no-value ordinary scopes are still required.

The stopped revision-41 fault observed new Commit packets retained at Proxima-2
but absent at the gateway/leaf, while active queues remained below 32. The gateway
reported 2417 local lock attempt exhaustions. These observations do not identify
one unique cause. Same-operation repeated archived receipts/transits currently
fsync shared files and the same archive directory repeatedly while holding the
local mesh lock.

Within one complete receive, every archived occurrence still authenticates its
complete index, receipt, transit and frame. Only then may its exact retained file
paths enter a bounded private operation-local set. Flush every distinct file and
every containing directory before publishing the updated state or returning a
custody acknowledgment. Duplicate shared paths need one actual fsync in that
operation. No result or set survives success, rejection or exception; standalone
sync_archive still immediately fsyncs its files and directories. Changed bytes,
future receives and cold startup retain complete authentication and actual sync.

The set refuses above twice the existing message-plus-transit batch capacities.
Network, receipt, archive, history, local lock and socket bounds are unchanged.
A file or directory fsync error prevents publication/acknowledgment; a later
invalid transit cannot turn earlier collected paths into custody. No digest,
metadata, cursor or synchronized directory grants ledger/signing/value authority.
