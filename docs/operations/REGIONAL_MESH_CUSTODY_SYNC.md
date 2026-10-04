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

[Six actual component checks](evidence/regional-custody-sync-component-checks-20261004.json)
passed in 0.088 seconds with real filesystem fsync, zero Native or socket calls.
They cover unique file/parent synchronization, no cross-call retention, directory
failure, symlink/capacity refusal, fully authenticated shared archive occurrences,
failed sync without state publication and later invalid evidence refusal.
Performance, frozen related/full checks and fresh ordinary qualification remain
pending. Same-host/process observations are not power loss, independent custody,
physical links or I1–I12 completion.

Review retained the original dependency-before-wrapper fsync order explicitly.
The operation-local collection preserves first appearance and deduplicates only
repeated paths; complete file fsync precedes directory fsync and state publication.
[Seven actual ordered component checks](evidence/regional-custody-sync-ordered-component-checks-20261004.json)
passed in 0.173 seconds, including the original shared-archive dependency-order
regression adapted to the real batch boundary. The earlier six-case freeze stays
unchanged and unexecuted as an ordinary candidate. The next freeze also includes
the already tested controller public-anchor/receipt-probe fixes, so fresh fault
scopes retain their pre-start inspection anchors instead of reverting to older
unanchored controller behavior. Native/Core and ordinary bounds remain unchanged.
