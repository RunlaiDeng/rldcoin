# Adjacent carriage preparation

The ground TCP scheduler keeps one outgoing owner and one socket at a time.
After a complete reply passes the existing connection, exchange and signature
checks, its local receive still authenticates and durably retains the complete
bytes. Within that same opened mesh operation, the owner may prepare only the
next neighbor already selected for this pass. The operation must close
successfully before those prepared bytes can be used for a new connection.

This scheduling step removes an intervening mesh reopen. It does not reuse a
decoded ledger or grant custody from a remote reply. Original mesh receive,
preparation, retry rotation, pinned endpoint/TLS policy and Native validation
remain mandatory. Socket waits hold no mesh lock. Every connection gets its own
fresh challenge and original attempt clock after its preparation is durable.

Only one process-local adjacent exchange is retained, as immutable canonical
bytes within `MAX_BATCH`. Current request objects are released before that
exchange is retained. Its configured peer, attempt, retry IDs and carriage
domain belong to this pass only. A failed preparation records a detached
refusal without retaining the opened Node or its traceback. A failed lease
close invalidates the prepared bytes. Failures preserve original packet/retry
evidence and do not suppress delivery or authorize a connection.

An independently failed next preparation does not revoke the prior reply's
already durable custody. Suppression for that prior exchange still follows
successful mesh close. A stop during preparation prevents a new connection;
the begun attempt remains a refusal with its retry evidence. An unattempted
later neighbor is not allocated a slot. Neighbor rotation and the existing
`MAX_OUTBOUND_PER_TICK`, `MAX_WORKERS`, wire, receipt, lock and socket bounds are
unchanged. No worker, socket, ledger admission or signing capacity is added.

Peer-attempt observation starts at preparation, which may overlap the prior
peer's local reply operation. This describes scheduling work, never concurrent
sockets, finality or recipient spendability. Cold state fully authenticates
again; no adjacent token survives a pass or restart. This remains ground
candidate behavior. Physical contacts, independent custody, complete value
flows, sustained faults and regional latency cohorts require their own
source-bound qualification.
