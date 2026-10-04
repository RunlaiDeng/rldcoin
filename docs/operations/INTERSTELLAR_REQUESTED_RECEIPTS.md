# Requested and historical receipt carriage candidate

The private identity/state binding `RLD-CONTACT-RECEIPT-SCHEDULER-V2` reserves
half of the unchanged 16-receipt exchange for exact IDs present in the configured
peer's authenticated signed inventory, and half for historical reverse routes.
Each class borrows otherwise unused slots. Complete signed receipt/routing bytes
remain unchanged. Inventory requests select transport only, never custody,
native acceptance, spendability, refunds or authority.

The existing `receipt_cursors` now advances only actual historical selections.
A separate `requested_receipt_cursors` advances only actual requested selections.
Both maps have at most 16 configured peers and unsigned bounded 63-bit positions;
actual advancement is durable before TCP/spool I/O, including failed sends.
Public exchange construction and other peers/ticks advance neither cursor.
Removed peers forget only cursor metadata. All receipts and unreceipted packets
remain retained. Combined state still refuses above 64 MiB.

Alternate the first class using the parity of the two durable actual counts,
then interleave the selected classes. Trimming to a tightened wire bound counts
only complete actually carried receipts. Even a one-receipt batch alternates
classes. Keep four transits, the normal outbound/receive/signature budgets,
fresh TLS/nonces, full per-receipt authentication and repeated archive fsync.
No evidence is suppressed or removed by the classification.

V1 identities/states refuse unchanged. A forged V2 marker without its complete
new schema also refuses. Use fresh no-value transport directories/keys/pins;
no state, value or custody conversion. Strict stopped inspection binds both
cursor key sets to externally retained exact contact configuration.

A stopped five-carrier inspection found one neighbor had 32 requested IDs among
271 eligible receipts but only one match in its next static 16-receipt batch.
That observation does not reconstruct prior scheduling or prove the unique
ordinary-cycle failure cause. Fresh fixed-pool selection/rotation, persistence
failure, capacity, old-schema refusal and one-receipt fairness checks are separate
from fresh ordinary Native/payment, full fault, changing topology, independent
custody, power-loss and physical-link qualification.
