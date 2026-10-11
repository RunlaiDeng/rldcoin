# Incoming custody and ordinary carriage notification

The ground TCP adapter may notify its existing outgoing owner when a successful
transport operation adds a new fully authenticated active packet ID. Compare only
bounded retained IDs under the original Mesh lease. Notify after the operation,
durable close and lease release all succeed. Receipt-only changes, repeated IDs,
failed bodies, writes, signatures or closes do not request another pass.

Incoming and outgoing owners remain independent. Either callback may be absent;
callback failure retains the original diagnostic counter and periodic fallback.
The existing single outgoing worker merges notices, preserves its minimum start
interval, original pinned-neighbor rotation and contact slots, and finishes an
active pass before beginning another. A notice does not preempt peer selection
or a socket, retain an extra input, start another worker or authorize a receipt.

The same boundary covers handler, deferred-input and authenticated reply custody.
Every request still binds its fresh challenge and exact prepared exchange; every
reply needs complete authentication and actual local durable custody before hop
suppression. Native intake and validation retain their separate original limits.
Restart uses the original retained evidence and cold checks; optional notices do
not survive as a recovery cursor.

A wake does not establish a connection, delivery, ledger acceptance, finality,
maturity or onward spendability. Signed transport models and same-host fixtures
do not qualify latency distributions, sustained faults, independent custody,
physical links, long history or an adopted network.
