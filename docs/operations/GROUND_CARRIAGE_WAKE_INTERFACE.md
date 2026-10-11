# Bounded ordinary carriage wake

The regional ground companion retains one outgoing Worker and the existing
pinned TCP adapter. An ordinary carriage Mesh operation may notify that Worker
only after newly retained exact packet IDs, normal Mesh close and ordinary lease
release. Comparing bounded ID sets does not inspect or authenticate a new body;
all normal Native and transport authentication remains required. A repeated
unchanged ID inventory, failed write, failed body or failed close does not notify.
A fresh packet nonce is a distinct packet, even if its complete frame repeats.

The notification is one process-local Event, not a packet queue or custody
acknowledgment. Notifications merge; one arriving during a pass remains pending
for the next pass. Awakened pass starts respect `MIN_WAKE_INTERVAL` in the
[Worker source](../../tools/regional_carriage_worker.py), the existing minimum
ground Worker interval. Without a notification, the configured
polling interval still follows completion. Original per-pass peer, packet, wire,
retry, lock and socket bounds are unchanged. An early pass cannot skip or remove
retained evidence, alter first-offer fairness, lower quorum or grant signing.

Only the registered outgoing owner receives a callback. Owner release clears it.
Closing wakes an idle wait but retains ownership until in-progress local work
finishes; the current socket-stop and durable retry rules remain mandatory.
`outbound_wake_failures` is a bounded local diagnostic count. Notification failure
leaves ordinary periodic carriage and the complete queue intact. Restart creates
a fresh Event and obtains its state only through normal full verification.

This mechanism concerns local ordinary enqueue scheduling. Incoming relay and
unresolved retransmissions retain the existing periodic path. The ground change
does not establish regional payment percentiles, sustained faults, physical
routes, independent custody, ledger acceptance or an adopted-network upgrade.
