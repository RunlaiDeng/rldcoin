# Explicit one-way contact directories — ground candidate

The supplemental ordinary node can configure a send-only or receive-only contact
with `adapter: "RLD-CONTACT-SPOOL-ONEWAY-V1"`, one pinned `peer` node ID, and exactly
one private absolute `outbox` or `inbox`. A contact cannot mix this adapter with
TCP fields, another adapter, or two directions. Legacy directory contacts keep
both distinct directions; configured TCP contacts retain their separate pinned
TLS behavior. No advertisement supplies paths, endpoints or adapter selection.

A signed node advertisement lists only configured outgoing neighbors. Receiving
from a pinned neighbor does not create an outgoing route to it. Direct receive
refuses send-only neighbors; exchange preparation refuses receive-only neighbors.
The ordinary mesh tick processes only configured incoming directories and writes
only configured outgoing directories. All configured directories must remain
private, safe and distinct within that node. Contact count, queue/file/byte,
archive, signature, hop, frame and exchange bounds remain unchanged.

The adapter uses the existing complete signed exchange, full transit/receipt
validation and durable receive boundary. It neither imposes an inbox file-age
expiry nor deletes unresolved evidence or refunds value. Successful local outbox
publication or a test carrier's file transfer is not a destination custody receipt,
ledger acceptance or spendability. Incoming bytes are consumed only after full
validation and durable local custody. Invalid signatures, capacity and persistence
failures retain the incoming file. A separate directed return route carries the
destination's signed receipt; its carrier need not possess the forward payload.
Without an actual information path back to a source, distant discovery or receipt
knowledge remains absent. A directed candidate route is not a link observation.

Strict cold inspection takes the setup-time public identity/config commitment,
checks outgoing directions against the retained signed advertisement and does not
read private identity files. A changed direction/config cannot supply a passing
old anchor. Every retained archive continues its ordinary authentication.

This is a ground directory adapter, not BPv7, a radio/laser, qualified physical
carriage, independent custody or a long-term cryptographic qualification. The
mechanical test carrier copies exact complete exchanges between separate local
queues; it does not install ledger proofs or grant authority. Old filesystem
timestamps only exercise absence of a file-age policy, not years of actual
signature/security operation. Ed25519, rollback, independent operators, resource
budgeting and stellar cryptographic/revocation horizons remain separate gates.

Use a new exact compiled ordinary driver and fresh private no-value transport/
fixture directories for this changed Python runtime. Preserve old fixtures and
failures without migration. Native consensus/source identity and signed evidence
formats remain unchanged. The new directional schema is explicit; old runtimes
refuse it. Component and actual ordinary lifecycle/cold qualification are pending
until the currently active revision-47 fault scope stops and checks execute.
