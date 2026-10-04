# Requested retained receipts in owned TCP replies

After durable reception, an inbound handler with an actual independent outgoing
owner returns the existing authenticated destination receipts for the request's
packets and signed packet inventory. It sends no reverse transit. The inventory
must exactly match the just-retained authenticated peer inventory; discovery or
an inventory digest cannot authorize a receipt or Native value.

The original 16-receipt and 64-KiB reply limits remain. Immediate packet receipts
take priority. Remaining requested receipts rotate after the last actually
selected ID, with one nullable process-local ID per configured TCP peer. A whole
receipt exceeding the remaining budget is skipped without advancing that ID.
Ordinary durable reverse-carriage cursors remain unchanged. Restart forgets the
hint; original receipt and packet evidence remains retained. A failed or lost
socket does not delete evidence, refund a debit or create destination authority.

TLS 1.3, fixed neighbor identities/endpoints/pins, fresh connection challenge and
exact response/exchange binding remain mandatory. The receiver must finish real
local durable reception before accepting hop suppression. Publication failure,
invalid inventory or byte refusal never grants custody. The independent reverse
worker still carries ordinary evidence.

Actual pinned-TLS tests reproduce the old missing receipt when the original
transit is suppressed, deliver retained receipts without worker help, rotate 35
requested IDs, keep ordinary cursors unchanged, rotate under a one-receipt byte
budget, and refuse corrupt inventory or failed repeated-custody fsync. These are
ground transport checks; they do not establish Native inclusion, ordinary BFT
liveness, independent custody, cross-host operation or physical links. Failed
ordinary fixtures remain stopped; a fresh frozen build and new private fixture
are required for subsequent ordinary qualification.
