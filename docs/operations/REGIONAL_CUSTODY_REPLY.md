# Independent carriage custody reply candidate

Verification-only ground candidate; transport receipts do not grant ledger or signer authority.

## Receive path

When the TCP server has an actual live independent outgoing owner, it first
executes the unchanged full `Node.receive` and durable custody transaction.
Only afterward does it construct a bounded signed mesh reply containing its
own authenticated advertisement, current signed active-packet inventory and
already authenticated receipts for the exact incoming packets. It carries no
reverse transit and advances no carriage cursor. The mesh reply plus response
overhead must fit 64 KiB and the original wire bound.

The independent owner still prepares and durably rotates all outgoing transit
and historical receipt carriage before opening its connections. Discovery,
reverse evidence, fairness, retries and cold authentication remain on that
ordinary path. A server without a live outgoing owner retains its existing
duplex response. There is no new serialized mode or authority and no fallback
from a failed ordinary worker.

Every incoming complete exchange, transit, signature, route, hop and receipt
still requires its original authentication. The signed TCP response still binds
the fresh challenge, both nonces and exact incoming exchange. The source must
durably receive the verified reply before temporary hop retransmit suppression.
Reply failure retains original evidence. Neither a custody acknowledgment nor a
destination transport receipt is ledger acceptance, spendability or a refund.
