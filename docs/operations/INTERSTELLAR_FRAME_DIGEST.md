# Exact streamed frame commitments — ground candidate

The active state codec and complete-transit authentication witness calculate the
same SHA-256 and byte length as ordinary canonical JSON. For a frame string that
requires no JSON escaping, serialize every surrounding metadata field through
the ordinary canonical encoder and hash its exact prefix, frame bytes and suffix.
Unsafe strings/shapes take the original complete canonical path. This is byte
construction only; canonical Base64, frame/network, packet/route/hop signatures,
receipt binding and Native value checks remain mandatory.

The helper retains no cross-call object, decoded payload, signature result or
ledger. No supplied size/hash initializes state. Existing 512 exact immutable
transit witnesses and all validation domain/limit bindings remain unchanged.
Active shared-frame disk and signed wire bytes are identical, including Unicode,
control/DEL escaping, arbitrary metadata order and frame-like unrelated fields.
Cold decode recomputes every complete commitment, then normal transport validation
runs. An altered frame, hop, route or packet cannot hit an old authenticated
witness; storage digests never authorize signatures, custody, value or signing.
