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

A stopped failed fixture's ordinary decode/validation was measured separately
from strict inspection's full archive reads. Its selected missing timeout packets
were durably queued upstream with a candidate route but no destination receipt.
Those observations locate retained carriage and quantify local CPU only; they do
not reconstruct past thread timing or uniquely establish the full fault cause.
Initial per-frame Base64 regex checking erased most serialization savings; the
revised helper checks JSON escape bytes only, leaving the existing Base64 checks
where they already belong. All original failed sources/reports remain preserved.

Native/Core are unchanged. Qualify the changed production Python code with a new
exact compiled default driver, fresh private no-value ordinary cycle, cold and
fault scopes. Preserve old failures without resuming or migrating their value or
custody. Never raise the 0.2-second acquisition, three-second socket, 600-second
campaign or existing admission/archive/history/wire bounds to obtain a pass.
The component candidate and measured savings do not qualify BFT liveness,
independent custody, power loss, physical stellar links or I1–I12 completion.
