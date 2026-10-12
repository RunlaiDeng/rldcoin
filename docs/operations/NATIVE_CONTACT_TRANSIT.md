# Native complete carriage checks

Ordinary packet and complete transit validation use
`RLD-NATIVE-CONTACT-TRANSIT-V1` through the existing contact crypto ABI. The
`Transit.Packet` and `Transit.Check` operations reuse the strict signature,
receipt-route and opaque frame kernels. `interstellar_transit_reference.py`
retains the original Python functions and independent signature/frame checks for
explicit comparison. Native refusal has no Python fallback.

## Exact composition

Each packet retains exactly seven fields and its complete canonical signature
body. Destination and nonce are lowercase 32-byte identifiers; the actual integer
hop limit remains 1–16. The frame must be canonical Base64 and pass the existing
complete frame checks, including canonical bytes, payload hash, message ID,
kind/chain and regional envelope shape. Regional carriage currency must equal
the caller's independently selected mesh currency. These opaque checks do not
execute the native consensus or value envelope.

Each transit retains exactly packet, source-signed routing certificate and hops.
The route is separately authenticated and binds the exact signed packet digest,
source signer, destination and verified frame ID. Every complete hop is verified
in its fixed signing domain and retains exactly six fields. Its signer, packet ID
and preceding signed-object digest must match the current chain. Revisited node
identities refuse. At most the packet's signed hop limit can be carried.

A supplied recipient requires at least one hop, the exact last destination and
the exact last signer selected as sender. Omitting the recipient preserves the
existing source/retained-carriage validation semantics. Packet and hop digests
use complete sorted canonical objects, including their signatures.

The 16-hop, 4-MiB-plus-4096-byte frame and 3-MiB payload ceilings remain unchanged;
smaller caller limits can only refuse more. The separate existing 64-MiB object
and crypto ABI ceilings do not increase exchange, archive, ledger or BFT limits.

## Response, witness and authority

The common native receipt binds exact control bytes and implementation. The
transit result also binds operation/network, checked packet body, complete frame,
visited identities and literal transport/authority flags. The bridge checks these
bindings and assembles only the already checked raw frame and path. It resolves
the current crypto provider on every operation, as do signed metadata checks;
an import-time provider function cannot substitute for the witness namespace.

The existing process-local transit witness is unchanged: only exact previously
authenticated canonical bytes under the complete network/contact/native provider
and validation-limit namespace can reuse an immutable visited tuple. No packet,
frame, header, private key or mutable result is retained. Changed bytes, roles,
limits or provider, eviction and cold startup perform complete verification.
Native composition has no persisted validation cache.

`transport_authenticated: true` concerns the signed carriage only.
`ledger_authority: false` and `custody_acknowledgment: false` remain explicit.
Actual durable custody, native ledger/BFT/owner execution, incident handling,
finality, import, maturity and spendability remain separate mandatory operations.
No checksum, route, visited path or transport receipt grants those rights.

Mesh scheduling/witness orchestration, service and remaining wallet/runtime
functions still require migration. Finite same-host checks do not qualify
independent security/custody, full faults/load, long history, cryptographic
adoption, physical routes or mainnet. Changed native source requires fresh signed
no-value fixtures; retained failed stores and old candidate value never migrate.
