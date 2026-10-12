# Native candidate routing

`RLD-NATIVE-CONTACT-ROUTING-V1` performs the ordinary pure breadth-first candidate
search through the matching contact crypto ABI. `interstellar_routing_reference.py`
retains the complete original Python method for explicit comparison. The default
Node method calls Rust; a native refusal has no Python fallback.

## Explicit graph and trust boundary

Ordinary Node startup authenticates every complete retained advertisement and
its exact map identity before routing. Receive authenticates each later complete
advertisement before state adoption. Independently configured contact directions
remain the only source of first-hop outgoing permission. Those original checks,
state/custody ordering and configured endpoint/pin rules remain unchanged.

This operation is a pure search over an explicit bounded adjacency projection.
It does not authenticate advertisements or initialize trusted state. It accepts
neither peer endpoints nor a decoded ledger. A typed graph, node identifier or
returned path cannot replace the caller's full state verification. No graph,
authorization witness or mutable result is cached or serialized.

The current independently selected network/node, destination, excluded nodes,
optional first hop, configured outgoing peers and complete adjacency view enter
the common exact-control receipt. The bridge checks the returned path's roles,
edges, exclusion and configured first-hop bindings before returning it.

## Original search behavior and bounds

Self destination returns the single source identity immediately, ignoring unused
exclusions, first-hop and graph data as before. Other searches use a FIFO
frontier. Each neighbor retains its original ordered position; equal-length
alternatives use that order. Excluded/visited identities are skipped. Only the
first hop requires independently configured outgoing permission and, when
supplied, the exact selected first-hop identity. Later graph edges do not learn
new endpoints or create configured connections.

Missing advertisements stop that branch. A destination can be a dangling
neighbor without its own advertisement. Directed/asymmetric graphs remain
directed. Cycles terminate without an invented route, receipt, refund or claim
that another process is online.

At most 64 known advertisements, 16 neighbors per row and 16 configured contacts
remain. Their at most 1024 edges can expose up to 1025 reached identities,
including dangling neighbors; the frontier is not reduced to the count of known
advertisements. Candidate paths can contain up to 65 identities. The typed
interface admits at most 1025 explicit exclusions; these are caller filter data,
not additional discovered nodes or authority. Smaller known-row/neighbor/contact
limits only refuse more.

Candidate paths longer than the existing signed packet's 16-hop ceiling remain
candidates. Ordinary carriage still applies its original total visited-plus-route
check and refuses paths that cannot fit. Never truncate a graph path or raise
the packet limit to manufacture a valid carriage route.

## Stateless candidate byte interface

The default private ABI uses `RLD-CANDIDATE-ROUTE-BYTES-V1` followed by a NUL
byte. It carries one-byte selected row/contact limits; raw 32-byte network,
source and destination identities; a literal zero/one optional-first-hop flag
and its identity; a big-endian two-byte exclusion count and ordered identities;
one-byte outgoing count and identities; and one-byte row count. Each row has
one raw identity, one-byte neighbor count and the complete ordered neighbors.
Rows must be strictly ascending and unique. Counts retain the bounds above;
checked offsets, complete input and exact EOF are mandatory. No peer cache,
handle or retained graph supplies omitted data.

This private input refuses above 70 KiB, without changing any network or ledger
bound. Oversized or null C inputs are not read. The common receipt hashes every
actual input byte and binds the current native implementation. The bridge keeps
the existing bounded response read, unique decoding, exact binding checks and
buffer release on every response path. Returned results additionally bind
`codec: RLD-CANDIDATE-ROUTE-BYTES-V1`.

The explicit JSON `Routing` control remains available for comparison. Both
interfaces use the same stateless search kernel; the default has no JSON or
Python fallback. Raw identities preserve the original lowercase hexadecimal
identity ordering and complete neighbor order.

## Result and authority

The result binds exact network/node/destination and nullable path, with literal
`candidate_only: true`, `labels_authenticated: false`, `ledger_authority: false`
and `custody_acknowledgment: false`. The common receipt binds complete control
bytes and current native implementation. The bridge resolves the current crypto
provider per operation and retains no fallback or process-local search cache.

Only these decoded candidate controls and trusted candidate-result envelopes
have a restricted encoding path: the complete tree must contain printable ASCII
keys/strings, integers/booleans/null and already strictly ordered map keys. The
standard serializer then retains the exact original canonical bytes and byte
bound. Unicode, control/DEL characters, floats and other map order retain the
original Python-compatible encoder. Unique input parsing, exact canonical-control
comparison and complete request/source hashes still run; no signature, graph,
size or authority check is skipped. Other contact operations keep their original
encoder path.

A candidate path is distinct from discovered signed identity, physical contact,
contact observation, destination transport receipt, ledger acceptance, finality,
import, maturity and spendability. Every later complete packet/hop/envelope,
native value proof and actual durable custody still verifies independently.
This operation changes no quorum, deadline, issuance, history, exchange/frame,
archive or scheduling limit and grants no signing/value rights.

Scheduling, service and remaining wallet/runtime functions still need migration.
Finite same-host checks do not qualify independent security/custody, complete
faults/load, long history, cryptographic adoption, physical routes or mainnet.
Changed native source requires fresh signed no-value fixtures; failed stores and
old candidate value never migrate.
