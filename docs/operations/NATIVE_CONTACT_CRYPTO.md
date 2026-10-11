# Native contact identity and signature backend

Ordinary contact Node identities are generated and inspected by the Rust
contact backend. Normal Node signers hold a private identity path and public
binding; Python does not decode their secret seed or retain a private signer.
Advertisements, packets, receipt routes, hops, inventories, exchanges, archives
and TCP challenge/request/response signatures run in Rust. Verification also
uses Rust. Domain-specific object, route, contact, custody and ledger checks
remain mandatory in their existing layers.

## Library and identity boundary

Build both binaries and the library with `cargo build --bins --lib`. The
platform's `librld_regional_ledger_candidate` library must sit beside the actual
node binary. Service startup compares its profile and implementation identity
with the binary's inspection-only `contact-crypto-info` output. Missing or
mismatched artifacts refuse without a Python crypto fallback. Standalone ground
mesh tools select the local debug library and check its complete mesh profile.
This is build consistency, not independent supply-chain qualification.

The private identity retains its existing canonical disk encoding and exact
mesh, archive, active-storage and scheduler profile fields. Rust requires a
private owned directory, a regular owned private file, no symlink/parent
traversal or hardlink, an exact public/private pair and pinned network. Native
initialization creates a new file exclusively and fsyncs the file and directory
before returning public identity. Existing files are never overwritten;
partial writes remain for explicit investigation. Signing rereads that file
and checks the separately supplied public binding on every call. Private bytes
are not returned by the ABI or passed through argv, environment or HTTP.
Transport identities are stateless signers and do not implement ledger signer
locks, latest-head protection or copied-key custody qualification.

## Bytes and authority

Signatures retain the exact `RLD-CONTACT-MESH-V3` purpose prefix and Python's
sorted ASCII canonical JSON bytes, including packet bodies. Rust accepts only
the listed contact purposes, checks the signed body's version/network/node
identity and performs strict Ed25519 verification. Invalid encodings and weak
or malformed signatures refuse. Valid ordinary signatures retain their wire
bytes. Native returns a new decoded object; signature agreement never validates
a mutable later object or bypasses envelope-specific checks. Process-local
transit and archive-index witnesses also bind the active native implementation
and library instance; a provider/domain change requires complete authentication
again, without removing retained evidence.

The local ABI uses one immutable input buffer and one library-owned output
buffer per call. The trusted in-process caller releases each unchanged returned
pointer/length once through the same library. Duplicate/unknown fields,
noncanonical input, wrong types and malformed receipts refuse. Its internal
buffer ceiling derives from the existing 64 MiB mesh document ceiling plus
bounded ABI metadata. It does not raise the 20 MiB exchange, TCP wire, ledger,
native proof, archive, count or worker limits. Each response binds exact request
bytes and implementation and declares no ledger authority, independently
qualified durable custody or independent security.

The former Python signature implementation is retained for independent tests
and callers explicitly supplying SDK fixture keys. Normal Node always uses the
native file signer; native refusal never selects that reference path. The
reference supplies no ledger, custody or finality rights.

## Remaining obligations

TLS certificate/private PEM handling, TLS negotiation, sockets, service
lifecycle, mesh durable custody and their independent qualification remain
separate. Signed replies still require actual durable custody before release;
peer authentication is not ledger acceptance, finality, maturity, spendability
or refund authority. The current ledger suite is not upgraded to a hybrid or
post-quantum suite. Changed native source requires fresh signed no-value
fixtures; compatible encodings never authorize old-value, failed-store or
adopted-network migration. Whole fault profiles, independent operations,
physical routes and mainnet acceptance remain open.
