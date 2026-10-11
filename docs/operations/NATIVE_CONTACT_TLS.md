# Native ground contact TLS

Ordinary `interstellar_tcp.Server` and `client_connect` use the source-bound
native contact library for certificate/private-key files, TLS handshakes and
length-prefixed canonical JSON frames. Build the library and node together with
`cargo build --manifest-path tools/regional-ledger/Cargo.toml --bins --lib`.
The node checks their implementation identities before normal contact startup.
`interstellar_tcp_reference.py` remains an independent Python oracle and explicit
SDK test peer. Native refusal never invokes that provider as a fallback.

`RLD-NATIVE-CONTACT-TLS-V1` is an in-process handle interface carried by the existing
bounded contact ABI. It returns public certificate observations and connection
handles, never private PEM or seed bytes. Only trusted local callers may supply
socket descriptors. Native server adoption duplicates a connected IPv4 descriptor
with close-on-exec; it does not take ownership of the caller's descriptor.

## Authentication and private material

TLS is exclusively 1.3. Clients independently pin the exact certificate DER SHA256,
configured network and neighbor identity. The self-signed certificate must use
Ed25519, contain exactly the expected common name and organizational unit, have
equal subject/issuer and a valid signature, and satisfy the local UTC validity
policy. The TLS CertificateVerify signature is also checked by rustls. Configured
literal IPv4 endpoints remain independent of advertisements. Client resumption,
early data and server tickets are disabled; no public CA or advertised hostname
supplies this trust.

`tcp-tls.private.pem` retains the original canonical certificate followed by
PKCS8 Ed25519 seed encoding. Native generation uses a separate random TLS key,
five-minute initial clock allowance and a 90-day certificate. File creation is
exclusive and owner-only; the complete file and parent directory are synced
before release. Existing private files must be bounded, canonical, owned, private,
limited to one hard link, nonsymlinked and key/certificate matched. Malformed, expired or partial
material refuses unchanged. No automatic renewal, overwrite or plaintext fallback
is provided. Private buffers are zeroized where the selected native types support
it; this does not establish independent key-custody qualification.

## Frames, deadlines and shutdown

Frames retain a four-byte big-endian length and exact canonical ASCII JSON bytes.
Zero lengths, lengths above 20 MiB plus 4096 bytes, duplicate JSON fields,
noncanonical input, incomplete reads and malformed values refuse. The original
three-second monotonic attempt covers connect, handshake and frame socket waits.
Native timed reads/writes recompute its remaining time; later operations cannot
rebase that deadline. Local verification CPU remains a separate measurement.

The process-local handle table admits at most 64 server contexts and 192
connections, derived from the existing 64-node, two-inbound and serial-outbound
limits. Ordinary listener admission still permits only two inbound workers.
Table locks are released before socket waits. Shutdown uses a separate socket
clone and never waits for a blocked per-connection I/O mutex. Workers retain
their native session until exit, and the service joins them before releasing its
custody. Close and context release are idempotent; handles cannot be recycled.

## Remaining authority and migration boundaries

Python still owns the listener, worker lifecycle, ordinary contact scheduling and
mesh durable custody. Explicit ground insecure mode remains a separate configured
path and is never selected following a TLS failure. Outgoing carriage is prepared
durably before connect; signed challenge/reply binding and local custody remain
mandatory. Native TLS/frame completion grants no destination receipt, ledger
acceptance, finality, maturity, signing or refund rights. The ordinary execution,
wallet and caller-head checks remain separate.

This ground implementation does not qualify PQ TLS, delayed revocation,
long-disconnection cryptographic horizons, power loss, cross-device/independent
custody, physical routes, sustained BFT faults or mainnet. Changed native source
requires fresh signed no-value fixtures; retained historical stores, balances,
keys and failed evidence are never migrated or reopened for replacement
qualification.
