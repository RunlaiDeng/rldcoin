# Native exact-transit witness

The Rust contact runtime owns its exact-transit witnesses directly through
`RLD-NATIVE-TRANSIT-WITNESS-V1`. A native refusal terminates that operation.
Only bounded immutable visited-ID tuples are retained, never a mutable packet,
header, frame, archive, ledger, key or callback.

## Complete bytes and scope

Each probe reads and hashes the complete current canonical transit bytes. The
scope binds the mesh version, network, recipient and sender, hop/frame/payload
limits, frame format/domain and ordered kind set, plus the current crypto
provider's format, implementation, library path and instance. Library path and
instance are namespace partitions, never identity or independent trust anchors.
The actual native implementation is checked during complete verification.

The scope hash is SHA-256 over `RLD-NATIVE-TRANSIT-WITNESS-SCOPE-V1` plus NUL and
the complete canonical scope bytes. Transit hash and exact length bind all
packet, routing-certificate and ordered hop bytes. A caller-provided digest alone
cannot hit or insert an entry. Bytes, scope or limits that differ stay cold.

The native store retains at most the original 512 entries, each containing only
scope/transit digests, complete byte length and immutable visited identities.
A hit moves that exact entry to the newest position. Tightened retention trims
oldest entries; zero retention removes all witnesses. Eviction deletes no signed
evidence, archive, custody, debit or liability. Process changes clear witnesses;
ordinary new processes authenticate again. The store is neither serialized nor
used to initialize ledger state.

## Probe and full check

The explicit JSON Probe/Check control uses bounded unique canonical decoding.
Scope fields and provider types are fixed; retention can only tighten 512. A
complete Check always executes the existing native packet/frame/routing/hop
kernel, even if identical bytes are warm. Every signature, complete opaque frame,
route binding, hop predecessor, loop and requested contact check remains required.
Only a successful complete Check can insert a witness. Verification holds no
witness mutex; final insertion and least-recently-used updates are bounded.

The default compact probe uses `RLD-TRANSIT-WITNESS-PROBE-BYTES-V1` plus NUL,
then a big-endian two-byte retention limit, four-byte scope length, eight-byte
transit length, 32-byte declared SHA-256 and the complete canonical scope bytes.
The transit remains a separate complete immutable input. Exact EOF, all lengths,
retention and the actual full transit hash are mandatory. It cannot insert.

A compact hit requires both current byte hashes and exact length to match an
entry created by full native verification. That exact prior canonical scope
binding permits avoiding repeated scope decoding on a hit. An arbitrary bounded
scope is at most an unauthenticated miss; full Check still validates its complete
schema, provider and native limits before any insertion. The compact probe does
not learn endpoints, accept an unchecked state or introduce a caller-controlled
hit flag. JSON controls stay bounded by 8192 bytes, compact headers plus scope by
8320 bytes, and complete private transit inputs by 20 MiB. These are private API
bounds and increase no network/frame/payload, archive or ledger limit.

The common receipt binds exact control bytes and current native implementation.
The result additionally binds full transit SHA-256/length and complete scope
SHA-256. Found/path/transport_authenticated fields have literal types; a miss
has no path and grants no authentication. The bridge verifies all bindings,
unique response fields, immutable path shape and complete-buffer release.
Current provider/source changes refuse rather than use another backend.

The Rust runtime constructs the scope from fixed native limits and its embedded
implementation identity. It uses an authenticated probe followed by a complete
Check on a miss; no foreign callback or mutable validation context is retained.

## Independent obligations

Hash agreement proves byte identity under the selected finite cryptographic
assumptions, never ledger, finality, signing, durable custody, current freshness,
import, maturity or spendability. Transport authentication remains distinct from
native value authorization. Archive ownership/inventory, contact freshness, TLS
and every native value/incident proof retain their independent checks; warming a
transit cannot hide disk tampering or supply omitted evidence.

Arithmetic encoding reuse remains separately bounded and never authenticates
material. Source-qualified failures stay historical. Changed native source needs
fresh signed no-value genesis/currency; old state, keys, balances and custody do
not migrate. Independent operations, power loss/cross-device custody, sustained
fault/load, long history, cryptographic adoption and physical routes remain open.
Legacy runtime states refuse unchanged. The Rust lifecycle requires fresh
private fixture directories and does not recreate historical qualification.

The ground dev/test profile optimizes the fixed `serde_json` dependency at level
1 while retaining debug assertions and overflow checks. Dependency versions,
unique decoding, typed bounds, exact canonical bytes and authentication policy
remain unchanged. A different build profile/binary needs its own source-bound
verification and fresh no-value fixtures; it inherits no historical pass.
