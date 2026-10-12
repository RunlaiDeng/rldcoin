# Native signed transport schemas

Ordinary advertisement, peer inventory, source-signed receipt route and destination
receipt checks use `RLD-NATIVE-CONTACT-SCHEMA-V1` through the matching native crypto
library. `interstellar_schema_reference.py` retains the original Python field checks
and independent Python signature oracle for explicit tests. Native refusal has no
fallback path.

## Complete authentication and fields

The typed `Schema` operation reuses the same strict native verification kernel as
the generic `Verify` operation. Every complete received signed object retains exact
format/network/node identity, lowercase public/signature encodings, fixed signature
domain and canonical whole-body checks. No already checked body or peer cache can
initialize this operation.

Advertisements require exactly the existing seven fields. Region identifiers
remain lowercase 32-byte hex; labels remain 1–80 ASCII characters at or above
code point 32, including the historical DEL boundary. Sequence is an actual integer
from 1 through `2^63-1`; booleans and floats refuse. At most 16 neighbors remain
strictly ordered, distinct, valid identifiers and different from the signer.

Inventories retain their four fields and at most 256 strictly ordered/distinct
packet identifiers. Receipt routes retain their six fields. Destination receipts
retain seven fields and exact `EVIDENCE_STORED_NOT_LEDGER_ACCEPTED` outcome. Their
complete nested source route is independently authenticated in its own domain,
then destination, packet ID and frame ID must match. An outer valid signature
never authenticates a damaged or mixed nested route.

Smaller caller contact/message bounds can only refuse more. The original 64-MiB
object and crypto ABI ceiling remain distinct from exchange, frame, history and
ledger bounds; this schema migration increases none of them.

## Receipt and authority

The existing common receipt binds exact control bytes and current native
implementation. A schema response additionally binds kind/network and the exact
checked body. The bridge validates shape, body identity and literal boolean flags
before returning the original body or packet identifier.

`transport_authenticated: true` describes only the signed transport metadata.
`ledger_authority: false` and `custody_acknowledgment: false` remain explicit.
Self-signed region labels, candidate routes, packet inventories and transport
receipts do not authorize a ledger, validator, issuance, signing, finality, import,
maturity, spendability or refund. Actual durable custody and complete native
ledger/BFT/owner verification remain separate and mandatory.

Complete packet/frame/hop checks use the separate [native transit interface](NATIVE_CONTACT_TRANSIT.md).
Mesh scheduling, service orchestration and remaining
wallet/runtime functions continue to require migration. Finite same-host fixtures
do not qualify independent security/custody, full faults/load, long history,
cryptographic adoption, physical routes or mainnet. Changed native source requires
fresh signed no-value fixtures; failed stores and old candidate value never migrate.
