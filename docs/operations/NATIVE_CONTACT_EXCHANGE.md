# Native signed exchange and TCP controls

`RLD-NATIVE-CONTACT-EXCHANGE-V1` checks the outer exchange envelope and TCP
challenge/request/response bindings through the existing bounded contact crypto
ABI. Serialized operations are `Exchange`, `Challenge`, `TcpRequest` and
`TcpResponse`, nested under the common `Exchange` request. Every received signed
object uses the existing strict signature/network/node identity kernel and its
fixed domain. `interstellar_exchange_reference.py` retains the original Python
predicates and independent signature oracle for explicit tests. Native refusal
has no Python fallback.

## Exchange and configured caller inputs

The exchange retains exactly its eight fields, exact independently configured
sender/recipient and incoming-contact permission. Its complete peer inventory
authenticates separately and must identify the same sender. Array bounds remain
64 advertisements, four transits and 256 receipts; the inventory retains its
original 256-ID ordering/uniqueness rules.

The native interface receives the incoming permission and TCP peer identities
from already validated local configuration. TCP configured peers remain bounded
by the existing 16-contact profile. A signed advertisement or incoming envelope
cannot provide this policy, endpoint or TLS pin. Smaller caller limits can only
refuse more; out-of-profile caller controls refuse rather than expand policy.

Outer exchange success does not authenticate its advertisement/transit/receipt
items. Ordinary receive still checks every complete item through the separate
native schema/transit kernels, checks retained-state and archive relationships,
and completes the original durable commit before publishing state or replying.
Its state adoption and synchronization sequence is unchanged.

## Fresh TCP and exact prepared exchange

The challenge retains six fields under fixed `RLD-CONTACT-TCP-V4`, configured
peer and independently selected certificate fingerprint. Its nonce is lowercase
32-byte hex. A null fingerprint is only the existing explicitly selected insecure
ground path; it creates no downgrade or fallback. Actual pinned TLS negotiation
and certificate verification remain separate mandatory operations.

The request retains eight fields. Recipient, configured sender and the connection's
fresh challenge must match; the request nonce is canonical hex. Its complete
signed exchange fits the unchanged 20-MiB ceiling and independently authenticates
in the exchange domain with exact sender/recipient binding.

The response retains eleven fields. Configured peer, requester, both original
nonces and the complete canonical digest of the exact separately retained sent
exchange must match. The sent request is a caller-selected local binding input,
never accepted from the replying peer or reconstructed from telemetry. Missing
local binding fields refuse. The original request construction and independent
outgoing custody remain mandatory.

Acknowledgment is a literal boolean. A refusal requires null bundle and exact
`CONTACT_REJECTED`; it returns no success and preserves queued evidence. Success
requires null error and a complete bounded signed exchange authenticated with
the reply's peer/requester identities. Its inner contents still need normal
receive validation and actual local durable custody.

## Receipt and authority

The common receipt binds exact control bytes and current implementation. The
operation result additionally binds mode/network, exact checked body and literal
flags. The bridge resolves the current crypto provider per call, verifies these
bindings and returns only the already checked body, nonce or bundle. It retains
no authentication or mutable-object cache. The checked body is returned once;
no duplicate large response object expands the ABI result.

`envelope_authenticated: true` describes only these complete outer signatures
and selected bindings. `ledger_authority: false` and
`durable_custody_acknowledgment: false` remain explicit, even if the signed remote
body claims `accepted: true`. A closed socket's verified reply still requires
actual local durable receive before retransmit suppression. Existing strong
file/directory synchronization, independent caller heads, failure residue and
no-refund rules remain mandatory.

This interface increases no crypto ABI, exchange/wire, frame, archive, ledger,
BFT or scheduling bound, and changes no quorum, deadline or maturity rule.
Scheduling, service, state adoption and remaining wallet/runtime functions still
require migration. Finite same-host checks do not qualify independent
security/custody, complete faults/load, long history, cryptographic adoption,
physical routes or mainnet. Changed native source requires fresh signed no-value
fixtures; failed stores and previous candidate value never migrate.
