# Reusing a packet binding within one authenticated operation

Cold transit authentication computes the complete signed packet digest once,
then uses it for the source-signed receipt route and every complete signed hop.
It still validates the packet signature, full frame and payload, currency,
source routing signature, hop signatures, predecessor chain, loop and contact
roles. An invalid transit never installs a validation witness.

After `transit_check` returns, local active-store ownership checks compare the
map key to that exact transit's already authenticated source route packet ID,
and the final visited node to the actual local node. They never accept an
unchecked route, storage digest or peer inventory as authorization. The existing
process-local transit witness continues to retain only immutable visited-node
tuples under its complete validation domain; no new witness or mutable record
is retained. Cache misses, changed bytes, changed limits and cold restart still
perform complete authentication.

This removes repeated canonical serialization within the same operation. It
changes no signed bytes, Native code, storage or wire formats, capacities,
timeouts or custody rules. It does not establish an ordinary liveness improvement
without measurement and fresh ordinary evidence. The currently running frozen
requested-receipt fixture continues to use its original source.

Eighty-one related checks passed. Three additional real private-store checks
refuse a wrong map key with cold and warm authentication, a correctly re-signed
route to another packet ID, and a valid signed hop whose final node is not the
store owner. Each refusal preserves the exact stored bytes. Failed fixtures
remain stopped; no balances, signing journals or caller heads are migrated.
