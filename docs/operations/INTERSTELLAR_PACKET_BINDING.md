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
without measurement and fresh ordinary evidence. Qualification remains bound to its selected source and input scope.

Required negative checks include wrong map keys under cold and warm authentication,
re-signed routes bound to another packet, and signed hops ending at a different
store owner. Every refusal must preserve complete retained bytes. Failed fixture
state cannot be migrated or reused to qualify a changed implementation.
