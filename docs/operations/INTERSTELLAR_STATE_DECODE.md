# One canonical admission of an active state image

The ordinary loader reads the bounded complete file, then passes its exact bytes
to the active-state codec. The codec bounds raw bytes before decoding, rejects
duplicate fields, compares the entire canonical encoding to those bytes and
uses that same call's exact byte length for image admission. No caller-supplied
size, digest, cached object or decoded ledger can bypass the comparison.

The separate object `unpack` interface still computes the full canonical image
size itself. Both public paths retain the same internal schema, storage domain,
network/node ownership, frame pool, complete object digests, exact expanded
transit sizes, references and orphan checks. Ordinary Node validation still
authenticates the complete packet, route, hops, receipts, archives and configured
inventory. Successfully decoding storage cannot authorize an invalid signature.

This removes a duplicate whole-image serialization from ordinary open. Signed
bytes, private storage format, capacities and custody remain unchanged. It adds
no witness or serialized state. The currently running frozen requested-receipt
fixture is unchanged. Old failed fixtures are read only and remain failed.

Eighty-eight related checks passed, including four new raw admission cases:
exact capacity and roundtrip; oversized input refused before decoding;
noncanonical bytes, duplicates and wrong identity refused; complete object
digest/expanded bounds refused; recomputed storage hashes still fail ordinary
packet authentication with the exact image retained. Runtime performance and
fresh ordinary qualification require their own evidence.
