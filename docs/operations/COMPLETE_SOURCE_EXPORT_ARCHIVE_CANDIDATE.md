# Complete source export archive inspection

`storage::inspect_export_archive_candidate` verifies a complete immutable packed
source certificate archive from signed genesis. The receiver supplies the
independently trusted currency root, authority and exact source/destination/export
query. The supplied archive head commits to bytes only. It cannot establish that
the supplied history is current, complete with respect to incidents, or the only
remaining historical copy.

The read-only `export-archive-inspect` CLI action uses `--dir` for the immutable
packed archive, the existing `--authority`/`--currency` receiver trust pins,
`--bootstrap` for the signed public bootstrap, `--query` for an exact typed JSON
object with `source`, `destination` and `export`, and `--carried-head` for its byte
commitment. It opens no ordinary Store and starts no contact service. It prints
one bounded JSON observation only after complete verification; failure emits no
partial success. A RESTORING target remains refused by the existing startup guard.

The verifier reconstructs Native state through the shared complete execution
kernel. Every original certificate, owner signature, block, predecessor and value
transition executes before it returns the export observation. A valid export
earlier in the stream does not permit an early return: a bad later certificate
rejects the complete query. Missing genesis/predecessors, wrong trust or route and
unknown exports also reject. Rehashed storage cannot authenticate a bad proof.

The narrow candidate accepts only local certified records. Foreign proofs,
receipts, contacts and incident identifiers require their full separate semantics
and are refused here. Sixteen-record pages, object bounds, active64 observations
and aggregate retained archive limits remain unchanged. The archive is never a
serialized ledger initializer; fresh process inspection executes from genesis.

The returned observation is not deserializable as Native state. It explicitly
grants no ordinary contact/import authority, recipient maturity, current incident
safety, independent freshness or owner signing. Existing contact envelopes retain
their own complete64-ancestor bound and reject oversized proofs. This API does not
change a signed admission, install remote value, migrate custody or qualify long
history at the target scale. Adopted remote import requires a separately specified
authenticated profile, incident policy, resource bounds and full lifecycle tests.

Only source and tests are public. Generated archives and binding/query files stay
local; no signer keys, owner journals, caller heads or live currency state belong
in a published package.

## Opaque carriage and receiver retention

`tools/regional_export_archive_carriage.py` packages only the exact public
`packed.json` manifest and its referenced immutable packs. Its canonical byte
container rejects duplicate, missing, extra, path-bearing or mismatched objects
before retention. The original transport payload/frame and retained-object limits
apply. It never scans signing custody or supplies receiver trust from the sender.

`retain_candidate` requires a fresh absent directory and refuses overwrite or
resumption. Partial writes preserve their residue and a retention sentinel;
the Native archive reader rejects that sentinel. Successful byte retention still
requires the complete Native inspector with independently held bootstrap,
authority, currency and exact route/export query. The supplied head commits only
to bytes and grants no freshness, incident, import or maturity rights.

Forward packet delivery, destination signed receipt and source receipt arrival
are separate observations. Ordinary reverse carriage can require later ticks;
a receiver must verify actual receipt binding within its unchanged budget and
must not infer return completion from forward delivery. Ground region labels do
not authenticate Native ledger admission. Clear process-local transit witnesses
before a cold transport read, and use a new Native process for complete execution.

## Explicit lossless source format

`storage::inspect_lossless_export_archive_candidate` accepts the separate existing
lossless packed format with a whole carried-manifest hash and byte length. The
CLI requires both `--carried-manifest` and `--carried-manifest-bytes`; absence of
both selects only the raw format. Neither format is inferred or downgraded.

The manifest reference binds the sender-chosen object inventory. It is not an
independently current state anchor, and this interface does not use the recovery
contract to adopt a sender head. Encoded objects authenticate before bounded
inflation; exact decoded lengths, original references, canonical codec and typed
pages authenticate before the shared complete Native replay. Later invalid
certificates still reject without partial output. Object, decoded-object, page,
aggregate retained-byte and active-history limits remain unchanged. Compression
alone supplies no independent copy, CPU budget, freshness, remote import or
qualification at the required long-history scale.

The opaque carriage codec preserves the explicit lossless manifest's ordered
original-object references as well as its encoded pack references. Missing or
ill-shaped original references and oversized decoded-object declarations reject
before retention. The Python codec performs no inflation and cannot validate a
compressed Native certificate; exact whole-manifest binding and all decoded
Native semantics remain the inspector's responsibility.
