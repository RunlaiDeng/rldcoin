# Process-local Native body witnesses

The paged Store executes all complete ordered records from pinned genesis on
every cold open and mutation. Its process-local body identity cache contains at
most 4,096 entries, in insertion order. An eviction removes only a redundant
identity witness. It does not remove original records, active verified ledgers,
receipt or contact anchors, permanent imports, incidents, or signer locks.

A new local certificate still authenticates its complete certificate and shape,
requires the exact selected Native predecessor, and executes the complete new
block under that predecessor's Native-derived ledger. A full identity cache does
not change those checks. The active semantic working set remains bounded at 64
snapshots and retains all required provenance and receipt anchors.

An evicted historical identity can be resolved only from the exact original
record prefix already successfully Native-executed in the same invocation. The
process derives that prefix's count and ordered record commitment from its
independently bound scope. It advances them only after successful Native record
execution. A lookup verifies the entire held current stream, examines only that
executed prefix, recomputes its exact count and commitment, and checks all matching
complete bodies for equality. Future records cannot claim prior execution. Any
source, order, body, scope or prefix mismatch refuses the lookup.

The newly supplied complete certificate still authenticates independently after
a lookup, and its complete body must match. A commitment read from disk, a peer
advertisement or a serialized witness cannot initialize this process-only state
or a Native ledger. Historical signing cursors carry the same held stream and
advance only through actual ordered execution; look-ahead records do not enter
the executed prefix before execution. Staged new append records are verified
natively and stay in the bounded process cache until the complete append is
published. An ordinary append remains at most 16 complete records.

The retained stream's original format, complete 16-record pages, signed rules,
8-MiB object/evidence/ledger limits and 4,096-file / 256-MiB archive ceiling remain
unchanged. A cache miss may reread the complete archive; bounded memory does not
imply constant-cost lookup or long-history throughput. Page packing is a separate
representation candidate. Neither mechanism establishes the required long-history
value execution, recovery, retention funding, independent rollback protection,
cryptographic adoption or physical route qualification.
