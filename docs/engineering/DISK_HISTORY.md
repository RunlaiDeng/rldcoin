# Disk-resident verified native history

## Active question and decision

The previous persistent index shared nodes but retained every full Committed
record in memory. The source-level hypothesis for this stage is that a bounded
cache plus immutable content-addressed disk pages can support all actual history
consumers while preserving native authority and fixed proof observations. The
observation is removal of the resident record tree and integration into cold/live
commit, historical authentication, proving, cancellation, recovery, CLI and block
paging. Review two source passes and compile the final source; a missing consumer
or an unchecked read blocks publication. No fixture, local test suite, runtime
campaign, measured memory use or latency is substituted for this observation.

## Representation and authority

A History observation contains only an Arc to its private disk owner and its exact
root Link, native count and head. An empty observation starts from the authenticated
initial descriptor. Append requires the next native height, currency/home and exact
predecessor, and follows complete native execution and matching QC validation in
Core.apply. Each leaf hashes complete canonical Committed bytes. Internal pages
bind format, currency/home, height and ordered child object digest/length/ranges.
A page has at most 32 children and 16 KiB; every nonfinal child is full, ranges are
contiguous, heights decrease and count/capacity arithmetic is checked. Depth 13
covers the uint64 height namespace. Reads check exact object length/digest, page
binding/ranges, record height/configuration/batch identity and canonical encoding.

The root is never deserialized from a disk manifest as authorization. Cold node
open streams every anchored event, verifies its ordinary native/consensus rules
and reconstructs the exact private history root. Old queries and proofs retain
their own immutable root, so a later write or unrelated object cannot extend that
observation. Hashes establish only equality to records already authenticated by
that process's native prefix. QCs, execution receipts, owners, money/slot and
terminal checks remain unchanged. Same-profile old journals can create this new
derived index through full replay; this is not value/key or currency migration.

## Durable publication and failures

Objects are stored in private digest shards using complete synced temporary
files, directory sync, rename and another directory sync. Existing exact objects
are checked byte-for-byte and synced again. Failed partials and orphan page roots
remain retained. A full new page path is prepared before changing History's
process-local root. Core stages all event effects in its private clone, then
appends the authoritative event with its normal separately retained journal head,
then installs the clone. A failure before journal append publishes no live state;
a failed authoritative append halts the node with its old live Core. Cold recovery
never treats a derived object as an extra event. A failed replay cannot finish
journal recovery or expose a signing node.

The exclusive disk owner survives through immutable observations, preventing a
second derived-index writer while proof/read workers still hold it. Every retained
file, including partial/orphan residue, counts toward local admission. The index
refuses new objects at 1 TiB / 4,194,304 files rather than deleting records or
claiming an unsupported future capacity. Reservations are conservative after
failed writes; status labels them accounted usage, not measured retained bytes.
Filesystem free space may fail earlier. A corrupted existing object refuses
unchanged. Retain that directory and cold-rebuild a fresh derived directory from
the unchanged valid authoritative journal/head; do not overwrite damage or adopt
an old serialized root. Independent latest-head protection remains separate.

## Actual consumers and finite scheduling

All historical reads now return Result<Option<Arc<Committed>>>: zero/future height
is absent, but missing, corrupted or out-of-profile retained data is an error.
Iteration stops with that error and consumers propagate it; no filtered error
turns a failed read into an absent decision or a new signing position. State/proof
replay streams the requested prefix. Native witnesses refuse more than 4,096 steps
before collecting them. A counting CBOR writer also enforces the guest's existing
1-GiB input bound while constructing steps, without allocating a serialized
complete State merely to measure it. A conservative 128-byte framing allowance
can refuse a marginal input earlier; it never raises the guest bound. Controller preparation and certificate CLI lookup use
exact birth/height lookup rather than a whole-history search. The exact actual
proof inputs remain complete; compact transition witnesses are not implemented.

Public block paging captures only the authenticated History observation under the
node mutex, then reads/encodes outside it under a two-reader semaphore and the
existing response bounds. Ordinary new operations use permanent native decision
indexes before considering historical wrapper deduplication; actual wrapper
retransmissions still check the complete old command and new wrapper evidence.

Journal-derived pending rejection pointers retain only unsent obligations, rotate
16 per recovery turn and reread the exact Reject record before constructing its
normal certified rejection proof. A durable Sent event removes the pending pointer.
No transport or timing event grants refund/import authority. Signer reconciliation
uses process-only exact-binding cursors over already considered native/terminal
prefixes. Cursors advance only after the existing authenticated custody retirement
operation, reset on restart and grant no key/lock permission. Unprocessed failures
retain their work; old controllers still use their original authority.

## Remaining work

The raw byte cache is at most 128 immutable objects / 32 MiB, shared across roots.
Active decoded records, full current State, proof input vectors, receipts, terminal
objects, delivered IDs and other queues remain separate memory costs. This is not
a 32-MiB full node. Duplicate derivative disk objects/page versions retain write and
archive costs. Index writes still occur on the commit path; their latency and disk
amplification are not measured. Full cold replay time remains proportional to
retained events. Complete current-State disk execution, compact authenticated
transition witnesses, disk receipt/terminal collections and archival packing,
paid replica succession, proof economics, independent custody/security and real
physical carriage remain unfinished or unqualified. Native/proof program sources
are unchanged by this host-storage stage; actual final profile comparison remains
required publication evidence.
