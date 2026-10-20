# Incremental native state commitments

## Decision and discriminating source observation

The previous position-based Merkle grouping changed after an ordered insertion;
sharing value tables alone did not eliminate full map hashing. The owner approved
`docs/proposals/INCREMENTAL_MAP_ROOT_AMENDMENT.md` on 20 October 2026, including
the corresponding paper/PDF/website amendment. This stage implements that exact
choice. The bounded source-review question is whether normal execution and witness
paths actually use the amended map, with complete authorization unchanged. A
passing compile establishes type/build integration only, not runtime correctness.

## Representation and commitment

`protocol/table.rs` retains primary-order records in an immutable AVL tree.
Segment keys are (grant,cursor), incidents (family,anchor), and other keys retain
their former ordered identities. Host pointers use Arc; guest pointers use Rc.
Neither topology, pointer, subtree size nor a serialized cache is accepted from
wire State. Complete strict ordered records reconstruct the private tables.

Each Table also retains an immutable counted compressed binary prefix map over
its exact native Entry keys. For hashed segment/incident keys that order differs
from the primary lookup order. Leaf/value hashing has one Record implementation,
used both for incremental mutations and complete material construction. Map tags
bind currency, home and collection. Insert/replace/remove stage both private roots;
errors publish neither. A replacement cannot change either key; cursor changes
explicitly remove and insert. Shared old nodes remain immutable.

A branch splits at the first differing bit, contains two nonempty ordered children
and binds split depth, masked common prefix, ordered child hashes/counts. Singleton
and empty cases are distinct, and the root binds total count. Construction is
canonical for a set, independent of AVL shape or insertion order. Private mutation
rebuilds only the affected paths and refuses height greater than 64 before state
publication. Counts, heights and index arithmetic are checked. This retains finite
refusal, not an all-history or all-distribution availability guarantee.

Membership carries root-to-leaf strictly increasing split bits, sibling hashes
and counts. Reversal reconstructs hashes and checked rank/count. Adjacent ordered
members or exact endpoints authenticate absence. A witness authenticates only its
exact expected root; current ownership, execution, permanent decisions, lineage,
QCs and receipts still require their ordinary checks. Counters and every permanent
map remain in State.root. Full invariants remain on executed states.

## Actual integration

State cloning shares table roots; native monetary operations use checked indexed
lookups, inserts, replacements and removals. State.root reads cached collection
roots, then constructs the fixed small collection/counter tree. State.witness
uses the retained map key path. Current execution and historical proof observations
share these immutable states. Receiving-family roots and paths use the same map
primitive, without raising capsule/receipt/input/owner/signature limits.

Disk index V2 partitions at the same differing bit and binds counts in its native
hash. Every page read rechecks its exact digest/profile/ranges and hash; complete
paths are independently verified against the retained native checkpoint. Traversal
and combined proof depth are bounded. Full cached State decoding reconstructs all
private indexes and verifies its root. Cold ledger startup still replays the
journal. No manifest, lookup range or cached pointer supplies monetary authority.

## Review findings and limits

Introducing a source subdirectory exposed inconsistent path ordering between the
Python executable-profile inventory and Rust build guard (state.rs versus
state/wire.rs). Both now sort canonical UTF-8 slash-separated relative names.
The refusal was retained; the guard was corrected, not bypassed. Final source and
actual programs must be bound after compilation. Old program/currency/index
bindings refuse; no monetary state/key migration is implemented or authorized.

Complete records and both in-memory indexes consume memory. Complete decode,
full invariant scans, snapshot/page publication and full transition witness input
remain. This stage is not a sparse executor, bounded-memory native disk engine,
funded archival succession, suite upgrade, independently reviewed proof relation,
measured proof economics, daily volume or receipt-latency result. The owner
requested no new fixtures/local test suites or runtime campaigns. Source review
and compilation are reported separately from those absent observations.
