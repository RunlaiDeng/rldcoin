# Disk-resident verified execution receipts

## Source question and bounded stage

Parent 34d79c6 retains every Certified execution receipt in Arc<Vec<Certified>>.
Core staging clones the vector on append; scheduler preparation also enumerates
all historical receipts. This stage asks whether immutable disk observations can
serve exact height, strict predecessor and inclusive successor queries without
retaining or copying that collection in every node/proof observation.

The discriminating source paths are verified Event::Proof publication, empty
initialization/full cold replay, path insertion and the consumers of all old
vector operations. The bounded work is one implementation and source-review /
compilation repair pass, ending with a source-bound workspace build and actual
host/prover profile comparison. No runtime fixture or local test suite is added.
A missing authority check or incorrect selection is a defect to fix, not a reason
to narrow the receipt or monetary contract.

## Authority and immutable storage

`receipt-index/` uses RLD-VERIFIED-RECEIPT-INDEX-1 and the exact currency, domain
and genesis binding. Opening it returns an empty root regardless of retained
files. Cold opening still fully replays the separately anchored authoritative
event journal. Each Event::Proof verifies the real unconditional succinct receipt,
exact program/journal, QC and exact local history header/configuration before
calling the private insertion method. An unverified peer receipt never enters
this index. Cached bytes do not substitute for a real receipt verification at
that boundary or in monetary proof consumers.

The index is a compressed binary prefix tree over nonzero u64 native sequences.
Leaves bind the sequence and the physical object containing the complete original
Certified bytes. Branch pages bind exact ordered ranges, counts and child objects;
the branch depth is the first differing key bit. Child depths strictly increase
and cannot exceed 64. Reads verify complete canonical bytes, length/digest and
recompute every retained summary. The separate 4-KiB page bound does not reduce
the existing 16-MiB complete carried-object bound. Certified records use that
same complete-object bound; the actual receipt still has its independent limit.

Insertion copies only the affected immutable path, retaining old roots. The
u64 key depth bounds a lookup to at most 64 branches. Exact queries descend by
key bits. Strict predecessor chooses the right subtree if its first key is less
than the requested sequence; otherwise it chooses the left. Inclusive successor
chooses the left if its last key reaches the requested sequence; otherwise the
right. Global range checks establish existence before those descents. Missing or
damaged objects return errors, never fabricated absence. Count/range arithmetic
and publication cardinality are checked. Existing matching headers keep the
first completely verified wrapper; every later envelope is still verified before
that deduplication.

Complete receipt bytes and newly copied pages are durably published using the
shared private immutable-object implementation before the staged Core appends
its authoritative Event::Proof. Only successful journal/latest-head publication
installs that Core/root. A failed write/append leaves all partial/orphan files and
the previous live root intact; an authoritative append failure halts signing.
No serialized root is loaded, exported as adoption evidence or used to skip
native replay. A retained object or digest grants no money, finality or freshness.

## Integration and resource boundary

Core and ProofContext now retain a small immutable root plus a shared raw cache,
not every decoded certificate. Birth evidence queries exact height; recursive
native proving selects the greatest strictly preceding certificate; retained
rejection recovery selects the least certificate at/after its committed decision.
CLI closure, service-funding and coupon evidence retain exact-height semantics.

Proof scheduling reads only the needed current/birth heights rather than making
a set of all historical certificates. It shares repeated birth-height results
within one scheduling observation. Selection runs on a blocking worker outside
the live mutex; errors are reported, not converted into unfinished proof targets.
Current-certified and state-proof HTTP queries similarly capture an immutable
observation under the mutex and read complete receipts outside it with the
existing two-reader admission bound. Status reports root-observed latest height
and object accounting; this does not promise immediate disk availability.

This private index has its own 4,096-object / 16-MiB raw cache and conservative
1-TiB / 4,194,304-file admission, including retained partial/orphan files. Decoded
certificates, proving jobs, response bytes, other caches and remaining native
collections add separate memory costs. Failed reservations may overcount until
verified reopen. All published versions remain; there is no pruning, packing,
paid archive rotation or disaster-recovery qualification. These finite limits
can exhaust and do not demonstrate 100-million daily payments.

To rebuild a damaged derived receipt index, stop the node and every reader/proof
worker, retain its whole directory privately, and cold replay the unchanged valid
journal/latest head into a fresh receipt-index directory. Do not alter currency,
keys, balances, native history or independent heads, and do not merge roots from
the old directory. No monetary genesis or network is created by this stage.

The paper, root algorithms, native relation, actual proof programs, fees, RLD-only
currency, 21-million cap and zero allocation are unchanged. Source review and
compilation do not establish runtime selection correctness, measured memory,
latency/throughput, crash/power-loss custody or independent security. Other native
maps, queues, paid archives and cryptographic succession remain unfinished.
