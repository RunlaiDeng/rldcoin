# Incremental map-root amendment — owner approved 20 October 2026

The owner explicitly approved this amendment and its implementation, including
matching canonical whitepaper, PDF and official website synchronization.
RLD remains the only payment/fee currency, with 21 million maximum issuance and
zero initial allocation. Historical paper receipts retain their original scope.

## Exact current constraint

Appendix A currently specifies:

> For n>1 leaves the tree splits at the largest power of two strictly below n;
> a singleton is its leaf hash, and an empty tree has a distinct tagged hash.

The current root is a Merkle tree over strictly sorted entry positions. For four
keys a<b<c<d its tree is H(H(a,b),H(c,d)). Inserting x<a produces five sorted
leaves and the tree H(H(H(x,a),H(b,c)),d). Previously retained pair hashes are
not the new pair hashes. More generally, arbitrary insertions can invalidate
many positional groupings. The current implementation rebuilds them. The example
is symbolic source analysis, not a benchmark or a general lower bound against
all possible additional authenticated caching constructions.

Persistent native value tables can improve cloning, lookup and record mutation
while preserving this root exactly. They do not by themselves make arbitrary
ordered-root updates logarithmic. Global capacity may also be distributed across
distinct funded homes; neither alternative is measured by this proposal.

## Proposed replacement text for the state-map paragraph

State maps use counted binary Merkle prefix commitments over their 32-byte keys.
Each collection tag binds currency, home and map name. A leaf hashes that tag,
its exact key and canonical value. A nonempty branch splits at the first bit at
which the keys in that subtree differ; keys with bit zero are its left child and
keys with bit one its right child. Its hash binds a separate internal-node tag,
the split-bit position, the exact common prefix, both ordered child hashes and
both child counts. There are no one-child branches. A singleton is its leaf hash,
and an empty tree has a distinct tagged hash. The collection root additionally
binds its tag and total leaf count. This construction depends on the entry set,
not the insertion order.

Membership carries the exact leaf, its ordered index and total count, and the
split position, sibling hash and sibling count at each branch on its path.
The verifier reconstructs each common prefix and branch direction from the
requested key, checks strictly ordered split positions, accumulates checked
counts and rank, and reconstructs the exact collection root. Absence authenticates
adjacent ordered members or exact endpoints under that same counted root.
Proofs retain the reference bound of at most 64 carried branch siblings. Native
admission refuses a mutation whose resulting map would exceed that bound before
it can create an unsupported monetary state. This is a finite resource refusal,
not a claim that all future key distributions or histories fit forever.

Native execution authenticates every touched old value against the predecessor
root and computes the resulting root. Persistent value storage and authenticated
map nodes are reconstructed from complete validated state or exact authenticated
access material; cached pointers and caller-supplied roots confer no authority.
Total counters, pool indices and every permanent monetary/issuance/decision map
remain committed. Changing a root never deletes an old decision, mints RLD,
releases escrow or resets a namespace.

## Approved implementation and publication scope

- Replace the positional map primitive with the specified counted, compressed
  prefix tree. Keep full owner/work/conservation/terminal checks and all existing
  amount, capsule, receipt, signature, controller and sibling refusal bounds.
- Integrate native persistent tables, membership/absence verification, receiving
  coupon trees, disk witness pages and current/proving data paths. An unused
  optional primitive would not count as adoption or completion.
- Build actual native/controller guests and the real prover; publish the exact
  new image/source binding. Old program descriptors/private stores refuse without
  rewrite; there is no monetary genesis or old-value/key migration in this stage.
- Revise only the corresponding canonical paper paragraph, downloadable paper
  artifacts and matching website exposition. Keep development status, resource
  qualification and release evidence in engineering documents. The revision
  needs its own exact source/body/PDF/publication receipt.

The proposed root change does not finish compact transition witnesses, a bounded
memory disk executor, funded archival succession, cryptographic suite upgrades,
proof economics, runtime throughput/latency qualification or physical carriage.
Those requirements remain. Mainnet authorization is still conditional on actual
functional completion. The owner requested source review/compilation without new
local fixtures or test campaigns; this proposal does not silently override that.

## Decision

On 20 October 2026 the owner selected “approve amendment and implement”. This
supersedes the fixed positional-root paragraph only within the described scope.
Implementation, compiled program identities and published artifact bindings are
recorded separately; approval itself does not establish runtime qualification.
