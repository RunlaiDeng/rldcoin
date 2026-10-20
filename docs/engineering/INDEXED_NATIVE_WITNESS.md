# Indexed native operation-log witnesses

## Question and implemented observation

The permanent applied-operation map grows with accepted requests although normal
execution queries only an operation ID and appends its exact digest. The stage
question is whether actual guest execution can replace that whole map with
root-bound accesses without weakening monetary execution or the 64-branch rule.
The source observation is the implemented native input/guest, shared executor,
default proof-worker and CLI builder, including full-witness refusal/fallback.
Review the root-update derivation and actual consumers, then compile real guests,
prover and host. No new local fixture/test suite or runtime campaign is run by
owner direction. Source review/compilation is not independent correctness review.

## Witness and predecessor binding

NativeInput tag 2 is IndexedExecution, a flat record containing currency, exact
Certified predecessor, complete other state with an empty complete applied-table
placeholder, native steps and AppliedAccess. Flattening avoids an extra enclosing
record depth around all existing current material. Access has format
RLD-NATIVE-APPLIED-ACCESS-1, the initial root/count and an ordered step per encountered
operation; each step has the exact ID and exactly one membership or absence proof.
All canonical byte, nesting, step-count and existing input bounds remain.

The guest accepts only the empty complete placeholder, creates a private partial
applied index, verifies the predecessor's real recursive receipt and matching QC,
and compares the resulting complete State.root, currency/home and sequence to the
predecessor. The supplied initial root is thus a committed collection value,
never standalone authority. Every first access checks its count inside the actual
root proof. Native batches are nonempty and every operation performs this access;
there is no valid empty-access path that can adopt an unchecked count.

All owner/work/issuance/fees/escrow/controller/import/rejection/cover and other
state checks run through the same native executor. Old operations require an
exact authenticated digest equal to SHA256(canonical complete Operation), advance
the trace cursor and do not execute again. New operations require exact absence,
execute their ordinary rules, then compute the new applied-map root from the
actual ID/digest. The guest compares every computed complete checkpoint to the
carried native header and authenticates intermediate QCs as before. The last QC
remains external to its own execution relation. Completion requires every access
consumed; a missing, changed, reordered or unused access refuses.

## Canonical absent-key insertion

Verify ordered adjacency/endpoints and every carried membership under the exact
current counted prefix root. Select the neighbor with the longest common prefix
with the absent key. Its first differing bit d identifies the insertion position:
ancestors with smaller split bits remain unchanged and the first deeper subtree
becomes one child of the new fork. An existing split at d refuses. Checked path
folding reconstructs that exact old subtree hash/count n. Direction and common
prefix come from the actual keys, never an advertised successor root. Hash the
new leaf and fork using the unchanged native tags and ordered child counts, then
fold the unchanged ancestors and wrap the checked new total count.

For capacity, a non-unary binary subtree with n leaves has height at most n-1.
If k ancestors precede insertion, every moved path is at most k+1+(n-1)=k+n.
Compact admission requires k+n<=64. The new leaf path is no longer than that;
all unaffected predecessor paths inherit their already certified bound. The
empty-map case creates a singleton. Unknown cached heights are not proof inputs.
This conservative argument can fail for a large balanced subtree whose actual
height would fit. A typed CompleteSubtreeRequired result selects full native
execution under its existing limits. Other invalid proofs/errors propagate. No
capacity increase, blind host height, or unchecked new root is permitted.

The canonical root remains exactly the approved counted compressed prefix root.
This is an access proof realization, not a new monetary algorithm or an arbitrary
state-root substitution. A root comparison against the complete rolling host map
also checks the builder's result at every newly constructed access. That host
comparison does not replace the independently executing guest relation.

## Uniqueness invariant and representation

AppliedIndex contains a private complete ordered table or a private access tape.
Ordinary wire State decodes only complete strictly ordered records. Complete
constructors and insertions enforce duplicate exclusion. A tape is created only
inside indexed execution, from the authenticated predecessor root. Exact absent
insertion preserves uniqueness, and duplicate lookup leaves the map unchanged.
The former materialized full-key sorted/unique scan is replaced for this one map
by these private constructors and root-bound transition checks, not by assuming
that an unchecked partial list is the whole map. All other invariant scans remain.

Cloned native states share immutable access bytes and copy only cursor/root/count.
Tentative batch failure publishes no state. An internal partial index refuses
record serialization, complete collection extraction and arbitrary proof issuance;
it cannot masquerade as a full snapshot. Native full execution and genesis keep
the original complete-record wire representation. Omitted records remain in the
host's authenticated current state and archives; the proof does not delete them.

## Default construction and limits

Node proof workers and CLI node-witness exports call native_input. With no
certified predecessor they use complete genesis execution. Otherwise they clone
the exact complete host applied index, derive current membership/neighbor paths
without enumerating its whole contents, and advance that index by the actual
committed operation digests. Witness byte accounting includes both native steps
and all access proofs before retaining an oversized input. The existing 128-byte
framing reservation and 1-GiB/4,096-step bounds remain. Only typed insufficient
height-proof or indexed-byte-budget exhaustion selects full input. The latter
prevents path overhead from needlessly refusing a small complete-map witness;
invalid proof/encoding errors do not silently choose another mode. A full input
exceeding the original bound
still refuses; no successful fallback availability is promised for every history.

The real native guest and real prover both execute IndexedExecution and verify the
same journal. Receipt assumptions still include the exact predecessor and remote
receipts. The backend, unconditional receipt checks and monetary QC composition
are unchanged. New actual compiled image IDs are pinned through the normal
source-bound workflow; incompatible old currencies/stores refuse unchanged.
No monetary genesis, keys, balances, live network or in-place suite migration is
created by this prelaunch implementation stage. Paper/PDF/root rules are unchanged.

The complete host applied index remains in memory. Other large current/permanent
maps still enter the guest in full, full invariant scans remain elsewhere, and
access paths add work/bytes proportional to encountered operations. A partial
index is not a bounded-memory full-node executor or a complete sparse relation
for every table. Worst-case full fallback, proof economics, measured memory,
throughput/latency and independent security qualification remain open.
