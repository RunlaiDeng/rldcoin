# Native UTXO disk execution and indexed proof input

## Source question and bounded stage

Parent 224dbe5 has six indexed maps but retains the entire unspent Output table
in host memory and native guest input. The active question is whether ordinary
payment inputs, spends and change can use exact native disk paths and checked
accesses while preserving complete monetary execution and historical evidence.
The discriminating paths are Outputs validation, native delete derivation, disk
mutation/seal, historical reconstruction and actual host/prover/guest input.
This stage uses implementation, source review and compilation repair; it creates
no fixture, local test suite, payment/proof run or measured performance campaign.

## Output invariants and deletion

Outputs privately wraps a complete native table, an indexed access map or a host
storage observation. Canonical wire State retains the same complete Output array
and position. Complete constructors check sorted/distinct IDs and validate every
record's exact home, owner and positive, ordered, at-most-64 components plus checked
amount sum. Every insertion, read and record stream validates those properties;
removal checks the actual record first and requires the returned record to agree.
The immutable record API exposes no in-place mutation or replacement. Native
allocation, current cover/incident usability, actual input-owner authorization,
input uniqueness and per-cover conservation remain in the same executor.

Whole-table UTXO key/home/owner/component scans in State.invariants are replaced
by these private construction/mutation invariants. Genesis is empty. Complete
wire reconstruction validates every record; indexed execution starts only from
an exact real certified predecessor root. New outputs always validate before
insertion; spending removes an existing checked record and cannot introduce a
new invalid one. No unchecked serialized metadata establishes that induction.
Other native invariants remain unchanged.

remove_member first authenticates the complete native membership/rank/count/path.
A singleton becomes the canonical empty root. Otherwise its immediate fork
collapses to the authenticated sibling hash/count, and the remaining ancestors
are rebuilt with their original depths, authenticated siblings and the same
prefix representative. Removing one leaf cannot increase a certified <=64 path.
The resulting total must equal old_count-1. Disk spend and host capture compare
this independently derived root with their complete path mutation. The guest
computes it directly. No caller supplies an accepted successor root.

## Reachable working paths and durable objects

Private utxo-index uses RLD-UTXO-DISK-1 with exact currency/home/genesis. It opens
at an empty observation and reconstructs roots only through complete native/QC
journal replay. Fixed branch/leaf metadata pages are at most 512 bytes; complete
Output records use separate exact objects bounded by 8 KiB. The native owner's
16-key and 64-component bounds imply a smaller complete Output encoding, so this
physical split accommodates supported maximal records without putting their
bytes into fixed pages. Native leaves still hash the actual typed Output.

Physical pages bind complete child objects, native subtree hashes/counts,
ranges, depth and height. Reads check exact canonical bytes, digests, lengths
and retained summaries. Value reads also check typed Output hash/home/properties;
membership/absence verify the exact native root. Bad or missing bytes are errors,
never missing inputs, zero balances or absence proofs.

Candidate updates use immutable Arc paths. Each current working node retains only
its reachable working children and optional value bytes. Updating a path releases
unreferenced unpublished intermediate nodes; frozen descendants are shared by
physical links. This drops only unsigned temporary material, never published
native evidence. No growing flat map copies every preceding tentative version.
Each working observation bounds reachable encoded material by 600,000 objects /
512 MiB. Native batches have at most 64 operations and each operation at most 64
inputs / 64 created outputs. At most 8,192 updates, 65 path nodes per update and
4,096 new value objects fit those bounds: 8,192*66 <600,000 and
8,192*65*512 +4,096*8,192 <512 MiB. This is a source size bound, not measured RSS;
Arc/struct allocations, overlapping versions and concurrent workers add costs.
The other maps retain their separate original working budgets.

The shared raw cache is independently bounded by 4,096 objects /16 MiB. The
private object owner admits 1 TiB /4,194,304 retained or reserved files, including
partials/orphans. Sealing walks only working nodes, durably publishes exact values
and pages, and returns a frozen observation. Core does that only after complete
native execution, exact header and matching QC, before verified history and
authoritative event/latest-head publication. A failed stage installs no live
candidate; every durably published residue remains. Spent outputs leave the
current root, but their physical objects and old historical roots are retained.
No timeout prunes evidence or refunds exports.

## History and actual executable witnesses

History V4 binds RLD-NATIVE-DISK-OBSERVATION-2 containing seven sealed map
snapshots. State-material V5 omits these arrays, then requires the separate
verified-history observations, empty placeholders, complete invariants and exact
whole native checkpoint root before returning State. No filesystem root can
initialize or advance a ledger. Direct current/historical UTXO queries use paths;
public complete snapshots/balances and full fallback stream records and propagate
errors. The wallet builder selects actual inputs by point lookup rather than
scanning all UTXOs.

NativeInput tag 4 (IndexedUtxo) adds typed Output accesses to tag 3's permanent
and applied accesses. It requires a complete empty Output placeholder, verifies
initial root/count openings, actual typed member or absence and every append or
spend at the current root/count/key. Native input-owner, fee, issuance, cover,
conservation, header/QC and real recursive receipt checks remain the same.
Every supplied access must be used; repeated reads reverify the same exact proof.
Usage is shared across execution clones solely for completeness checking; roots
and counts remain per clone. Partial maps cannot export complete State or issue
arbitrary membership. The executor uses the final returned State for completion
checks without cloning all access vectors again.

The normal builder prefers tag 4 from a certified predecessor, captures actual
reads/inserts/spends during complete verified native replay, compares every whole
header and compact update root, and seals only already verified step boundaries.
All seven sets share the unchanged 1-GiB canonical input budget plus its existing
128-byte framing allowance; each typed record set retains the 2,000,000 unique-access bound; applied retains
its existing 4,096*64 ordered-access bound.
Only typed compact insertion-height or capture-capacity insufficiency selects
tag 3, then its existing tag 2/full fallbacks under original limits. Other errors
propagate. Genesis remains full. A full input that cannot fit still refuses.
The actual real prover and guest support tag 4 and the same native journal.

## Boundaries

The paper/root algorithm, RLD-only money, 21-million cap, zero allocation and
monetary rights remain unchanged. Actual program/source bindings change and are
rebuilt/pinned; old monetary descriptors refuse without rewriting old state,
keys or balances. No monetary genesis/keys/network are created here.

Other native maps and active-controller/mint scans still require work. Immutable
file/write amplification, packing/rotation, paid replicated archives, secure
latest-state custody, cryptographic transition and physical routes remain open.
Maximum-size witness/proving feasibility and RAM, latency, daily throughput,
crash/power-loss and independent security are unmeasured/unqualified. Compilation
is separate from these obligations and does not establish mainnet readiness.
