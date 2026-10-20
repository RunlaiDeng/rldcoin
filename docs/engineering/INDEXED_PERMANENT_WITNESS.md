# Indexed native execution for five permanent maps

## Stage and question

Parent 9702763 executes five permanent maps on disk but still includes every
birth, destination decision, redemption, source resolution and consumed funding
record in an actual native proof input. The active question is whether exact
root-bound accesses can replace those five complete guest arrays while preserving
the existing complete native executor, monetary checks and predecessor binding.

This stage ends with the implemented builder/guest/prover chain, source review,
compilation repair and final actual program/source comparison. No fixture, local
test suite, proof/payment campaign or measured capacity result is introduced.
A missing check is repaired, never replaced with a claimed runtime pass.

## Input, roots and typed values

NativeInput tag 3 (IndexedPermanent) contains the existing indexed-native fields
plus five typed RLD-NATIVE-PERMANENT-ACCESS-1 maps. Genesis remains full execution.
The six serialized State placeholders must be empty complete maps. The guest
installs the applied tape and five permanent access maps before verifying the
real certified predecessor and its exact complete State root. Currency, domain,
configuration, sequence and native successor headers still use the same executor.

Each permanent map declares its initial native root/count. An empty map requires
the canonical empty root and no opening. A nonempty map requires a verified native
membership opening whose path count equals the declared count. This authenticates
that count even if this execution never reads the collection. The root itself is
bound through the predecessor's complete native State root, not a host signature.

Each access names exact current root, count and key. It carries either one complete
typed record plus native membership, or native absence and no record/member.
The typed record's direct key and exact normal record hash must match the proven
entry; currency/collection tags remain unchanged. Both types of proof verify
against the current native root/count, including existing neighbor/endpoint
requirements for absence. A missing or malformed access refuses; it cannot become
an absent decision, unredeemed controller or unused funding capability.

An append first verifies that exact absence, then computes the new counted prefix
root with the existing insert_absent derivation and checked count increment. It
retains the existing conservative 64-branch guard. Unsupported hidden-subtree
height evidence is a typed need for complete material, not a guessed height or
relaxed admission. No replacement or deletion is exposed.

## Reads, clones and completeness

Permanent accesses are indexed by (root,key), with duplicate pairs refused. A
repeated read at the same exact root reuses its proof but verifies it again.
Monetary roots/counts are copied per State clone and update only after successful
append derivation. Shared usage observations record which proof indices have been
verified. They do not supply values, bypass authentication, change roots, release
locks or grant monetary authority. The actual execution is the same linear native
batch loop; failed execution yields no journal.

Every supplied access must be used by successful checked execution; finish rejects
unused evidence. Empty access sets are permitted only with the authenticated
initial root/count opening above. Serialization, complete-record enumeration and
arbitrary membership issuance from a partial map refuse. Usage synchronization is
host-only Mutex or single-guest RefCell; mutable usage is not signed state. Raw
wire input still decodes ordinary complete empty placeholders, never a serialized
partial State. Five-map access order is a first-use host encoding, not a new
consensus ordering rule: exact roots/keys and complete usage determine execution.

## Actual host construction

The ordinary native_input path and CLI witness command prefer IndexedPermanent
when a certified predecessor exists. The builder replays exact already verified
native records using complete disk observations wrapped with host-only capture.
Actual get/insert calls capture typed values and proof paths. It deduplicates
identical (root,key) accesses, refuses changed retained evidence and independently
derives each compact insertion root against the complete native successor.
Every replayed whole native header and applied-map root must match verified
history before sealing that already committed step. Candidate capture state has
no snapshot/export authority. Capture extraction requires every execution wrapper
to have been dropped; it moves the completed access vectors, not copies of all
historical maps.

One shared counting-CBOR budget covers remaining complete State, receipt/base,
step material, applied accesses, permanent openings and unique typed accesses,
with 128 framing bytes under the unchanged 1-GiB guest input bound. Each permanent
access set also has a 2,000,000-record bound in both capture and guest admission.
The budget is finite admission, not an assertion that maximum inputs are practical.
Indexes, decoded records, usage sets and encoded inputs add separate memory costs.

Only typed compact-height insufficiency or capture-capacity exhaustion selects
the original applied-only indexed input, then its existing full fallback under
original bounds. Authentication, replay, changed-data, I/O, context and encoding
errors propagate. Genesis always uses full input. A full input that cannot fit
still refuses. The actual host precheck and real guest both execute tag 3 and
produce the same unchanged native journal; real unconditional receipt resolution
and exact image checks remain mandatory.

## Scope and remaining obligations

This implements compact executable material for applied plus these five permanent
maps. Other native collections still need full execution material, disk execution
and/or better invariant/active-state indexing. Host capture still performs native
replay and actual required scans; moving an array out of the input does not prove
seconds-scale receipt, acceptable proving cost or 100-million daily capacity.
Fallback may be required and its finite capacity is not waived. No measured proof
size, cost, memory, throughput, latency, crash behavior or independent security
qualification follows from compilation. Long-history archives, paid replicas,
cryptographic transition and physical stellar routes remain open.

The native/controller program binding changes and is rebuilt/pinned to actual
real guests/prover before the final host build. Old descriptors refuse unchanged;
no currency/value/key migration or monetary genesis is performed. The paper,
counted prefix algorithm, fees, RLD-only currency, 21-million cap and zero initial
allocation remain unchanged.
