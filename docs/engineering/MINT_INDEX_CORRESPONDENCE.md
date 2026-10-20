# Real recursive Mint index correspondence certificates

## Question and bounded stage

Parent 3941d24 keeps exact disk event/slot indexes, but the real native input still
requires every MintRecord. A host auxiliary root cannot replace those records.
This stage implements a real recursive certificate of the exact relationship
between event and slot roots, including ordinary generation, verification,
publication and recovery. It is a prerequisite for compact Mint execution;
monetary native input does not yet consume this certificate as an access map.

The discriminating chain is actual guest relation/journal, real assumption
resolution, host input construction, lane/CLI invocation and source-bound durable
publication. Work is implementation, source review and compilation repair, with
no fixture, local test suite, proof/payment run or performance campaign.

## Pure claim and actual relation

NativeInput tag 5 (MintIndex) uses the existing real native program with distinct
RLD-MINT-INDEX-CORRESPONDENCE-1 journal purpose. Claim binds exact currency/home,
native event root, auxiliary slot root and common count. It is not a native
checkpoint, admission, controller decision, owner signature or issuance permit.
No native money root, array, fee, reward/cap rule or journal format is changed.

Three mutually exclusive bases are supported. Empty starts at the two canonical
empty maps. Complete material reconstructs both indexes from the entire canonical
Mint array and permits no mixed update list. Recursive material verifies an
unconditional real predecessor certificate under the exact native image/control
parameters and requires the same home. Mixed bases refuse.

At most 4,096 appends follow empty or recursive bases. Every record validates its
existing root/slot/owner bounds. Both event and slot absences must match the
current common count and exact current roots. The guest computes both successor
roots from the actual event record and corresponding (root,slot)->event entry,
then checks count increment and the global finite slot budget. The existing
compact insertion-height guard remains; no supplied successor root is accepted.

Starting empty gives exact empty correspondence. Complete construction gives
one slot entry for each complete event and rejects duplicate events/global slots.
Each checked append adds exactly the same new fact to both previously related
maps, with both absences proving it was not already represented. Recursive real
receipt verification carries that invariant, including canonical native roots
and count, to the next claim. It does not prove work, ownership, ordering, local
admission or a monetary checkpoint; those remain the native monetary relation.

The actual guest dispatch and actual rld-prover native command support tag 5.
The host precheck executes the same relation. Nested predecessor receipt fields
enter the existing assumption resolver; the final unconditional succinct receipt
must verify and have exactly the expected purpose/journal before release. There
is no host success boolean, fake backend or unresolved-assumption fallback.

## Source-bound input construction and scheduling

ProofContext chooses a stored verified correspondence no later than the requested
local checkpoint, checks its actual receipt and exact observed base roots, then
streams target Mint events. Retained equal facts need no append; changed retained
facts refuse. New facts obtain both native absence paths, derive compact roots
and compare them with complete host updates. Only after the entire pair equals
the exact already verified target observation can those private working roots
seal. Intermediate uncommitted subsets never publish.

A shared counting-CBOR budget applies the existing 1-GiB input limit with 128
framing bytes. Only typed compact-height or append/byte-capacity insufficiency
selects complete reconstruction under the same limit; authentication, context,
read and changed-data errors propagate. A complete input that cannot fit refuses.
Target enumeration still streams historical Mint events and may reconstruct
historical State; this does not eliminate host replay/cold-history costs.

A fourth independent proving lane first produces the empty correspondence, then
uses monotone retained Mint counts and verified-history observations to locate
the first changed native checkpoint after its latest anchor. Each actual job
retains the complete exact input, bounded attempt state/diagnostics and actual
receipt in the existing proving workspace. All four lanes share the unchanged
configured concurrency (default three) and resource budget. Native settlement,
contact ticking and direct cancellation remain separate workers/relations.

## Verified catalogue and authoritative event

mint-proof-index uses RLD-MINT-INDEX-CERTIFICATES-1 with exact currency/home/genesis.
It opens empty and reconstructs roots/latest-anchor observations by full anchored
event replay. Typed RLD-MINT-INDEX-REF-1 paths bind complete claim plus exact
certificate object digest/length, keyed by native Mint event root. Complete receipt
bytes are retained separately; raw cache remains 4,096 objects /16 MiB and local
admission 1 TiB /4,194,304 files. No serialized catalogue head is adopted.

A new journal event verifies the actual correspondence receipt and exact local
checkpoint Mint pair/count before staging catalogue insertion. Claim-conflicting
verified duplicates refuse; an unchanged root keeps its first verified wrapper.
Complete object/path publication precedes authoritative event/latest-head append;
only successful append installs the new Core/catalogue/latest observation. Failed
partial/orphan bytes remain; an authoritative append failure halts signing under
the existing rule. The latest pointer is a small root/height observation, not a
resident list of all certificates. Reads check full canonical bytes and exact
claim/reference context; missing data is an error, never a missing-proof default.

The certificate itself contains no native height authority. The local event's
height is separately checked against immutable native history. A proof for an
invented event set cannot be installed as that local checkpoint or used as its
native quorum certificate. Future compact Mint execution must additionally bind
the certified event root to its real native predecessor and authenticate every
actual event/slot access; that integration remains open in this stage.

## Operator paths and remaining scope

Ordinary configured proving runs the lane automatically. node mint-index-witness
writes a bounded tag-5 input at a retained height (zero for genesis). The ordinary
rld-prover native command proves it. node mint-index-certificate reads the resulting
receipt, derives the expected exact local claim at the requested height, verifies
and durably publishes it, then writes the certificate. These commands do not
create monetary keys/genesis or start a network.

Compilation and source review do not establish actual proof cost, feasibility,
resource use, latency, throughput, crash/power-loss or independent security.
Compact Mint monetary execution, other collections, file/write amplification,
paid archival rotation, crypto transition and physical routes remain unfinished.
The paper, counted prefix algorithm, RLD-only currency, 21-million cap and zero
allocation are unchanged. Actual program/source bindings change; old descriptors
refuse without rewriting old currency, keys, stores or values.
