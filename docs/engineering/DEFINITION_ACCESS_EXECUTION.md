# Immutable acceptance and fee definition execution

## Question, scope and exit observation

Parent 3e3063d keeps every acceptance Cover and historical FeePolicy in resident
tables and complete native inputs. Both are immutable, content-addressed and only
appended by native operations/genesis; retaining all of them in each ordinary
proof is unnecessary. This stage moves their actual execution to checked immutable
disk paths and their guest execution to authenticated typed accesses. It also
removes the redundant all-cover key scan and full cover searches in mining/wallet
callers. Mutable families, services, coupons, controllers and issuance maps remain
separate unfinished work.

The discriminating source chain is native representation and callers, ordinary
startup, genesis/historical reconstruction, exact state/checkpoint roots, default
capture, real guest/prover dispatch and final source-bound full compilation. The
bounded stage is implementation/review with compilation repairs, not a new local
fixture, test suite, proof/payment or performance campaign. Failed compilation
observations are kept in the compile receipt; a build cannot establish runtime
behavior or qualification.

## Monetary and logical invariants

State covers and fee_policies now use the existing Permanent interface. Their
complete canonical wire arrays and direct content ID keys remain unchanged.
Cover leaf value equals its RLD-COVER hash; FeePolicy key/value equal its existing
RLD-FEE-POLICY hash. Counted prefix roots, native top roots/checkpoint format,
real proof requirements, RLD-only currency, 21-million cap, zero allocations,
work/reward, positive owner-authorized fees and acceptance rules are unchanged.

Sorted private constructors and duplicate-refusing append ensure unique keys.
These definitions were never replaced or removed by the native command relation;
the new interface makes that restriction explicit. Root-context checks remain in
invariants. Complete wire decoding reconstructs records rather than adopting a
pointer/root. Removing the repeated all-cover key vector/sort check does not
remove a native uniqueness obligation. Covers are validated on existing native
admission/acceptance paths and each disk typed value read/publication; fee-policy
validation and exact historical equality checks are retained.

Native cover and fee-policy reads are fallible, owned observations. Missing or
damaged data cannot become "not present". Cover collision checks compare the full
typed record; historical fee policy checks compare the full policy at its content
key. Native cover lifts, destination acceptance, incident quarantine, source
sponsor and fee rules still execute. Mining work resolves only distinct covers
needed by its selected grants, in content-ID order. Payment/claim builders and
wallet balance display resolve exact cover IDs. Missing wallet definitions now
refuse instead of accidentally appearing unquarantined.

## Private storage and nonempty genesis

definition-index binds RLD-DEFINITION-DISK-1 to exact currency/home/genesis. Two
typed Paths use distinct RLD-COVER-PATH-1 and RLD-FEE-POLICY-PATH-1 domains and the
same already-adopted counted native hashes. No stored head is opened as authority.
Only completely validated native genesis/replay derives roots. Definition values
and path pages retain complete canonical bytes; physical digest/length, node
summary, native hash, range/count and context are checked before use.

Genesis already contains a fee policy and the bootstrap home also contains an
initial cover. They must not be overwritten by empty storage. Initialization
copies those validated complete records into empty backings, compares both exact
root and count, then seals. Historical fallback creates the actual validated
genesis again and seeds its fresh empty definition observations before attaching
the complete ten-map backings. Seeding refuses a nonzero sequence or nonempty
target. It is private reconstruction of an authenticated genesis, not peer state
adoption, a monetary genesis ceremony, allocation or value/key migration.

History V6 records ten-map observation V4, retaining the existing 4-KiB bound.
State material V7 omits those ten arrays; historical restoration takes their
observations from independently verified native history and checks the complete
native state root after attachment. Old format/domain observations refuse without
rewrite. Capture wrappers cannot issue historical observations, so only the
underlying full host roots seal at already verified native boundaries.

The unchanged observation bound follows directly from the CBOR schema: a Link
needs at most 161 bytes (including object, IDs, maximum-width counts and depth);
each Paths/applied snapshot is at most 296 bytes, each tagged Permanent snapshot
at most 376, and the pair of Mint snapshots at most 631. Five Permanent snapshots,
one applied, three Paths (UTXO and definitions), one Mint pair and at most 64
outer/framing bytes give at most 3,759 bytes. These are conservative encoding
upper bounds from the current fixed schemas, not measurements or fixtures.

Both definition paths share one existing Objects owner: 16-MiB/4,096-object raw
cache and 1-TiB/4,194,304-file retained admission. Published partial/orphan/old
objects remain. Each working path still refuses above 600,000 reachable objects
or 512 MiB encoded working bytes. Original value types and FeePolicy keep 8 KiB;
Cover uses the existing 1-GiB complete input cap rather than a coin-record bound.
The working admission may refuse earlier. Large values bypass the smaller cache;
decoding/validation/capture may allocate substantial temporary memory. This is
not a measured resident-memory, maximum-record feasibility or latency guarantee.

## Actual sparse execution and default construction

NativeInput tag 7 wraps the existing UTXO/applied/permanent input, two typed
definition access sets and optional certified Mint access. Existing tags keep
their distinct purposes. Definition placeholders must be empty and complete.
The tapes authenticate their exact collection contexts, roots and initial count
openings (or canonical empty roots), even when a collection is not touched. The
ordinary real native predecessor receipt and complete state root authenticate
both monetary definition roots before execution.

Every read verifies its typed canonical record under the exact current root/key/
count. Append proves prior absence and derives the next native prefix root; no
supplied successor or cache summary authorizes an update. Shared usage tracking
is distinct from per-observation monetary roots. All supplied steps must be used;
partial map export, arbitrary membership and storage adoption refuse. The same
unchanged native owner/work/fee/cover/controller/issuance checks run in the actual
guest, and the real prover precheck executes that same relation before proving
and verifying its exact native journal.

Default construction first tries definitions plus certified Mint accesses when
the exact correspondence is retained, or definitions plus complete Mint material
when absent. If the first mode suffers typed compact-height/capture-capacity
refusal, definition access with full Mint is attempted separately; a Mint-only
compact limitation must not force full definitions. Prior bounded profiles remain
fallbacks only for these typed capacity errors. Invalid receipt, changed claim,
I/O or authentication failure propagates. All input material/metadata/openings
and captured accesses share the unchanged 1-GiB counting-CBOR budget. Every host
replayed header must match verified history, and only those committed steps seal.
No proof lane/concurrency limit, branch or native/capsule bound is raised.

## Remaining completion boundaries

Other current collections and their scans, complete snapshots and historical
replay still require work. Proof construction can retain substantial access
material and full fallback may not fit. Actual Argon2id proof cost, maximum input
feasibility, runtime composition, sustained volume/latency, paid archival rotation,
independent latest-state custody/security, crypto transitions and physical stellar
routes remain unqualified. New program/source profiles refuse incompatible old
descriptors/stores; they do not migrate balances, heads or keys. No monetary
network is created or started here, and functional-completion authorization for
mainnet is not fulfilled by this stage's compilation.
