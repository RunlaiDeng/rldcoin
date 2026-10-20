# Authenticated service/coupon updates and receiving-family execution

## Question and bounded work

Parent 63db056 still retains every service contract, coupon-use record and receiving
family in resident tables and full native inputs. Services renew/pay down and
coupon uses can close; treating them as append-only would silently lose required
behavior. This stage implements a separate insert/replace map, exact disk paths,
host capture and actual guest/prover execution. Families remain append-only.

The discriminating chain is unchanged native command semantics, same-key
authenticated replacement, normal node startup and historical replay, default
access construction, real guest/prover dispatch and source-bound full compilation.
Work is source implementation/review and bounded compilation repair; no fixtures,
local test suites, proof/payment or performance campaign are created/run. A
compile pass exits this implementation stage, not the project/qualification goal.

## Replacement relation and isolation

Mutable is distinct from Permanent. It exposes get, contains, insert and replace,
not removal. Complete decoding reconstructs the original sorted canonical array
and counted prefix commitment with direct record keys. Insert refuses an existing
key. Replace requires an existing identical key. Private construction and these
paths enforce uniqueness, so repeating complete key scans for services/coupons
and permanent families is unnecessary. Native invariant root/context checks and
all unrelated issuance/controller checks remain.

replace_member first authenticates the old membership, including its entry,
root, rank, counts, split positions and sibling paths. The new entry must have
the exact same key. Starting from its new leaf, fold the same checked ordered
sibling hashes/counts/depths back to the root and require the same total count.
No successor root is accepted. A value change cannot alter the key partition,
topology or path height, so it preserves the certified predecessor's 64-branch
admission bound without a guessed hidden-subtree height. Insert still uses the
existing conservative absent-key rule and typed complete-subtree fallback.

The mutable access tape verifies the actual old typed value, then derives the
replacement root while retaining count. Cloned observations share immutable
supplied material and usage tracking only; monetary roots remain per clone.
Every supplied step must be checked/used. Repeated exact reads may reuse the
same evidence; a later read/update under a changed root requires its own material.
Partial records cannot export all values, serialize as complete State, issue
arbitrary membership/access or become historical storage authority.

The native command relation is unchanged: renewal still requires the renewal
payer, increasing horizon and exact input/change/service conservation; payout
still requires custodians, policy-controlled payouts, exact fee and balance
subtraction; coupon closure keeps all existing source/terminal/owner checks and
sets closed=true. Generic replacement never supplies an authorization shortcut.
Permanent receiving families and decision namespaces gain no replacement API.
Wire record order, native roots/checkpoint format, RLD-only currency/fees,
21-million cap, zero allocation and issuance/work rules are unchanged.

## Full host execution and custody

Normal startup opens service-index, RLD-SERVICE-STATE-DISK-1, with exact currency,
home and genesis binding. Services, coupon uses and families use distinct typed
node domains. All begin empty and acquire roots only by complete native/QC replay.
There is no adoption of a root from a directory, peer or serialized cache. Service
typed reads validate owner policies and sorted positive balance components;
fully paid contracts may retain an empty balance. Receiving-family typed reads
validate issuer, destination and existing count/unit bounds.

Disk replacement authenticates current membership, copies only the retained
immutable path, writes a validated new value and compares the complete resulting
root/count with the independently derived compact replacement. Working roots are
not published until the normal verified boundary seals. The mutable storage
interface exposes no spend/removal path; the existing UTXO interface remains
separate. All old/partial/orphan durable objects stay retained on errors/refusal.

The three maps share a 4,096-object/16-MiB byte cache and 1-TiB/4,194,304-file
retained admission. Each uses the unchanged 8-KiB value, 600,000 reachable working
object, 512-MiB encoded working-byte and 64-branch limits. Those are finite
admission limits, not measured process RAM or capacity. Status reports actual
accounting or an unavailable observation, never zero usage from an error.

Native callers and CLI closure/funding/family paths use fallible point reads.
Missing/damaged data cannot become an absent/unused coupon or an available service
balance. Native storage attachment still checks empty complete placeholders.
Genesis service/coupon/family maps are empty, while the previous authenticated
nonempty fee/cover genesis seeding remains unchanged.

## Complete observation with shared fixed context

History V7 binds RLD-NATIVE-DISK-OBSERVATION-5 and material V8 omits thirteen map
arrays. There are fourteen retained roots because Mint has an auxiliary slot
index. Repeating currency/home/genesis/tag strings in every nested observation
would spend the existing 4-KiB bound on duplicates. The fixed typed codec checks
each original snapshot's canonical bytes, exact role/format/map tag and identical
currency/home/genesis, then stores all complete root descriptors under that one
context and a fixed fourteen-role inventory.

Reconstruction reinstates each exact known format/tag and complete original
root metadata. The Mint pair is reconstructed as well. There is no external
dictionary reference, peer cache, optional root omission, generic compression,
height/count truncation or adopted native head. Wrong inventory/context/kind
refuses. Each normal historical backend still authenticates its full root object,
context, physical digest/length and summary; the complete restored State must
still match its independently verified native checkpoint. Context sharing is
representation only and grants no money, signing, finality or freshness rights.

The encoded observation still refuses above 4,096 bytes. Fourteen fixed Link
descriptors (at most 161 encoded bytes each) plus one format/context and framing
fit below that bound by schema analysis. This is not a fixture/benchmark result.
Old observation/history/material formats refuse without rewriting or migration.
Every derived owner must be retained together during stopped reconstruction;
the anchored journal and separately retained latest head remain authoritative.

## Actual proof input and default capture

NativeInput tag 8 wraps the prior definition/UTXO/permanent/applied composition
with typed service, coupon-use and family access sets. Mint access remains
optional and requires its actual correspondence certificate; bounded complete
Mint material is available when that certificate is absent. Initial root/count
openings authenticate even unread maps. The ordinary real native predecessor
receipt and complete State root bind all three newly partial monetary maps.

Actual guest execution and the real prover precheck run these exact native
relations; the final real unconditional succinct receipt retains the ordinary
native checkpoint journal. No fake proof, unresolved assumption, caller success
flag or host-only state root is accepted.

Default host construction prefers this path with certified Mint, or without it
when unavailable. It captures exact current root/key reads, insert absences and
replacement members from full verified storage. Complete host updates must equal
the compact derived roots/counts, every replayed header must equal immutable
verified history, and only those committed boundaries seal. Capture cannot issue
historical/full-export authority. All metadata, openings, receipts, operations and
steps share the unchanged 1-GiB input bound and per-tape step cap. Only typed
compact-height/capture-capacity refusal selects previous bounded profiles;
authentication, changed data, invalid receipt and I/O errors propagate.

## Remaining completion boundaries

Controllers, incidents and issuance grant/segment tables and their full scans
remain resident. Snapshot/cold replay and proof construction still have complete
material costs; repeated bounded fallback may be expensive. Maximum Argon2id
proof/input feasibility, runtime composition, sustained volume/latency,
power-loss/latest-state custody, paid archive rotation, independent security,
crypto transitions and physical stellar routes remain unqualified. Program/source
bindings change; old descriptors/private state refuse unchanged. No monetary
genesis, keys, balance migration or mainnet is created by this stage.
