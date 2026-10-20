# Certified sparse Mint execution

## Question and discriminating implementation

Parent 97ec449 proves and retains event/slot correspondence but native monetary
inputs still contain all Mint records. This stage consumes that actual relation
inside ordinary native execution, using authenticated point, predecessor, range
and append operations. The bounded work is source integration/review and actual
guest/prover/host compilation, with no new fixture, local suite or proof/payment
campaign. Compilation is the exit observation, not runtime qualification.

NativeInput tag 6 wraps the existing UTXO/permanent/applied witness plus one real
Mint index certificate and two typed access sets. Tags 0–5 retain their existing
purposes. The paper, root algorithm, native monetary checkpoint format, RLD-only
currency, 21-million lifetime cap and zero allocation remain unchanged.

## Authority and exact reads

The input must carry an empty complete Mint placeholder. Installation verifies
the actual correspondence receipt using the currency's exact native image,
control/verifier profile and distinct Mint-index journal. Certificate currency,
home, event root, auxiliary slot root and common count bind both access sets.
Each set proves its initial count/root through an authenticated opening, or the
canonical zero-count empty root. This check happens even when no access follows.

The ordinary native relation verifies the real predecessor checkpoint receipt,
currency/home/sequence and entire State root. That state root contains the primary
Mint event root. Thus an invented but internally consistent index certificate
cannot stand in for the actual native predecessor. The auxiliary slot map grants
no work, issuance, native ordering, ownership, finality or fee authority by itself.

An event lookup authenticates the current root/key/count and exact canonical
MintRecord entry, including native owner and root/slot bounds. A slot lookup first
authenticates the requested upper key under the current slot root. If it is a
member, its exact entry is selected. Otherwise the existing absence verifier
authenticates adjacent ordered members or exact endpoints; only its left endpoint
is the exact predecessor. Choosing any earlier member would not prove emptiness
and is not permitted. Slot keys decode only from zero-prefixed 32-byte keys with
in-range root/slot fields. Its event ID must resolve under the primary event root
to a typed record with the same event/root/slot.

For active interval [lo,hi), query the predecessor at (root,hi-1). The interval is
empty exactly when no predecessor exists, its root differs, or its slot is below
lo. This is identical to the complete-index rule. Exact get_slot similarly uses
the same predecessor and filters for equality. Existing work/frontier, grants,
reward/cap, owner/fee, controller and conservation rules continue to execute.

## Append, observation isolation and refusal

Mint maps remain append-only. Duplicate event and global slot checks precede
mutation. Both event and slot tapes are cloned, and insertions derive each new
root from an authenticated absence at its exact prior root/count. Both checked
count increments must agree before either successor observation is installed.
An error cannot publish a half-updated monetary map. Neither map supports remove
or replacement. The original conservative compact insertion-height guard and
64-branch bound remain unchanged.

Tape clones share immutable supplied evidence and usage tracking only. Current
monetary roots/counts remain separate per observation. Every supplied root/key
step is authenticated when used; duplicate supplied keys and unused evidence
refuse. A verified repeat access may use the same exact evidence. Partial maps
cannot export complete records, serialize as complete State even when empty,
issue arbitrary membership/access, open historical storage or become a complete
host backing. Those operations do not invent unchecked records from a cache.

## Default construction and bounded fallback

Default native input construction looks up the actual predecessor Mint event root
in the replay-derived certificate catalogue. A found certificate must verify and
match the exact complete host event/slot/count observation. Missing correspondence
retains the previous full-Mint path; invalid receipt, wrong claim, damaged object
or I/O failure propagates and cannot select that fallback.

Host replay wraps the complete Mint maps with two access capture logs. Exact
event lookups capture typed members/absences; slot upper queries capture members
or adjacency proofs and also capture the primary predecessor event. Native
appends capture both absences, derive both compact roots, execute the complete
update and compare both results. Repeated root/key capture must be byte-for-byte
identical. Every resulting header remains compared with its fully verified local
history record. Underlying disk roots seal only after an already committed native
step is reproduced. Capture logs cannot become historical roots or full exports.

The certificate, both metadata/openings, all access steps and all other material
share the unchanged counting-CBOR 1-GiB input bound with framing allowance. Each
typed tape remains bounded by two million supplied steps. Only typed compact
height or capture-capacity insufficiency selects the previous bounded full-Mint
profile. Complete material that cannot fit still refuses. The catalogue and proof
lane retain their existing finite admission, default concurrency and source-bound
publication/recovery rules; no new network, key, genesis or proving campaign is
started by this stage.

## Remaining limits

Other native collections still use complete material and some full scans. Mint
correspondence construction can still stream complete historical events; fallback,
snapshot export and cold replay remain expensive. Working-path/object admission
is not a measured RAM or throughput bound. Actual full Argon2id proof cost,
maximum witness feasibility, latency/volume, power-loss custody, long-history paid
archival rotation, independent security, crypto transitions and physical routes
remain open. New native programs/source bindings refuse incompatible old stores
without rewriting money, descriptor, keys or latest heads. A compile pass does
not establish functional completion or authorize launch before that condition.
