# Process-local Native body witnesses

The paged Store executes all complete ordered records from pinned genesis on
every cold open. Live mutations stage its privately held actual Native replay
after verifying the full unchanged current stream. Its body identity cache contains at
most 4,096 entries, in insertion order. An eviction removes only a redundant
identity witness. It does not remove original records, active verified ledgers,
receipt or contact anchors, permanent imports, incidents, or signer locks.

A new local certificate still authenticates its complete certificate and shape,
requires the exact selected Native predecessor, and executes the complete new
block under that predecessor's Native-derived ledger. A full identity cache does
not change those checks. The active semantic working set remains bounded at 64
snapshots and retains all required provenance and receipt anchors.

An evicted historical identity can be resolved only from the exact original
record prefix already successfully Native-executed in the same invocation. The
process derives that prefix's count and ordered record commitment from its
independently bound scope. It advances them only after successful Native record
execution. A lookup verifies the entire held current stream, examines only that
executed prefix, recomputes its exact count and commitment, and checks all matching
complete bodies for equality. Future records cannot claim prior execution. Any
source, order, body, scope or prefix mismatch refuses the lookup.

The newly supplied complete certificate still authenticates independently after
a lookup, and its complete body must match. A commitment read from disk, a peer
advertisement or a serialized witness cannot initialize this process-only state
or a Native ledger. Historical signing cursors carry the same held stream and
advance only through actual ordered execution; look-ahead records do not enter
the executed prefix before execution. Staged new append records are verified
natively and stay in the bounded process cache until the complete append is
published. An ordinary append remains at most 16 complete records.

The retained stream's original format, complete 16-record pages, signed rules,
8-MiB object/evidence/ledger limits and 4,096-file / 256-MiB archive ceiling remain
unchanged. A cache miss may reread the complete archive; bounded memory does not
imply constant-cost lookup or long-history throughput. Page packing is a separate
representation candidate. Neither mechanism establishes the required long-history
value execution, recovery, retention funding, independent rollback protection,
cryptographic adoption or physical route qualification.


## Ordinary current-process commit state

The ordinary paged Store holds a private `CurrentReplay`, created only after
authenticated empty genesis or full cold Native execution. It has no serialization
or deserialization interface. Its exact header, retained record head and executed
prefix remain separate from the Store's public chain, journal and evidence views.
A live append verifies the complete current stream, scope, count and logical head,
then requires every public chain field, ledger, trust binding, evidence snapshot
and epoch set, and journal to match that actually executed state. Altering a public
projection cannot initialize a ledger or supply Native authority.

The original bounded batch is staged on a clone of that private replay. Each new
complete record still authenticates and executes natively. During staging, the
executed-prefix resolver consults only the committed prefix; new authenticated
bodies stay in the process witness. The staged prefix advances through the
successfully executed batch before publication. Complete incident proofs and the
original shared root/stream capacity must verify before the original durable
transaction. Only successful publication installs the new private process state
and public views. A persistence refusal poisons the handle and retains its prior
committed process state and all durable residue. Cold opens never load this cache.

This removes historical Native re-execution from the append transaction. Full
source I/O, historical conflict scans and signer-history verification retain their
separate costs and authority checks. It does not adopt
lossless prefix storage for ordinary nodes, change any signature custody format
or supply new independent rollback, resource, cryptographic or route qualification.


## Ordinary contact preflight

Ordinary paged contact preflight stages the same private current Native replay.
Before release it requires a healthy Store, zero pending incident guard, unchanged
complete stream/header and exact public projections. It rereads and authenticates
every complete retained incident, requires the incident set and derived safety
view to match actual execution, and accounts for all root-side and stream-side
objects together under the original archive ceiling. A new pending guard, orphan
incident or altered safety projection refuses even an exact contact retry.

The incoming complete contact still verifies its Native signatures, commands and
stand-alone dependency closure from genesis. Current local evidence cannot fill
a wire omission. Contact conflict scanning remains over complete original records.
After full incoming authentication, an exact retained retry checks current local
guards again and neither appends nor grants an import. A new contact uses the
original guarded atomic append transaction. This avoids replaying the destination's
old Native history during contact preflight; it does not skip incoming proof
execution, incident checks or separate local import and maturity. Historical
signing cursors retain their full independent Native replay requirements.


## Ordinary receipt and candidate reads

Paged receipt history reads use the same privately held committed Native replay
and complete current-source guards as contact preflight. The returned receipt
index derives only from records this invocation actually executed. All current
header, stream bytes, executed boundaries, public projections, incident proofs,
pending incident guard, derived safety and shared archive capacity must match.
A modified page or projection cannot be replaced by a cached receipt view.

Normal paged candidate generation invokes this guarded read for channel watching.
It preserves the existing challenge slots, owner and fee authorization, absolute
challenge windows and complete new Native command execution. New receipt records
still authenticate their complete funded-state and invoice signatures on the
original atomic append path. A read or unsigned candidate changes no ledger or
stored bytes, and cannot promise inclusion. Full cold reads and historical signing
cursors retain their independent execution from genesis; no serialized receipt
index can initialize current authority.
