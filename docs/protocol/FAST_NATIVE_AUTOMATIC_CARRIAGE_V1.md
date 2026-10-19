# Automatic native and existing-signature carriage

This NO_VALUE_ONLY session mode composes controlled native/caller custody with
pinned admitted peers. It carries complete existing blocks and signed operations;
it cannot create an owner approval or signature, initialize a ledger from a
remote balance, migrate value, change native work/issuance or qualify G1-G11.

## Explicit local entry

Use serve-control ROOT GENESIS PIN CALLER_HEAD_FILE --peer-root PEER_ROOT
--peer-head-file PEER_HEAD_FILE --auto-sync. Both local head files must be in
trusted-file mode. Ordinary startup remains explicit: --auto-import-blocks keeps
its block-only scope, and no automatic mode is enabled by omission. A peer data
receipt does not prove that the recipient enabled native ingress. Unsupported
kinds/versions refuse; there is no plaintext or unverified fallback.

The mode runs native/data ingress and outbound during ordinary idle operation,
before/after the separately activated local fee monitor and ordinary background
miner. Fee monitoring still requires its own signed input-owner policy and private
memory-only unlock. Existing unsigned owner requests, retainer acknowledgments,
key paths/passwords and principal signing never enter automatic peer work.

## Complete block batch format

Packet kind9 contains:

| Field | Encoding |
|---|---|
| Magic | ASCII RLDFBLK1,8 bytes |
| Version and suite | unsigned16 big-endian1 each |
| Currency | exact pinned genesis hash,32 bytes |
| First source journal ordinal | unsigned64 big-endian, nonzero |
| Complete block count | unsigned16 big-endian,1..32 |
| Each block | unsigned32 byte length, then exact complete native block |

Header size is54 bytes. Each block is270..262144 bytes and has the existing native
version/currency. Duplicate block identities, ordinal overflow, wrong scope,
unsupported version/suite, truncation and trailing bytes refuse. The entire batch
is at most262144 bytes, preserving the existing262345-byte packet envelope. A
single maximum block that cannot fit with framing uses the existing kind1 packet;
it never enlarges either limit. Packet/link signatures and fresh connection nonce
checks remain unchanged. A structural batch is data only, not proof of native
work, correct roots, authorization, maturity or current spendability.

The [public deterministic vector](fast-block-batch-v1-vectors.json) includes
independently assembled framing and packet signatures plus two native empty PoW
blocks. Its labeled public keys/genesis have no monetary custody authority. The
Rust example fast-carriage-vector assembles those bytes without using the batch
or packet encoder; codec tests also execute each full block from pinned genesis.

Source ordinals describe that sender's local append-only native custody order,
including valid unselected branches. They do not name recipient heights or grant
causal/finality authority. The recipient ignores them as authorization and executes
every complete block against its own independently authenticated native parents.

## Source coverage and original custody

Outbound is bound to the exact currency, unique controlled caller header and local
peer identity. Native source bytes come only from the actual fully verified native
journal and its process-local reconstructed order; full-prefix checks precede
carriage. Previously queued kind1/kind9 data covers a local source ordinal only
when its complete bytes match that exact source record. A high ordinal, wrong
body, unbound payload or later fragment cannot hide an earlier gap. At most2048
retained intervals are used per neighbor. Existing queue clocks and normal ACK
reservations/retries remain unchanged; queued data is not recipient acceptance.

Each newly observed complete retained peer envelope is authenticated under an
unchanged actual custody prefix. Received native byte digests are scoped only to
that authenticated sender. They can avoid a NEW return carriage only when the
matching complete block already exists in independently validated local native
custody. They cannot initialize a ledger, suppress carriage to another neighbor,
claim native acceptance, cancel an existing outgoing ACK obligation or replace
fresh authentication of another message. Signed-operation byte identities likewise
avoid returning existing data to the sender that supplied it.

At most2048 packets times32 full-block byte witnesses exist across the local
process. All witnesses/cursors are process-local and cold startup reconstructs
from complete retained envelopes and full native replay. Neither serialized
coverage nor a peer-supplied hash supplies native or monetary state. Actual peer
and native file identities, complete bytes, bounds and trusted heads are rechecked.
Copied/all-state rollback and independently retained latest state remain separate
qualification obligations.

One admitted neighbor and one data class are selected per outbound tick. Existing
full signed pool entries use the unchanged versioned kind6 frame. Native batches
close at32 records or the byte boundary, flush immediately for actual operations,
and otherwise become eligible to flush after one observed second for the first
pending range. Scheduling and contacts can add delay. This local timer grants no
value and changes no transaction/window expiry.
An offline neighbor retains ordinary pending data while other neighbors receive
their own fair attempts. Discovery never learns endpoints or pins from a message.

## Independent bounded ingress

Ingress is bound to the exact controlled caller and peer scope. Each tick selects
one retained incoming data packet. It can admit at most four new complete native
blocks, with at most32 already-known complete block checks in a batch. Complete
native prevalidation precedes each exact caller intent; actual admission repeats
all monetary, work, parent, signature and capacity checks. A missing parent,
invalid body, clock wait or full store retains the original packet and diagnostic.
Retries are fair and defer unchanged failed contexts until another observation
second or native-head change. No local timeout deletes evidence or refunds value.
Deferring one packet keeps the local worker awake while other retained packets
are still eligible. Once all retained data is completed or deferred at that
unchanged context, the worker may idle. An out-of-order future block therefore
cannot impose the idle wait on an available parent packet. Every eventual
admission still performs the complete native prevalidation and normal execution.

Kind6 ingress authenticates a complete existing actor operation into the normal
bounded512-entry/2-MiB signature pool. Queue custody is not execution. Actual
ordinary own-template mining/admission still verifies inputs, funding, conservation,
expiry, dispute windows and maturity. No first signature or synthetic approval is
created. Exact duplicates retain their original caller/pool age.

At most2048 process-local completion observations suppress repeated already
processed immutable data only after actual native or exact retained-pool checks.
Complete peer/native prefix checks still precede reuse, new received envelopes
still authenticate, and another caller cannot reuse those observations. Cold
startup begins with no completion witness and reauthenticates. Status separates
native-data coverage, pool data, deferred packets, queue custody and native state;
unknown observation is never reported as fabricated height zero or spendability.

## Required composition and qualification

The original permanent peer2048-packet/32-MiB and414-byte response reservation,
caller/native/pool limits, native2016-block AND172800-second strict dispute window
and h+100 miner maturity remain unchanged. No new mode raises them or prunes data.
Native evidence, policy signature liabilities and original owner requests survive
retries, restart, duplicate data and losing histories under their existing rules.

Required checks include exact public wire bytes, all count/size/scope refusals,
source holes and cold queue age, invalid native bytes receiving only a data ACK,
sender-specific duplicate avoidance, origin-disconnected ordinary mining/relay,
and actual controlled idle CLI propagation of funded policy claims, settlement and
mature miner spend. A local bootstrap/carriage sample does not qualify a complete
finite service deadline, arbitrary faults, independent custody/operators, power
loss, full long-history/mass exit, physical routes or actual local latency/daily
one-hundred-million-payment composition. Those remain mandatory separate gates.
