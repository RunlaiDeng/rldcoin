# Survivor-first node, wallet and delayed transport

This document defines required external behavior. A conforming implementation may
choose its database and operating system but cannot change consensus, durability
promises, signing intent or the distinction between receipt and money.

## O01. Ordinary lifecycle and retained authority

A full-node installation pins C03 genesis and starts validation, a local wallet
interface, neighbor synchronization, durable forwarding and optional mining through
its ordinary lifecycle. Mining is off until the operator supplies a valid reward
public key and enables it; lack of peers is never a reason to disable it. All
initialized full nodes must offer this capability without a special founder mode,
remote coordinator, private committee keys or a different consensus flag. Receiving
to an address requires no online recipient; observing or spending the payment does.

Startup acquires an exclusive writer lease for the database, verifies genesis and
durable records, resolves O03 intents and fully validates the selected history.
Authenticated indexes may accelerate lookup but cannot replace replay authorization.
Enable signing/mining only after state, unresolved operations and clock status are
known. A relay-only or pruned installation must be visibly labeled as such and
cannot claim the survivor-full-node property. Full survivor nodes retain every
block of the selected history, all uncompleted wallet intents and durable carriage
obligations. They have no mandatory server to recover from when alone.

## O02. Atomic state installation

A state change has a unique local monotonically increasing `revision:u128` and
records `prior_revision, prior_tip, new_tip, new_state_root, operation_id`, plus
exact newly required canonical blocks and the selected branch description. A
transactional engine or write-ahead journal must provide the following order:

1. Validate all candidate bytes and construct the complete new branch state without
   altering authoritative selected state. Reserve enough space for commit/recovery.
2. Durably write an INTENT binding prior and successor state and required exact
   object identities. Durably retain all objects needed to replay that successor.
3. Atomically publish a COMMITTED record selecting the successor. It must be durable
   together with referenced objects before acknowledging the state transition.
4. Publish notifications and update regenerable caches. Notification/cache failure
   cannot undo a committed monetary state or justify acknowledging an uncommitted one.

“Durable” means an implementation-specific documented crash/power-loss persistence
contract, including file and directory synchronization where required, not simply a
successful write to a process buffer. Group commits may batch work but must never
acknowledge a member before its entire dependency set is durable. Atomic recovery
must expose either the complete prior state or the complete committed successor,
never a mixture of debits, credits, issuance or selected tips.

The same transaction applies to extension, deep reorganization, imports of block
history and explicit database repair. A transport receipt is not this transaction.
Failure at validation, capacity reservation or intent creation leaves the prior
state unchanged. Preserve damaged bytes and diagnostic evidence outside the active
authority set; do not silently rewrite an invalid history to pass replay.

## O03. Restart, response loss and backup

On restart, a complete committed transition is replayed and retained even if the
caller never received its response. A complete uncommitted INTENT may finish only
after exact dependency replay and checking that its prior state is still selected;
otherwise it stays pending or is explicitly abandoned without new signing. A torn
INTENT with no complete binding cannot authorize a successor. Preserve its residue,
replay the last complete committed prefix and report the interrupted operation.
Orphan objects and an untrusted cache never choose a successor by themselves.

The caller supplies an idempotency operation_id for each mutating request. Exact
retries return its retained result. Reusing an ID with different intent refuses.
After a lost response, query by ID; do not create a second payment. Recovery must
distinguish a known exact pending transition from an arbitrary stale caller head.
An older backup of every local file cannot prove its own freshness. Independent
latest-state records improve detection but are not required consensus signers.

A complete backup contains genesis, selected history, retained pending/committed
operations, wallet intent and reservation journal, and explicit custody metadata.
Keys are encrypted separately; contact keys are not wallet keys. Restore writes a
new directory with a RESTORING marker, verifies all evidence and the supplied
independently retained latest revision/intent head when available, then atomically
clears the marker. No overwrites or reuse of interrupted targets. With no independent
freshness evidence, expose FRESHNESS_UNKNOWN: replayed balances may be displayed and
mining may continue with an existing public reward key, but signing requires an
explicit local risk acknowledgment and reconciliation of known pending intents.
It must never be described as independently protected against all-state rollback.

One surviving full node with its intact current state does not need an external
witness to keep mining or spending. If that state is rolled back or destroyed,
availability cannot also guarantee knowledge of lost signatures or remote spends.
Copying a spending key onto multiple devices can produce conflicting transfers;
version 1 resolves included conflicts by C10, not a claim of exclusive physical
custody. Cross-device and hardware custody require independent qualification.

## O04. Reorganization and notifications

Every selected-tip change increments revision, including equal-work tie changes.
Validation of an alternative branch runs against its own common-ancestor state.
Never execute its transactions against the losing tip's balances. Before publication
compute the complete changed set of transaction/reward inclusion, conflict, maturity
and spendability observations. Commit that set consistently with the new state.

Clients subscribe from a revision cursor and receive ordered changes. A gap or
overflow gives RESYNC_REQUIRED with the current revision; a snapshot response binds
all balances and statuses to one tip/revision. Show a rollback explicitly, including
affected descendants and disappearing reward value. A receipt remains a historical
transport fact even when its payment is rolled back. Previously spent losing-branch
value does not become a debt hidden from the display; both old and new observations
remain auditable. No local confirmation preference prevents a valid deep reorg.

## O05. Transaction pool and reoffering

Pool policy is local, never block validity. The default pool is at most 65536
transactions and 64 MiB canonical transaction bytes, including waiting transactions.
Validate canonical bytes, chain, signature and shape before admission. Ready inputs
must be valid at selected_tip.height+1. Missing-parent transactions may be retained
as WAITING_FOR_INPUT; known conflicts remain CONFLICTED, never available balance.
Keep at most one ready pool spend per input: choose higher fee/byte using exact
cross multiplication, then lower transaction_id. Other conflicting signed intents
may be kept in the wallet journal without being relayed as ready.

Block templates choose ready transactions by fee/byte then ID, subject to disjoint
inputs/count/byte bounds, and sort the selected set by ID for C05. Empty blocks are
allowed. A miner MAY choose another valid set; inclusion is not guaranteed by a fee.

After a reorg reconsider detached non-reward transactions in ascending old height
then ID, followed by the existing pool. Recheck everything against the new next
height. Valid ready transactions may be reoffered with their **original signature**;
no change of recipient, amount, fee, expiry or input is implicit. Missing descendants
wait for their parents; they cannot spend a losing reward or transaction output on
another history. Expired transactions are not re-signed. Pool eviction changes
neither the wallet intent journal nor a durable transport custody promise.

## O06. Wallet intent, balances and signing

The local wallet API must bind `chain_id, operation_id:bytes[32], selected_tip,
revision, exact inputs, ordered outputs, fee, expiry` into the user's review.
Operation IDs are nonzero and never reused. A changed selected tip or changed input
ownership/maturity requires revalidation before signing; a changed transfer requires
new review. Persist the reviewed intent and reserve those inputs before releasing
the signature. Persist the exact signed X before returning it or transmitting it.
Restart can recover that exact X; it cannot first-sign an unreviewed intent.

Reservations prevent this local wallet's accidental conflicting signatures; they
are not consensus locks. Signed intents do not lose their reservation solely due to
timeout, a dropped connection, pool eviction or a receipt. The wallet reconciles
them with selected-chain inclusion/conflict. A reservation on a still-unspent input
may be waived only by an explicit recorded user decision, warning that another
branch may have included the signature. Selected-chain spending removes the input
from available funds; if a reorg restores it, restore its unresolved reservation
unless an explicit waiver exists. Height expiry is not a permanent global revocation
because reorganization can decrease the selected height. Never silently sign a
replacement.

Display selected-chain unspent total, immature reward total, mature unspent total,
reserved mature amount and available-to-propose amount separately. Pending receipts
and nonselected-branch value are excluded from those totals. A transfer output
included at height h may be proposed for a later block immediately; its payment is
still reversible. Reward output h is eligible for spending only in a candidate at
height >=h+100. All balances include their chain/tip/revision and observation age.

Passwords and signing keys remain in native secure input/storage, never HTTP URLs,
logs, argv or peer messages. User interfaces call a loopback authenticated capability
API with Host/Origin checks; no public remote signing endpoint is a baseline feature.
Key files use O13. Whole-database backups also retain O03's history and intent state;
a key file alone is never labeled a complete wallet backup.

## O07. Contact objects and exact message format

Consensus objects are unchanged across Earth and interstellar contacts. Discovery
and forwarding confer no issuance, work, validation or settlement authority. A
full node can send a transfer to a recipient's contact identity, or broadcast it to
miners; destination identity is routing metadata and need not equal output owner.

Contact suite 1 uses C02 keys/signatures with different domain tags. A peer is
identified by `H("PEER", public_key)`. A pinned neighbor configuration contains its
exact public key and independently admitted literal endpoint/adapter. Advertised
endpoints are candidates only: no implicit access to loopback, private management
services or arbitrary URLs. There is no mandatory central directory; discovery may
start with direct physical contact, local advertisements, operator introduction or
offline files. A node with no contacts still mines and accepts local transfers.

The origin packet unsigned bytes P are:

```
magic:bytes[8] = ASCII "RLDSPKT1"
version:u16 = 1, suite:u16 = 1, chain_id:bytes[32]
origin:bytes[32]                 // contact public key
destination:bytes[32]            // peer ID, or all zero for broadcast
sequence:u128                   // monotonically allocated by this origin/chain
kind:u8
payload_length:u32
payload:bytes[payload_length]
```

`packet_id=H("PACKET",P)`; complete packet `P || signature[64]`, signing
`ASCII("RLD-SURVIVOR-1/PACKET-SIGN") || 0x00 || P`. Origin allocation is durably
recorded before release. Out-of-order lower sequences are not rejected merely
because a higher sequence arrived first. Reused (origin,sequence) with different bytes is recorded
as origin equivocation and refused for new custody; it never freezes valid ledger
blocks from other packets. Keys may rotate by creating a new contact identity with
independently admitted routes. The ledger chain does not change.

Each complete packet is <=1048347 bytes, so payload <=1048154 bytes (193-byte
overhead). The following are the complete payload registry; all counts/lengths are
big-endian and all trailing bytes refuse:

| kind | Payload |
|---|---|
| 1 GENESIS | Exact C03 manifest; advertised identity only, never automatic adoption |
| 2 TRANSACTION | Exact complete C04 X |
| 3 BLOCK | Exact complete C05 block |
| 4 HEAD | tip_id[32], height:u128, cumulative_work:u384; untrusted synchronization hint |
| 5 GET_OBJECTS | count:u16 in 1..128, entries `(object_kind:u8, id[32])`, strictly sorted; kinds 1,2,3 only |
| 6 LOCATOR | count:u16 in 1..128 followed by unique block IDs, newest first, final ID=chain_id |
| 7 INVENTORY | count:u16 in 0..128, entries as GET_OBJECTS in strictly increasing order |
| 8 PEERS | count:u16 in 0..64, sorted unique peer public keys[32]; introductions only, no endpoint/pin changes |
| 9 RETURN_RECEIPT | Exact type-3 frame from O08 with result=1, for the same chain; packet destination is the origin peer ID of the receipted packet |

Object IDs are chain_id, transaction_id and block_id respectively; send complete
objects using their corresponding packet kind. HEAD, LOCATOR and inventories do
not prove work or possession. A LOCATOR contains tip and up to ten immediate
ancestors, then ancestors with backward offsets 2,4,8,... from the last included
height, skipping duplicates and ending at genesis; stop when genesis is reached.
The count cap may truncate intermediate entries but must retain tip and genesis.
The receiver finds the first locator entry it knows on its selected history and
advertises up to 128 successive block IDs there (or genesis if none match).
Further rounds advance the locator; out-of-order blocks wait for parents. Do not
accept a header or claimed state in place of full parent bodies. A receiving node
with no shared prefix needs the complete validated history from genesis; a payment
proof alone is insufficient. A sender behind a different branch may need to serve
that branch's exact requested objects too.

RETURN_RECEIPT transports a destination's already signed observation back through
intermediaries. Its frame receiver may be the final delivering neighbor rather than
the original packet origin. To discharge a retained addressed-packet obligation,
independently verify the nested receipt signature, chain and packet_id, and require
`H("PEER",receipt.sender_key)` to equal that packet's exact destination. This is
an authenticated historical destination observation, not a new interactive-session
acknowledgment; it must not satisfy a different session's challenge. A relay may
construct this wrapper from public signed bytes without gaining receipt authority.
For kind9, send no receipt-of-receipt and grant no new durable custody obligation;
control copies may be evicted from a bounded cache. Losing this control message
causes data retransmission/retention, never loss of the original obligation or a
refund. On a duplicate original packet, the destination can issue another exact
packet-bound receipt for the current delivery and resume the return path.

## O08. Per-hop exchange, custody and acknowledgments

Each physical/stream exchange frame is
`magic[8]="RLDSFRM1" || length:u32 || body[length]`, length<=1048576.
The first body byte is a frame type:

| Type | Remaining body and signed message |
|---|---|
| 1 CHALLENGE | chain_id[32], sender_key[32], receiver_peer_id[32], nonce[32], signature[64]; sign `tag("CHALLENGE") || preceding fields` |
| 2 DELIVER | chain_id[32], sender_key[32], receiver_peer_id[32], challenge[32], delivery_nonce[32], packet_length:u32, packet bytes, signature[64]; sign `tag("DELIVER") || preceding fields` |
| 3 RECEIPT | chain_id[32], sender_key[32], receiver_peer_id[32], challenge[32], delivery_nonce[32], packet_id[32], result:u8, signature[64]; sign `tag("RECEIPT") || preceding fields` |

Here `tag(s)=ASCII("RLD-SURVIVOR-1/"+s)||0x00`; signatures do not include the frame
type, magic, length or their own bytes. Receiver_peer_id always names the intended
frame recipient. For a receipt, sender is the custodian and receiver is the earlier
deliverer. Result 0 means durable hop custody; 1 means durable addressed-destination
custody; 2 means capacity refusal; 3 means invalid packet; 4 means unsupported.
Only 0/1 are acknowledgments. DELIVER overhead is 229 bytes including type, so a
maximum-sized packet fits the 1048576-byte frame body. No adapter
may silently raise the consensus block limit. Envelope fragmentation, if used, must
reassemble the exact bounded frame before authentication/custody.

For an interactive contact the receiver generates a fresh nonzero random challenge and
signs type 1 to the sender; it is valid only on that connection. Sender signs type
2 binding that challenge, its own fresh nonzero random delivery nonce, exact packet and
both roles. Receiver verifies role/pins, all signatures, lengths and origin packet
before durable custody and type 3. Payload syntax/chain/size validation is mandatory;
missing ledger ancestors can remain pending after byte custody. Receipt binds both nonces and exact packet ID;
verify its signature/roles before accepting it. No replay from another connection
grants new custody. A verified reply on a closing socket must still be durably
saved locally before suppressing retransmission. Socket timeout is not a refund.

For scheduled one-way/offline delivery use the same DELIVER encoding with the
challenge all zero and a fresh delivery_nonce; the receiver accepts this only on
an independently configured offline/one-way adapter. Receipts echo both fields
and can return years later through a separately routed frame file. A zero challenge
is never accepted on the interactive adapter. Replay is expected and idempotent,
not proof of recent contact. Offline files contain exactly one full frame; no file
paths, archive extraction or executable content occur in the format. A deployment
may carry frames as application payloads in [BPv7](https://www.rfc-editor.org/rfc/rfc9171.html);
BPv7 routing/fragmentation/security policy is an adapter qualification, not ledger
finality. Bundle expiration can affect a copy, never delete the node's financial
evidence or refund a payment.

Ground TCP uses pinned TLS 1.3 with independently configured peer/certificate pins;
TLS private keys are distinct from wallet keys. No plaintext downgrade. Application
challenge signatures are still required. Long-delay links must not assume a
short-lived ground certificate stays valid during transit; offline end-to-end
packet verification is separate. No actual physical adapter is qualified by this
format definition. Authentic old packets can still have stale payment history.

## O09. Durable forwarding, discovery and resource fairness

Ordinary startup resumes the outbox without requiring an Earth directory. Store
each exact authenticated packet before acknowledging custody (kind9 has no
acknowledgment or custody promise). Deduplicate by
packet_id and exact bytes, and retain origin/sequence bindings with each retained
packet. A duplicate may be reacknowledged only after verifying retained durable
bytes and custody status. Hash equality alone is not proof of ledger validity.
One malformed member cannot earn acknowledgment for an unchecked batch.

Select admitted available neighbors by persistent round-robin cursor. For an
addressed packet prefer a directly admitted destination, otherwise offer it to
other admitted neighbors except the immediate sender; broadcast packets use that
same ordinary relay process. Contacts may be directional, intermittent and late.
Discovery advertisements update candidate identities, never claim that a peer is
currently reachable or authorize new value. Each contact offers HEAD/LOCATOR,
requests missing dependencies and forwards queued traffic. Between scheduling
classes use durable round-robin (sync requests, blocks, transactions, receipts,
discovery), at most 16 frames from one class before the next ready class. Rotate
objects within classes so new arrivals do not starve old pending evidence. Policy
may tune throughput but must retain a documented nonstarvation bound per admitted
finite workload. No eventual-delivery guarantee applies under sustained overload.

Each link authenticates the immutable origin packet and its own exact sender,
receiver, nonces and receipt. This baseline does **not** assert a fully signed
end-to-end path history or infer distance/trust from a hop count. A malicious relay
can withhold, replay or reroute an unchanged packet; it cannot change its destination
or payment. Suppress repeated forwarding to an acknowledged neighbor until a
restart/probe or explicit retry, preserve the packet, and never send immediately
back to its incoming neighbor. Deduplication, quotas and fair scheduling limit
loops; they do not prove a physical route exists. No fixed cosmic directory or
permanent global hop limit is a consensus requirement.

Default carriage budget is 256 MiB and 4096 complete packets, including pending
received receipts and metadata charged at their actual byte size. Limits are local
operating policy and adjustable only with explicit resource provisioning; they do
not change block validity. Reserve sufficient space before accepting custody. Full
queues refuse new custody with result 2 and preserve acknowledged obligations.
No timeout deletes acknowledged payloads. A sender or intermediate custodian keeps
the last retained copy until a valid signed result-1 receipt by the exact addressed
destination is durably retained, or the local owner explicitly withdraws that
transport obligation. Hop result 0 alone is insufficient to delete the last copy.
Broadcast has no final recipient and needs explicit retention/operator policy;
dropping a broadcast copy never deletes selected ledger history or wallet intent.
The user must be told which transport guarantee a withdrawal abandons.

Destination custody is only receipt of bytes. It neither certifies a transaction
nor guarantees preservation against a malicious custodian. A full node that has
promised survivor capability keeps its selected history regardless of transport
garbage collection. Unacknowledged inbound junk may be discarded under quotas.
Useful alternate validated branches can be evicted as a local capacity policy,
but this must not install a consensus depth checkpoint: if later needed, reacquire
and revalidate them or enter REORG_WAIT. Queue capacity and cumulative ledger
growth are separate budgets; running out of ledger space pauses mutation/mining
with RESOURCE_WAIT, preserves known state and permits operator expansion.

## O10. Cross-stellar payment semantics

There is no cross-region export/import currency operation. A sender signs one C04
transfer. It can be included locally, transported as X plus required blocks, or
transported before inclusion to a remote miner. The recipient verifies exact chain
identity, complete relevant history, ownership and selected-chain inclusion itself.
If remote and local nodes share unspent inputs, the original transaction can be
mined on either branch. If it spends a reward or output unique to a losing branch,
it cannot be made spendable on the winner by a receipt, proof of location or bridge.
An owner may later create a new transfer from valid winning inputs after explicit
review; the protocol never guarantees that replacement exists or preserves value.

With one node remaining it can include a transfer to any valid address and update
its own ledger. A remote human with no reachable receiving device cannot observe
delivery until a physical contact exists. A recipient full node that remains alive
is, by definition, another node. These are compatible capabilities, not a promise
of communication with destroyed or permanently unreachable receivers.

At interstellar delay, ongoing remote work can repeatedly replace low-work local
history. Payments may take years to arrive and can be reversed even after many
local confirmations. The profile offers asynchronous conditional settlement; it
does not guarantee eventual inclusion, preservation of every isolated economy or
a universally safe confirmation count. Merchants choose exposure off chain. No
operator may label local maturity, a delivery receipt or a fixed number of blocks
as universe-wide irreversible settlement.

## O11. Required consumer status and API contract

External JSON is a display/API encoding, never consensus bytes. Encode all integers
as canonical unsigned decimal strings, byte arrays as lowercase fixed-length hex,
booleans as booleans and unavailable observations as null, never invented zeros.
Every result includes `profile, chain_id, selected_tip, revision, observed_at`.
Local untrusted clock means observed_at=null with clock_state=CLOCK_WAIT.
State snapshots must be atomic with respect to selected revision.

The required logical operations are `node_status`, `get_object(kind,id)`,
`submit_transaction(operation_id,transaction_hex)`, `review_transfer`,
`sign_review(operation_id,review_digest)`, `operation_status(operation_id)`,
`wallet_state(owner)`, `changes_since(revision)` and `set_mining(enabled,miner)`.
Implementations may expose a CLI, local API or both but must preserve these inputs
and semantics. `review_digest=H("REVIEW", chain_id || operation_id || tip ||
revision:u128 || U)`. Signing refuses a digest other than the exact persisted review.
Submission accepts only signed bytes and never authorizes first signing. Operation
queries are read-only and recovery never changes the reviewed transfer.

Transfer state is a tuple, not one misleading progress bar:

| Dimension | Values and meaning |
|---|---|
| local_intent | REVIEWED, SIGNED, WITHDRAWN; withdrawal cannot revoke a released signature |
| transport | NOT_QUEUED, QUEUED, HOP_CUSTODY, DESTINATION_CUSTODY, REFUSED; list exact peer observations separately |
| ledger | UNSEEN, WAITING_FOR_HISTORY, READY, INCLUDED, DETACHED, CONFLICTED, EXPIRED, INVALID, UNSUPPORTED |
| inclusion | block_id/height or null; confirmations = tip.height-height+1 only when included on selected chain |
| outputs | individual outpoint, selected unspent/spent/absent, maturity_height, eligible_next_height, local reservation |
| confidence | always CONDITIONAL, with REORG_WAIT/CLOCK_WAIT/RESOURCE_WAIT/FRESHNESS_UNKNOWN diagnostics when applicable |

INCLUDED means selected history contains the exact transaction; it may have spent
outputs and is not equivalent to a positive balance. DETACHED means previously
included and now absent; a conflict/expiry reason may be additionally present. A
reorg event must be emitted even when immediately reoffering makes ledger state
READY. Permanent error categories are INVALID_ENCODING, WRONG_CHAIN,
UNSUPPORTED_VERSION, INVALID_CRYPTO, INVALID_CONSENSUS, OPERATION_ID_CONFLICT.
Contextual/wait categories are MISSING_HISTORY, CONFLICT, IMMATURE, EXPIRED,
CLOCK_WAIT, RESOURCE_WAIT, REORG_WAIT, FRESHNESS_UNKNOWN, RESYNC_REQUIRED.
No error or telemetry failure fabricates a block, balance or acknowledgment.

## O12. Versions, maintenance and adoption

Version 1 has no hidden BFT/legacy compatibility, automatic network migration,
script opcode extensions or remote emergency override. Unknown versions/suites
refuse without reinterpretation. A future rule change requires a separately complete
versioned specification, independent review, reproducible implementations and an
explicit operator-adopted activation manifest identifying old chain, exact anchor,
new rules and replay/ownership/monetary continuity rules. Version 1 alone cannot
validate such an activation and must stop at the unsupported boundary. Agreement
on the activation and handling competing anchors is an adoption decision, not an
undocumented admin privilege in this baseline. Incompatible versions may split.

Crypto migration must occur while the old protection is still trustworthy; a
signature from an already broken key cannot prove rightful migration. Original
authenticated bytes, obligations and fork evidence must remain available, with
separately reviewed renewal proofs. There is no eternal safety guarantee or
pretense that Ed25519 plus a version number completes post-quantum transition.
Long journeys require finite-horizon cryptographic, archive, physical-contact and
maintenance qualification. If no safe upgrade is adopted before a primitive fails,
this baseline cannot guarantee authentic ownership. Preserve this limit in the paper.

## O13. Native encrypted key file and owner succession

The portable key-file format is `RLD-SURVIVOR-KEY-1`. Its authenticated header is:
`magic[8]="RLDSKEY1", version:u16=1, kdf:u16=1, aead:u16=1, N:u32=32768,
r:u32=8, p:u32=1, salt[32], nonce[12], ciphertext_length:u32=113`.
All integers use C01 encoding. Require these exact algorithms/parameters before
expensive computation; unsupported values refuse without fallback. Derive a 32-byte
key using [scrypt](https://www.rfc-editor.org/rfc/rfc7914.html) with the header's salt
and parameters. Password input is exact UTF-8 bytes, length 1..1024, without Unicode
normalization or implicit trimming. Warn about weak passwords; KDF work does not
make a weak password safe. Generate salt and nonce independently from the operating
system cryptographic random source on every encryption; entropy failure refuses.

Plaintext is `purpose:u8=1 (wallet), chain_id[32], owner_public_key[32],
Ed25519 RFC8032 secret input[32]`, exactly 97 bytes. Encrypt with AEAD_AES_256_GCM
from [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116.html), 12-byte nonce and full
16-byte tag appended to ciphertext. Associated data is the complete exact header.
File is header || ciphertext-and-tag, no trailing data. Verify authentication
before interpreting plaintext; derive owner from the secret and compare exact
owner/chain/purpose. Never emit decrypted material in diagnostics. Atomic replacement
must preserve the old file on failure. This is a finite-horizon software format,
not evidence of hardware custody or immunity to malware/weak-password attacks.

Baseline ownership is direct-key only. Loss of the key has no protocol reset;
theft can authorize conflicting transfers. Inheritance uses a valid ordinary
transfer while an owner can still authorize it, or deliberate out-of-band custody
of that key with its associated risks. There is no undisclosed guardian, recovery
quorum, channel watcher, frozen-account rescuer or minting compensation authority.
Such features would require a separately specified version and adoption. Local
software may assist backup but cannot bypass an on-chain owner signature.
