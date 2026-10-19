# Serialized native payment session V1

This NO_VALUE_ONLY local application composes the
[native selector](FAST_NATIVE_NODE_V1.md), [owner journal](FAST_OWNER_AUTHORIZATION_V1.md)
and [delegated receipt custody](FAST_PAYMENT_RETENTION_V1.md). It changes no
native genesis, work, transaction, invoice, partial, delegation or acknowledgment
bytes. It is not monetary adoption, a public signing endpoint, independent custody,
a continuously monitored service or a composed G9-G11 campaign.

The separate [trusted caller-control profile](FAST_SESSION_HEAD_CONTROL_V1.md)
uses fresh local caller version2, an explicitly selected private head file and
one exact pre-retained key-free request. Legacy literal-head interfaces refuse
that format. Controlled recovery authenticates the complete histories and returns
only an existing proof or audited absence, never first-executing or first-signing.
Its optional block-only ingress can run while the local client is idle; current
native selection still invalidates stale owner reviews. This local integrity/
latest-state assumption is not independent freshness or continuous fee service.

## Native view, exact review and keys

### Ordinary wallet input discovery

The private `native_wallet` command takes the exact current `head`, a valid
Ed25519 `owner`, optional `after` reference and `limit` from1 through16. Its library
entry is `Session::native_wallet`. It discovers actual selected-native ordinary
outputs without requiring the caller to supply known coin references or a key.
The cursor is a canonical lowercase-hex34-byte output reference, exclusive in
native reference order. `next_cursor` is the last returned reference when more
matching outputs exist, otherwise null. Every page requires the same exact
current caller head; a changed head requires a fresh observation.

Amounts are decimal runlai strings. Totals cover all currently selected outputs
for this owner, independently of pagination: `native_total`,
`mature_for_next_block_total`, `immature_total`, `locally_reserved_total` and
`mature_locally_unreserved_total`. The reserved total overlaps maturity totals
and must not be added to them. Fast-channel claims and locked principal are
excluded; they have separate owner-state observations.

Each output includes its reference, amount, maturity height, next-block maturity,
preparation reservation, fee-policy reservation and `manual_input_candidate`.
Successful retained transfer/own-opening/escrow preparations reserve their exact
inputs. Signed fee-policy families reserve roots and derived changes even after
expiry, exhaustion or reorganization; this read releases nothing. References
reserved by both mechanisms count once. Another caller's private reservations
are unknown, explicitly reported with `reservation_scope="THIS_CALLER_ONLY"`
and `other_wallet_reservations_known=false`.

Normal complete native/caller/control checks bracket the observation. Full cold
replay remains mandatory when opening a session. Rows are candidates for explicit
review, not spending authorization or guaranteed inclusion: keys remain unloaded,
signatures are not created, and `independent_freshness` remains false. The query
does not append records, clear pending intent, renew a policy or change any native
rule, maturity, caller capacity or monetary-network status.

### Fast owner state and signing

The private [owner-state observation](FAST_OWNER_STATE_VIEW_V1.md) separates
authenticated retained principal/fee evidence from conditional onward usability
and pending preparation. Actual selected backing, own remaining fee slots and
pending state determine whether a conditional principal is shown; closing or
exhausted funding retains historical evidence without displaying usable funds.
Original preparation metadata survives review, signing and cold replay, while
the original client submission clock remains a separate obligation. Reads cannot
approve spending, release reservations or establish native fee payout.

A session exclusively owns one native selector, one caller journal and up to16
registered actor journals. Actor roles are owner index0/1 or delegated retainer2.
Different actors/keys/processes do not establish independent operators. Requests
come through private local native stdin. No HTTP/browser, raw key, caller ledger,
serialized balance, clock override, founder API or base signer roster is accepted.
The currency is a separately supplied113-byte no-value genesis and pinned chain.

The private native_coin command takes an exact current head and a canonical
34-byte output reference. It returns that selected native ledger's owner,
amount, maturity height and next-block native maturity, or null when absent.
The response binds the current native head, selected tip and its actual timestamp.
The library exposes the same observation as Session::native_coin. Normal control,
caller and complete native prefix/identity checks precede every read; cold
startup still replays native, caller and registered actor histories from genesis.
No decoded balance or observation initializes a ledger. The command does not
append a caller request, load a key, approve spending or release a reservation.
Native maturity alone does not establish current owner consent, route/liquidity,
reservation availability, independent freshness or irreversible finality. Wallets
still require the ordinary exact preparation and authorization for a spend.

An unsigned proposal comes from this owner's last completely authenticated
receipt and the selector's current active funding origin. Constructing a proposal
neither reserves nor signs. Both parties independently submit exact invoice bytes
for review/preparation in their own journals. A session persists the key-free
request first, invokes the existing native/current-owner checks, then durably
records the verified child-head effect and review digest before releasing its
response. The review displays actual currency/channel, owner, payer, recipient,
amount, fee, invoice ID, sequence, funding miner and delegated retainer.

Signing requires a new explicit request containing approved=true, exact invoice
or receipt ID, exact review digest and the request ID of a previously durably
completed prepare/review. That previous request must belong to the same actor,
review the same child head and match the selected native context. A changed tip,
child head, amount or invoice cannot be silently rebased. The actual underlying
owner/retainer journal checks current native backing and its exact digest before
invoking the encrypted-key loader. A missing/wrong approval, stale native backing,
already signed pending state or bad custody cannot read a new signing key.

O13 keys are private regular non-symlink187-byte files, with path/opened identity
and size checks. The decrypted public key must be exactly the native owner or
delegated retainer. Passwords are bounded secure local stdin bytes only, never
argv, environment, HTTP, stored action, journal or log fields. Input/password
buffers are zeroized after processing. Keys/passwords are not copied into outputs.
A review token or a boolean alone does not prove a person actually inspected the
screen; a consumer frontend still has to obtain and protect real owner approval.

The complete receipt requires both ordered partials. Delegated custody requires
its exact full receipt, current native backing and separate persisted review.
Each owner advances only after its own retained partial, full jointly signed
receipt and delegated acknowledgment match. Missing counterpart/custody never
releases a reservation. Complete historical exit evidence remains retainable
when current backing closes or loses its branch; it does not recreate value.
All protocol payment fees retain the native funding miner and positive payer rate.
Receipt accrual is separate from native claim inclusion, payout and h+100 maturity.

## Key-free caller journal and child audit

A root contains `native.journal`, `caller.journal` and `actors/`. Creation requires
a new root. A private CREATING marker precedes initialization; incomplete creation
or RESTORING refuses unchanged. There is no merge, old-store conversion, automatic
repair, truncation, failed-target overwrite or value migration. File and parent
synchronization precedes response. The existing native/owner/retainer OS leases
and the caller's exclusive writer remain mandatory.

All integers in binary framing are big-endian. Caller header197 bytes:

```
ASCII("RLDFSES1")8 || version:u16=1 || suite:u16=1
chain32 || genesis113 || native_initial_storage_head32 || created_at:u64
```

Header hash is SHA256(`ASCII("RLD-FAST-SESSION-1/HEADER") || 0x00 || exact_header`).
The native initial head must equal the fully checked selector's actual header
head. It cannot nominate an existing selected ledger or omit earlier native work.

A record is `length:u32 || kind:u8 || previous_head32 || payload_length:u32 ||
canonical_JSON_payload || record_hash32`. Length counts bytes after itself and
is69+payload_length, at most1048576. Hash/head is SHA256 of
`ASCII("RLD-FAST-SESSION-1/RECORD") || 0x00 || kind || previous_head ||
payload_length || canonical_JSON_payload`. No alternative or trailing encoding.

Kind1 intent is the exact ordered JSON object `{"id":ID,"action":ACTION,"at":TIME}`.
ID is a nonzero32-byte lowercase hex request ID, unique in that session. TIME is
an unsigned u64 JSON integer, nondecreasing and no later than the opening clock.
ACTION has one exact typed method and fields below. Canonical bytes are the
UTF-8 `serde_json` compact serialization of the declared typed structures and
declaration order in `fast_session.rs`; cold replay reserializes and requires
byte equality, rejecting unknown/duplicate fields and alternate encodings.
Request digest is SHA256(`ASCII("RLD-FAST-SESSION-1/REQUEST") || 0x00 ||
canonical_ACTION`). It covers every key-free action field, including key path
and explicit approval. It never contains a password, raw key or decoded ledger.

Kind2 reply is the ordered JSON object with fields `id`, `request`, `effect`,
`review`, `diagnostic`. The first two bind the exact pending request/digest.
`effect` is null or the exact newly retained child head; `review` is null or a
32-byte digest; `diagnostic` is null or at most256 UTF-8 bytes. A reply payload is
at most4096 bytes. No arbitrary response JSON, signature, balance or success flag
is deserialized as native authority. Returned proof bytes come from completely
verified child records. Before accepting an intent, reserve capacity for its full
record plus the maximum reply; no accepted obligation depends on later enlargement.

There is at most one incomplete intent. Every cold open:

1. Checks the independently retained latest caller head and canonical caller chain.
2. Reexecutes the native selector's complete known branches from pinned genesis.
3. Reconstructs the exact native selected tip/head at each completed caller action.
4. Opens one actor at a time and fully replays its native origin and every retained
   signature/receipt/ack. It checks exact registration/header bytes, role, delegation,
   current backing at each successful historical request, each actual child record,
   times, review references, exact previous/new heads and complete transition coverage.
5. Refuses any unmatched native/actor tail, fabricated review, weaker selected view
   or unsupported metadata before permitting new key loading.

An actor ID is SHA256(`ASCII("RLD-FAST-SESSION-1/ACTOR") || 0x00 || chain32 ||
channel_open_OP32 || role:u8 || delegation_ID32`). Its sole path is
`actors/<lowercase_actor_ID>.journal`; a request cannot choose arbitrary child state
paths. Registration derives full genesis-to-funding history from the selector's
own authenticated selected ancestry, not caller-supplied balances/history.
Header and step hashes locate/check bytes only; native/cryptographic replay remains
authoritative. Warm operations compare the exact retained caller prefix and
Unix file identity; child/native checks remain independent. An actual custody
fault requires cold verification. Old caller-head requests cannot first-sign.

Caller and each actor file/prefix are at most32 MiB. Caller request count is at
most65536; actors at most16. The native selector keeps its separate256-MiB/
262144-block/default100000-coin limits. Native block indexes, one open actor,
parsed caller requests, proofs and execution memory add separate real costs.
These are fixed local admission bounds, not achieved throughput or ordinary-
hardware qualification; peer data cannot enlarge them. Full prefix checks and
historical audits are intentionally expensive. Scaling/archival/rotation,
ordinary resource envelopes and composed daily workload remain required work.

## Explicit interruption recovery

Before a potentially mutating action, the external caller retains its exact
request ID, action digest and prior caller head. `serve` normally requires the
independently retained latest caller head. It never adopts a same-file observed
head as independent freshness, and an incomplete intent requires explicit recovery.

Recovery requires the immediate pre-request caller head, exact request ID and
exact action digest. It cold-authenticates the complete caller/child histories.
If a child has not changed, it records NO_CHILD_STEP resolution; it does not first-
prepare, sign, acknowledge, cancel, free an owner slot or claim payment failure.
If exactly that next child record exists, it keylessly verifies and returns its
original signed proof. Different/multiple/torn tails refuse unchanged. A native
step preserves the actual greatest-work branch; recovery cannot choose a weaker
history. An existing caller reply is audited and reproduced as existing evidence.

Recovery may append only the caller's verified resolution record. It never loads
a key, writes a native/owner/retainer step, first-signs or creates a new money right.
A previously unsigned invoice still needs a new explicit reviewed signing request.
Key-file paths may be absent during recovery. All-state/head/key rollback, copied
keys across independent journals, power loss and cross-device latest-state custody
remain unqualified. A local caller journal is not an independent freshness oracle.

## Local entry points and requests

```
rld-fast-payment-session create ROOT GENESIS_FILE PINNED_CHAIN
rld-fast-payment-session serve ROOT GENESIS_FILE PINNED_CHAIN LATEST_SESSION_HEAD
rld-fast-payment-session recover ROOT GENESIS_FILE PINNED_CHAIN PRIOR_SESSION_HEAD REQUEST_ID REQUEST_DIGEST
```

Every input line is at most2 MiB. Keys/IDs are lowercase32-byte hex. Responses
always report fast_completion_authorized=false, no independent freshness or
network monitoring, and NO_VALUE_ONLY. A signature/ack remains conditional proof.
The executable takes actual system time; requests cannot override it.

Control requests have `command` and exact fields:

- `status`: head.
- `pending`: head, actor, invoice (owner invoice ID or retainer receipt ID); keyless
  retained proof only, never a new observation of current backing.
- `propose`: head, actor, payer (0/1), amount (canonical decimal string), invoice
  (nonzero caller nonce32); returns unsigned bytes from native/retained state.
- `execute`: head, request_id, action, password (null except explicit native key
  operations). Password is ephemeral stdin material, excluded from ACTION/digest.

ACTION declaration-order fields (method first; all `tip` values are exact selected
native IDs, not supplied ledger states):

| method | Remaining fields |
| --- | --- |
| native | tip, block (complete native hex) |
| owner_create | tip, channel, owner (0/1), delegation (245-byte hex) |
| retainer_create | tip, channel, delegation |
| owner_prepare | tip, actor, invoice (323/575-byte unsigned hex) |
| owner_review | tip, actor |
| owner_sign | tip, actor, invoice (invoice ID), review_request, review, key_file, approved |
| owner_complete | tip, actor, receipt (579/831-byte hex), ack (340-byte hex) |
| retainer_prepare | tip, actor, receipt |
| retainer_review | tip, actor |
| retainer_sign | tip, actor, receipt (receipt ID), review_request, review, key_file, approved |

A client must retain every valid submission/refusal/pending request and original
clock when later measuring F02/F03; an unrecorded edge rejection or retry is not
an excluded denominator or completed payment. This local interface is not live
peer delivery. Authenticated peer/session transport, consumer consent UI, durable
external latest-head custody, fee-solvent timely native claim monitoring,
independent operations/review, funding/settlement/mass-exit capacity, long-history,
physical routes and the complete G1-G11 campaigns remain mandatory. No narrow
process/signature test supplies those gates or an operational stellar payment route.
