# Direct native payment peer carriage V1

RLD-FAST-PEER-1 is a direct admitted-neighbor ground data adapter for the
[native payment session](FAST_PAYMENT_SESSION_V1.md). It changes no native genesis,
work, monetary transaction, wallet signature, fee rule or ordinary Survivor-1
contact registry. No monetary adoption, physical route, always-online directory,
independent custody/operation or G1-G11 composition follows from this adapter.
Ordinary CPU mining and asynchronous interstellar carriage remain separate.

## Roles, admission and startup

Each transport directory has a separate random Ed25519 data identity and a
separate self-signed TLS certificate/private key. Neither is a wallet, miner or
fee-retainer signing key. Retained key/TLS files are private regular files and are
never regenerated on a missing/mismatched retained key. CREATING/BINDING/RESTORING
residue refuses without repair. Generated material and private admission/box state
must never be published, including encrypted material or runtime inventories.

Admission is local typed JSON: chain, identity, literal listen SocketAddr and at
most16 peers containing key, literal endpoint and certificate_sha256. Unknown
fields, duplicate/self/invalid keys or duplicate pins, zero destination port and
unspecified destination IP refuse. Canonical typed JSON SHA256 binds that exact
admission to the box; changes require explicit new transport state, not learned
endpoints/pins or a silent fallback. Only TLS1.3, strict Ed25519, mutual exact pins,
chain/identity certificate bindings and finite local certificate validity are used.
No DNS directory, public CA, plaintext/insecure downgrade or early data is used.
The existing90-day ground certificate policy is not stellar cryptographic or
long-disconnection/revocation qualification.

```
rld-fast-peer init PEER_ROOT CHAIN
rld-fast-peer bind PEER_ROOT CONFIG_FILE
rld-fast-peer recover PEER_ROOT CHAIN PRIOR_PEER_HEAD PACKET_OR_MESSAGE_ID
rld-fast-payment-session serve ROOT GENESIS PIN SESSION_HEAD --peer-root PEER_ROOT --peer-head PEER_HEAD
```

Init returns public identity/fingerprint only. Bind durably creates admission and
an empty data-custody journal. Normal opening requires the separately retained exact
latest peer head and unchanged material/configuration. The adapter starts with the
ordinary session lifecycle; no separate manual listener is required. Native control
and bounded incoming/outgoing workers remain separate. A busy listener retries
without claiming a working endpoint or disabling local native/owner operation.
Sockets wait under no ledger/custody lock. Inbound connections are capped at2,
incoming queue8, outgoing queue1 and one in-flight delivery. Each TLS attempt has
one3-second socket deadline; main-loop custody may occur after a timed-out socket,
so timeout never proves non-delivery, frees value or deletes pending evidence.

Incoming data never contains a signing RPC, password, key-file path, owner approval,
caller state or accepted ledger snapshot. Node data reception, native import,
owner acceptance, onward payment and mature miner payout remain distinct.

## Canonical packet and connection bytes

All integers are big-endian. Every tag is `ASCII("RLD-FAST-PEER-1/") || label ||
0x00`. Hashes are SHA256(tag || bytes); signatures are strict Ed25519 over tag ||
bytes. Existing native/wallet/retainer domains are unchanged.

Packet unsigned body:

```
version:u16=1 || suite:u16=1 || chain32 || sender_data_key32 || destination_data_key32
kind:u8 || message_tag32 || payload_length:u32 || exact_payload
```

Append sender signature64 under PACKET. Complete size is201+payload_length, maximum
262345. Sender/destination must be valid distinct points. Message tag is
hash(MESSAGE, first101_unsigned_bytes || exact_payload), never a connection nonce.
The same exact data/roles/kind yields the same packet and retry identity; a peer
cannot make duplicate content distinct by changing that tag. Packet ID is
hash(PACKET-ID, complete_packet). New connection freshness comes separately below.

| kind | Payload | Meaning before local execution |
| --- | --- | --- |
|1|270..262144-byte complete version2 native block, matching chain|Untrusted native evidence; full genesis/PoW/owner/value execution still required|
|2|323/575-byte existing unsigned invoice, version1/suite1/matching chain|Proposal only; no owner signature or reservation|
|3|invoice_ID32 plus129-byte existing ordered own partial|Carrier-authenticated bytes; native-context wallet verification still required|
|4|579/831-byte existing complete receipt, matching version/chain|Complete bytes; both owner/state/invoice signatures and backing still require local checks|
|5|340-byte existing retainer acknowledgment, matching version/chain|Complete bytes; exact native origin/delegation/receipt verification still required|
|6|39..4134-byte versioned signed native-operation frame|Signed data only; explicit local pool retention and full native template/admission checks remain required|
|7|403..2511-byte versioned unsigned native opening proposal frame|Proposal data; independent local native review and own approval remain mandatory|
|8|468..2576-byte proposal frame plus65-byte verified opening partial|One actual owner signature only; both owners and full native admission remain mandatory|

No alternative/trailing encoding or other kind is accepted. The separately
assembled [public transport byte vectors](fast-peer-v1-vectors.json) use labeled
public no-value data keys and deliberately invalid zero wallet signatures in their
partial. They prove codec interoperability only, not a funded origin or payment.
Kind6 has its own version/suite/chain/length frame and separate
[operation-pool contract and public vector](FAST_NATIVE_OPERATION_POOL_V1.md).
Older peers refuse this unknown kind without fallback; kinds1..5 are unchanged.
Kinds7/8 have the separate [opening authorization and frame contract](FAST_NATIVE_OPENING_AUTHORIZATION_V1.md)
and [public no-value byte vectors](fast-native-opening-v1-vectors.json). Their
owner signatures never substitute for current native ownership/maturity checks.
Peers lacking these kinds refuse them explicitly; existing data versions and
limits are unchanged and no old state or value is converted.

After pinned mutual TLS authenticates the exact configured remote certificate,
server sends164 bytes: `v/suite4 || chain32 || server_data_key32 || fresh_S32 ||
signature64(CHALLENGE, first100_bytes)`. S is fresh nonzero local entropy.
Client verifies it and creates its own fresh nonzero C. Delivery body:

```
v/suite4 || chain32 || client_data_key32 || server_data_key32
S32 || C32 || packet_length:u32 || complete_packet || signature64
```

Signature uses DELIVERY over everything preceding it. Size is232+packet_length;
a4-byte complete length frames it on TLS. Server verifies both fresh connection
bindings, TLS-client/data-signer identity, exact destination, full packet signature
and payload shape on every envelope before any deduplication. Old bodies cannot
authenticate changed envelopes or another connection.

After actual complete durable receiver custody,293-byte response is:

```
v/suite4 || chain32 || server_data_key32 || client_data_key32
S32 || C32 || packet_ID32 || current_receiver_box_head32 || scope:u8=0 || signature64
```

Signature uses RESPONSE over the229-byte unsigned body. Scope0 means data custody
only. Client verifies roles, chain, packet ID, both live nonces and signature;
it must durably retain that exact response before suppressing retries. No network
receipt grants ledger inclusion, owner consent, miner reward, current backing,
finality, a route or qualified usable receipt.

## Durable data box

Header148 bytes: `ASCII("RLDFPEER")8 || v/suite4 || chain32 || local_data_key32 ||
local_TLS_fingerprint32 || admission_digest32 || created_at:u64`. Header head is
hash(BOX-HEADER, exact_header). Each record:

```
length:u32 || index:u64 || previous_head32 || observed_at:u64
kind:u8 || payload_length:u32 || payload || record_hash32
```

Length counts everything after itself and equals85+payload_length. Index starts
at1. Head is hash(BOX-RECORD, index || previous_head || observed_at || kind ||
payload_length || payload). Record kind1 queues a full packet, kind2 receives a
full packet, kind3 stores packet_ID32 plus the exact293-byte verified response.
Cold opening checks exact header/pins, complete every-packet signature, stable
message tag, admission/direction, full response authentication, record chain,
nondecreasing local times and exact externally pinned latest head. A digest or
JSON flag never initializes native value or supplies independent freshness.

Box/prefix is bounded by32 MiB and2048 retained packet identities, including
completed obligations; no pruning or expiry is available. An outgoing queue must
reserve414 bytes for its eventual complete response record. All admission,
including incoming data, preserves every outstanding response reservation. Full
capacity refuses unchanged, before a new custody response. Exact duplicates still
reauthenticate and fsync retained file and parent before acknowledgment. Pending
work retains its original queued_at; retry/timeout never resets its age.
Warm mutation/read checks exact retained prefix, length and Unix inode/device
under an exclusive writer lease. File/directory synchronization precedes response.
Any custody failure suspends new acknowledgments; preserve corrupt/torn data and
all failed residue. These process/filesystem checks are not power-loss, copied-key,
common/all-state rollback or independent latest-head qualification.

If the caller missed only the last custody advance, explicit recovery requires
its separately retained exact predecessor head and the exact last packet ID or
stable message tag. The latter can be computed from known chain, data identities,
kind and payload before queuing. Recovery fully cold-authenticates the complete
box and its unchanged material/admission, requires that exact immediate last
transition, rechecks retained bytes and synchronizes file and parent. It returns
the existing head without appending, starting sockets, loading a wallet key or
creating any signature. This covers a last queue, receive or stored response;
it cannot skip multiple unknown transitions, truncate a tail or repair bad bytes.
Normal opening continues to require the exact current head. This narrow data-only
reconciliation is not an independent latest-state witness or value recovery.

## Local payment/session integration

A peer-enabled node ticks transport while local stdin is idle. It reports the real
optional listening endpoint, latest peer head, retained inventory, pending attempts
and diagnostics without fabricating a height, balance or successful connection.
The nested peer diagnostic retains the last observed transport fault; it is not
the local control command's error or a claim that a later retry failed. Successful
data delivery is observed through the exact retained destination response.
Local callers must retain latest caller/peer heads and their pending request IDs.
Nested peer status accompanies local errors as well as successes. Queuing a list
of destinations is not atomic: preserve any earlier successful queue entries and
inspect the returned head/inventory. Exact deterministic retry is idempotent.
For now native import is an explicit local private-control operation using actual
received full bytes. This preserves the session's independently supplied caller
head, pending-operation recovery and local selection checks; a peer cannot choose
a ledger head or silently rebase an approval. Autonomous external-head coordination
and continuous native/payment monitoring remain full-product work.

Additional local commands, always with current session `head`:

- peer_status, peer_inventory, peer_data(packet): data observations only.
- peer_queue(destination, kind, payload): durably queue typed exact bytes.
- peer_invoice(actor, invoice, destination): send the retained prepared invoice.
- peer_partial(actor, invoice, destination): send only the already retained own
  partial; no key loading or first signing.
- peer_prepare(actor, packet, request_id): locally execute OwnerPrepare for kind2
  or RetainerPrepare for kind4, under full current native checks; never sign.
- peer_combine_send(actor, invoice, partial, destinations): combine retained own
  partial with exact received counterparty partial and queue the verified full
  receipt to admitted destinations. No new signature/value is created.
- peer_ack(actor, receipt, destination): send only an existing retained signed
  retainer acknowledgment.
- peer_complete(actor, invoice, partial, ack, request_id): locally verify existing
  dual authorization and exact received retainer proof, then retain via the normal
  caller/owner journal. Historical retention does not restore orphan backing.
- peer_import(packet, request_id): full normal native admission for received kind1.
- peer_operation(operation, destination): carry existing retained signed native
  operations as kind6; no first signing or inclusion promise.
- peer_pool_submit(packet, request_id): explicit local retention of kind6 signed
  data; no ledger effect. Pool mining/admission remain separate local commands.
- peer_block(block, destination): queue exact retained native block bytes as kind1.
- peer_opening(source_request, destination): carry an exact retained opening
  proposal or an already retained own partial, without loading a wallet key.
- peer_open_prepare(packet, request_id, owner, timestamp): explicitly review
  received kind7 against current native state and reserve only the local index's
  inputs. No network command approves or signs that review.
- peer_open_combine(packet, request_id, prepare_request, sign_request, review):
  require kind8's exact proposal to match the retained local review and combine
  distinct existing owner proofs; full native execution remains separate.

Local execute owner_sign/retainer_sign remains the only corresponding key-loading
path and still requires exact persisted review, approved=true and secure native
password input. Transport commands cannot substitute peer identity for owner or
miner/retainer authority. Inventory's ledger_acceptance_known=false describes its
own lack of native authority; it is not proof that a local native import failed.

Direct same-host sockets, manual local approval/import and static admitted peers
are not automatic discovery/multi-hop, independent operators, physical routes,
ordinary-hardware hostile-load, monitored fee solvency/claim inclusion, scalable
archival/mass exit or daily100M/local latency qualification. Preserve every original
G1-G11 and interstellar obligation and all failed scopes. No stronger adoption or
performance claim follows from these local transport/session interfaces.
