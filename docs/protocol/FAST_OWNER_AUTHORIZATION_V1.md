# Native-funded fast owner authorization V1

This is a separately retained per-owner application journal over
[complete payment V1](FAST_PAYMENT_RETENTION_V1.md) and native
[RLD-FAST-ESCROW-1](NATIVE_FAST_ESCROW_V1.md). It changes no consensus, issuance,
block or existing payment/delegation/acknowledgment bytes. It supplies explicit
owner review and durable partial signing, not live native selection, a network
service, independent custody, mainnet or G9-G11 qualification.

## Unsigned proposal and explicit authorization

`Invoice::propose(origin, previous_payment, payer, amount, invoice_ID)` constructs
the existing323/575-byte unsigned invoice without a key or reservation. Native
funding, the complete previous receipt (if present), exact principal transition,
positive authorized fee and unexhausted payer slots are checked. An unsigned
nonzero invoice ID is caller-selected; existing signatures do not authorize a
changed ID. `Invoice::verify` performs the same checks on external bytes.
Invoice ID is SHA256(`ASCII("RLD-FAST-PAYMENT-1/INVOICE-ID") || 0x00 || I`).
`verify_partial` authenticates the exact129-byte own state/invoice signature pair
under the native origin and its ordered owner index. A proposal is not payment.

Each owner independently creates a private journal from full native genesis-to-
funding history, exact miner-signed retainer delegation and own index0/1. No key
or serialized ledger initializes the journal. `prepare` verifies the currently
active nonclosing native escrow and separately supplied expected native tip;
checks the caller's independently retained latest journal head; checks exact
previous complete receipt/state; and durably appends I before key loading.
Capacity for preparation, own signature and complete receipt/ack is reserved
before accepting the new local obligation. File and directory are synchronized.
There is one pending transition. An identical retry returns the same review under
the same current tip/head. Different amounts, invoices or subsequent transitions
refuse while pending, even before signing. There is no cancel, expiry, timeout
release, silent rebase, alternate-signature replacement or reservation waiver.

`review` exposes own key, payer, recipient, amount, fee, sequence, invoice/logical
IDs and the digest. The digest is SHA256(`ASCII("RLD-FAST-OWNER-1/REVIEW") || 0x00 ||
current_native_tip32 || journal_head32 || delegation_ID32 || own_index:u8 ||
invoice_ID32`). The frontend/caller must show these actual values and obtain
explicit owner authorization. An unsigned review token does not establish that
a person approved it. A changed native tip requires another explicit review.
`sign` verifies prefix/file identity, current backing, clock, caller head and
exact digest before invoking the encrypted-key loader. The loaded key must be
this owner. Only this owner's two existing state/invoice signatures are created;
the129-byte partial is durably appended and synchronized before returning it.
A repeated signing call refuses before key loading; use keyless retrieval instead.
O13 encrypted key files accept passwords as secure local bytes only, never argv,
environment, HTTP or logs. No key or password enters a journal or recovery tool.

## Counterparty and custody composition

`Payment::combine` still never signs. It authenticates both ordered partials and
the exact complete receipt. A local partial is not a jointly authorized state.
`retain_complete` requires that receipt to equal this owner's prepared I and
persisted own partial, verifies both owners and the exact delegated340-byte
custody acknowledgment, then durably appends both complete proofs. Only then
may a next invoice be prepared from that exact receipt/state. Another signature
made outside this journal, even if valid under the same key, cannot replace the
required retained local signature. No missing/bad acknowledgment advances state.

Retention of complete historical proof is deliberately keyless and independent
of current backing. If the escrow later closes or loses its branch, keep the
proof for challenge/audit; it does not recreate money. New preparation/signing
still require active native backing. `retained_complete` exposes exact latest
complete proof even while a later invoice is pending, so the pending reservation
cannot hide previous unilateral-exit evidence. It does not claim freshness,
timely challenge inclusion or actual miner payout. Those native/service duties
remain separately required.

## Exact bounded journal

All integers are big-endian, with no alternative or trailing encoding. Header:

```
ASCII("RLDFOWN1")8 || version:u16=1 || suite:u16=1
chain32 || channel_open_OP32 || genesis113
history_bytes:u64 || complete_native_history || delegation245 || own_index:u8
```

History is existing native `length:u32 || full_block`, at most262144 blocks,
ending exactly at this escrow's actual native funding height. Cold opening fully
executes every native block and authenticates delegation; no digest supplies
ledger authority. Fixed header overhead is443 bytes. Header head is SHA256 of
`ASCII("RLD-FAST-OWNER-1/HEADER") || 0x00 || exact_header`.

Record `length:u32 || index:u64 || previous_head32 || kind:u8 || payload || hash32`.
Length counts bytes after itself and is73..2048; index starts at1. Record head is
SHA256(`ASCII("RLD-FAST-OWNER-1/RECORD") || 0x00 || index:u64 || previous_head32 ||
kind:u8 || payload`). Payloads:

- Kind1: `local_time:u64 || observed_native_tip32 || invoice_length:u16 || I`.
- Kind2: `local_time:u64 || signing_native_tip32 || own_partial129`.
- Kind3: `local_time:u64 || receipt_length:u16 || full_receipt || acknowledgment340`.

Cold replay checks exact predecessor links, state ordering, every complete
signature, own role, original invoice, complete receipt/ack and nondecreasing
local/acknowledgment clocks. An observed clock ahead of the opening clock refuses;
no clock error removes or replaces retained evidence. Hash-chain agreement alone
never authenticates a partial, complete receipt or native funding.

The journal retains a completely authenticated exact byte prefix in process.
Before each append/retrieval it compares the entire on-disk prefix, size and Unix
inode/device; no decoded state initializes authority. It holds an exclusive OS
writer lock. Private regular-file/private-directory and file-identity operations
are Unix-only; unsupported platforms refuse. Peer data cannot enlarge the caller
limit, at most256 MiB per file/prefix copy. Native replay memory is separate.
No pruning, tail truncation, automatic repair, state migration or overwritten
creation is available. Failed writes poison mutation; preserve ambiguous/corrupt
bytes for explicit cold inspection. Complete file/directory sync precedes response.

## Keyless recovery and limits

Normal `open` requires the independently retained exact latest head. It does not
adopt a head obtained from the same possibly rolled-back file. `retained_pending`
with the exact current head returns I and an optional already signed partial.
`recover` additionally handles one ambiguous prepare/sign response: caller supplies
the independently retained immediate predecessor head and exact invoice ID; the
fully authenticated final record must be precisely that next step. It returns
PREPARED_NO_SIGNATURE or ALREADY_SIGNED. No key, first signing or new record is
allowed. `recover_complete` similarly requires the predecessor head and exact
receipt ID for a final kind3 record. It returns only retained full receipt/ack.
All reads synchronize and recheck retained exact data before release.

The standalone command is:

```
rld-fast-owner-recover partial|complete JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD INVOICE_OR_RECEIPT_ID
```

It accepts no key/password, uses actual local time, replays native/owner proofs,
appends nothing, and reports key_loaded=false, backing_currentness_known=false,
fast_completion_authorized=false and NO_VALUE_ONLY. No signature is first-created
by recovery. A caller must durably retain its intent, prior/latest head and review
before requesting mutation; this library does not implement a frontend/caller-head
service, hardware signing or independent latest-state custody. Copied keys with
separate journals and common/all-state rollback remain unqualified. Same-host
process termination is not power-loss/cross-device qualification. Continuous
native branch selection, fee-solvent timely monitoring, live transport, actual
composed daily workload, ordinary hardware and independent operators/review remain
mandatory. Nothing here converts a partial or custody acknowledgment into final
base-chain money or a complete fast-payment claim.
