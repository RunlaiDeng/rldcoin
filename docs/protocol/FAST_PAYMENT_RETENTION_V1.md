# Funded fast payment and delegated fee retention V1

This is a no-value application/custody candidate over
[RLD-FAST-ESCROW-1](NATIVE_FAST_ESCROW_V1.md). It changes no genesis, block,
issuance or native escrow operation. A payment receipt and retainer acknowledgment
are necessary evidence, not monetary adoption, independent monitoring, principal
finality or a completed G9-G11 campaign. Durable owner partial signing is specified
separately in [owner authorization V1](FAST_OWNER_AUTHORIZATION_V1.md); the ordinary
frontend/caller-head service and continuously monitored fast service remain required.

## Native origin and complete payment

An origin is constructed exclusively by native genesis/header/body/value replay
through the actual funding block. It contains the exact228-byte fee context,
initial owner balances, channel OP ID and birth height. Supplied context bytes,
balances or a hash cannot construct a native origin. Existing-receipt verification
may use that historical origin; first retention additionally requires the same
currently active, nonclosing escrow on a separately pinned current native tip.

The complete payment uses big-endian integers and no alternative/trailing encoding.
Its unsigned invoice body I is:

```
version:u16=1 || suite:u16=1
chain:bytes[32] || channel_open_OP:bytes[32] || context_commitment:bytes[32]
invoice:bytes[32]!=zero || previous_receipt_ID:bytes[32]
payer_index:u8                       // 0=A, 1=B
amount:u128 || protocol_fee:u128
previous_certificate_length:u16     // exactly0(initial) or252
previous_certificate:bytes[length]
next_unsigned_state:bytes[124]
```

I is323 or575 bytes. Append state_signature_A64, state_signature_B64,
invoice_signature_A64, invoice_signature_B64, giving579 or831 bytes. State
signatures retain the exact [fee-component domain](FAST_MINER_FEE_CLAIMS_V1.md).
Both invoice signatures cover
`ASCII("RLD-FAST-PAYMENT-1/INVOICE") || 0x00 || I`. A partial is
`owner_index:u8 || own_state_signature64 || own_invoice_signature64`, exactly129
bytes. Combining two partials never signs and requires distinct correct indices
and both full domains. No owner-signing authority follows from this assembler.

Length0 means the originally jointly authorized funding split, q=0, zero counters,
and previous_receipt_ID zero. A252-byte previous certificate must have q>0 and a
nonzero previous receipt ID; it authenticates both native-context state signatures.
Next q must equal previous q+1 and the sum of its two counters. Only the payer's
counter increments by one; the other's is unchanged. The exact positive fee is
that payer's native funding rate and cannot exceed its remaining authorized slots.
Amount is positive and funded by the payer's previous principal; the recipient's
principal increases by that amount. Principal and fee backing remain distinct.
All overflow, changed fee/amount, skipped state, changed context/owner or invoice,
unsupported version, bad signature and noncanonical initial states refuse.

Receipt ID is SHA256(`ASCII("RLD-FAST-PAYMENT-1/RECEIPT") || 0x00 || full_receipt`).
Logical payment ID is SHA256(`ASCII("RLD-FAST-PAYMENT-1/PAYMENT-ID") || 0x00 ||
chain32 || native_funding_identity32 || payer_index:u8 || payer_next_slot:u64`).
Another invoice using the same slot conflicts rather than creating a new payment.
A custody journal additionally requires previous_receipt_ID and complete previous
certificate to equal its last acknowledged receipt/state. A signature alone does
not prove that a supplied previous-receipt ID describes an available history.

## Funding-miner delegation

A fee retainer is explicitly authorized by the funding block's actual miner key.
The245-byte delegation is unsigned D followed by that miner's64-byte signature:

```
version:u16=1 || suite:u16=1
chain32 || channel_open_OP32 || context_commitment32 || miner_key32 || retainer_key32
maximum_tip_age:u64=7200 || maximum_monitoring_gap:u64=3600 || purpose:u8=1
```

D is181 bytes. The miner signs
`ASCII("RLD-FAST-PAYMENT-1/DELEGATION") || 0x00 || D`. The native origin determines
chain/channel/context/miner; a caller cannot nominate another beneficiary. The
retainer key must be valid and distinct from both owners and the miner. Different
keys do not establish independent people/operations. Delegation ID is SHA256 of
`ASCII("RLD-FAST-PAYMENT-1/DELEGATION-ID") || 0x00 || full_delegation`.
It grants receipt/monitoring authority only, never an owner signature, base signer
role, arbitrary spending, issuance or cryptographic independent freshness.

Before first acknowledgment, the current native tip must match the caller's
separately supplied expected tip, be future-eligible and no more than7200 seconds
old under the actual local clock. The escrow/context must still be active and
not closing. A previous acknowledgment's observed time cannot move backward.
These are finite local observations; they do not prove unseen work, actual
continuous3600-second monitoring or timely challenge inclusion. No qualified fast
completion may be inferred until those independent service obligations are met.

## Durable custody acknowledgment

The340-byte acknowledgment consists of unsigned A276 bytes and a64-byte retainer
signature. A is:

```
version:u16=1 || suite:u16=1
chain32 || channel_open_OP32 || context_commitment32 || delegation_ID32
receipt_ID32 || logical_payment_ID32 || observed_native_tip32 || prepared_journal_head32
next_sequence:u64 || observed_at:u64
```

Sign `ASCII("RLD-FAST-PAYMENT-1/ACK") || 0x00 || A`. It attests exact complete
receipt custody, not ledger inclusion, mature fees or final money. Before key
loading, validate the full payment/native scope, caller journal/native heads and
review. Persist the complete prepared receipt first, synchronize file and parent,
then sign and durably retain the exact acknowledgment before releasing it.
The review digest is SHA256(`ASCII("RLD-FAST-PAYMENT-1/REVIEW") || 0x00 ||
current_native_tip32 || prepared_head32 || receipt_ID32 || delegation_ID32`).
Changed native head requires a newly reviewed digest, not silent rebasing.

Passwords are secure local byte inputs, never argv/environment/HTTP/log fields.
Native O13 encrypted key files may supply the exact separately delegated key.
Recover-only takes the caller's prior retained head and exact receipt ID; it may
return an already authenticated complete signed acknowledgment after fsync, never
load a key, first-sign, change a receipt or treat a timeout as payment failure.
An unsigned prepared record remains pending until explicit key-authorized signing.
The separate command
`rld-fast-retainer-recover JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD RECEIPT_ID`
implements only this keyless recovery. It accepts no key/password and outputs
PREPARED_NO_ACK or ALREADY_SIGNED, the exact retained bytes and head, with unknown
current backing and fast_completion_authorized=false. It fsyncs authenticated
retained data but appends no record and cannot first-sign. An existing acknowledgment
does not become a new observation of current native backing through recovery.

## Bounded append-only journal

The journal uses a private regular file and private parent directory, an exclusive
native OS lock and an independently retained latest caller head. No migration,
tail truncation, incomplete-output replacement, pruning or inferred latest head
is permitted. Existing stopped/corrupt bytes remain. Private permissions and file
identity checks are implemented on Unix; other platforms refuse journal opening
until that native contract exists. File and retained prefix bytes are bounded by
the caller's local limit (maximum256 MiB per copy); native
replay memory and bounded one-record buffers are separate. This limit cannot be
enlarged by a peer, delegation or payment. Capacity is reserved for both prepare
and acknowledgment before accepting a new custody obligation.

The header is `ASCII("RLDFRET1")8 || version:u16=1 || suite:u16=1 || chain32 ||
channel_open_OP32 || genesis113 || history_bytes:u64 || history || delegation245`.
History uses native `length:u32 || complete_block` records and must end at the
actual funding block, with no more than262144 blocks. Header ID is SHA256 of
`ASCII("RLD-FAST-PAYMENT-1/JOURNAL-HEADER") || 0x00 || exact_header`.
It identifies bytes; cold startup still fully executes all native funding history.

Each record is `length:u32 || index:u64 || previous_head32 || kind:u8 || payload ||
record_hash32`, where length counts everything after itself and is73..1024.
Indices start at1. Hash is SHA256(`ASCII("RLD-FAST-PAYMENT-1/JOURNAL-RECORD") ||
0x00 || index:u64 || previous_head32 || kind:u8 || payload`). It becomes the head.
Kind1 payload is `observed_native_tip32 || receipt_length:u16 || complete_receipt`;
kind2 payload is the complete340-byte acknowledgment. A second prepare while
pending refuses. Acknowledgment must bind the pending receipt/delegation/prepared
head and authenticate the delegated signer; only then advance the last complete
state and receipt ID. Every cold record is fully authenticated, never decoded as
cached ledger authority. Truncated, altered or forked history refuses unchanged.

A warm journal may retain its exact completely authenticated prefix, latest
payment evidence and numerical counters in process. Before each append it reads
and compares the entire retained file prefix byte-for-byte and rechecks path/file
identity. Changed bytes, length or inode suspend writes; no unchecked state cache
initializes custody. Appends fsync both file and parent before response. I/O errors
poison mutation until complete cold verification; an ambiguous complete signed
tail needs explicit keyless recovery, never replacement signing.

## Unfinished product obligations

This component does not provide durable ordinary-user owner signing, live node
branch selection/monitoring, a network endpoint, independent retainer operation,
cross-device/common rollback resistance, power-loss qualification or actual fee
challenge service. A qualified retainer must also retain its own mature operation-
fee liquidity or a separately adopted bounded fee authority; delegation alone
does not spend a miner/owner coin. The caller's current ledger must come from one
serialized native selector retaining greatest known work, with a separately held
latest native head. An arbitrary valid old branch and a self-observed hash do not
establish that condition; this journal does not implement native selection/monitoring.
Closing/orphaned backing prevents new acknowledgments under that current view;
historical recovery preserves old evidence without restoring value. The canonical
native claim/settlement path still has to include those proofs and mature payouts.
Full prefix comparison/replay, KDF and retained receipt data have real resource
costs; measure them under the complete daily cohort rather than extrapolating a
small test. No local acknowledgment alone closes G9, G10 or G11.
