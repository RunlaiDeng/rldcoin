# Streamed payment capsule, version 1

This file specifies a no-value application-layer codec for D02. It changes no
Survivor-1 consensus bytes, contact payload registry, mining, supply or owner
authorization. Existing packet/frame size limits remain unchanged; a capsule file
is not implicitly an accepted contact packet. A transport adapter needs its own
bounded custody integration. No monetary adoption or independent qualification
follows from implementing this codec.

## Canonical bytes

All integers are unsigned big-endian. No optional fields, alternative encodings or
trailing bytes are accepted. The fixed 96-byte header is:

```
magic:bytes[8] = ASCII "RLDPCAP1"
version:u16 = 1
suite:u16 = 1
chain_id:bytes[32]
block_count:u64
transaction_length:u32
history_bytes:u64
tip:bytes[32]
```

The header is followed by the exact complete C04 transaction X (248..1638 bytes),
the exact 85-byte C03 genesis, then block_count records of `length:u32 || block`.
Each block is 270..262144 bytes. history_bytes is the exact sum of these length
prefixes and block bytes. A zero count requires zero history_bytes and tip equal
to chain_id. Otherwise blocks form one complete consecutive genesis-to-tip history;
no peer cache, unchecked checkpoint or serialized ledger supplies its beginning.

The final 32 bytes are SHA256 of
`ASCII("RLD-SURVIVOR-CAPSULE-1/CONTENT") || 0x00 || all preceding capsule bytes`.
This digest identifies the entire exact container, including X's signature and
all carried evidence. It is neither a signature by the owner on the wrapper nor
ledger authority. X retains its ordinary independent owner signature; the history
retains all native block/transaction checks. Different valid evidence may produce
another capsule digest for precisely the same X.

Total file size is exactly `213 + transaction_length + history_bytes`. It is
bounded by the caller's locally provisioned ledger database byte budget, not a
peer-supplied limit. Declared count is bounded by history_bytes / 274 before any
count-dependent allocation. Verification reads at most one bounded block plus
bounded per-block digest/length metadata and the normal native ledger/coin map.
There is no fixed assumption that history fits in one 32-block native admission
or one contact frame. Resource refusal never prunes already retained obligations.

## Verification and observations

The caller supplies authentic expected genesis and chain independently. Both the
header pin and carried genesis must match. Strict C04 decoding authenticates exact
X. If the caller supplies a previously retained expected X, every byte, including
the signature, must match; a digest/transaction ID alone is insufficient.

Reconstruct the carried ledger with ordinary Ledger::from_genesis and execute
every complete block with the shared native kernel. Check complete record lengths,
the declared terminal tip, whole-content digest and exact end of file. Syntax,
signature, work, parent, timing, state-root, ownership, maturity and issuance rules
are never replaced by the capsule digest. A complete history need not include X:
its input can be missing, conflicted or immature. The recipient reports those
conditions under its actual selected state; a valid signed intent alone is no money.

Truncated header/body/footer is WAITING_FOR_HISTORY. Unsupported version/suite,
wrong independently pinned chain/genesis, noncanonical size/count, altered expected
X, bad digest, invalid native history or wrong declared tip refuses. Initial full
verification completes before any local monetary mutation. Read-only verification
reports carried native evidence, never independent freshness, global finality or
current recipient spendability. Local activation still requires the native clock.

## Export, refresh and import

Export writes a fresh private file, fully replays the selected source history as
it streams, writes its final digest, then synchronizes file and parent directory.
It acknowledges no incomplete export and never overwrites an existing path.
Partial failed output remains for diagnosis and fails ordinary verification.

Refresh verifies an earlier capsule and exports its exact X against the source's
current fully replayed selected history. There is no new signing, change of fee,
expiry, inputs or recipients, refund or restoration of orphaned reward value.

Import first performs complete independent verification, then rereads each record
and checks its full-byte digest against process-local metadata from that replay.
Every imported block still goes through ordinary Store::accept, with deterministic
domain-separated operation IDs binding capsule digest, record index and bytes.
Neither the existing 32-block grouped interface nor any transport limit is raised.
Ordinary branch selection can keep a stronger local history; branches never merge.
After import, X is retained through the ordinary transaction pool and observations
are recomputed against the actual local selected tip, not the carried claim.

A file/I/O/capacity failure during application may leave individually native-valid
prefix transitions durably retained; it does not acknowledge complete capsule
import. Exact retry fully verifies again and uses the original per-record operation
IDs. No new owner signature is produced. Changed reread bytes refuse rather than
being accepted on the strength of a prior digest. This is not an atomic multi-block
publication, independent latest-state protection or power-loss qualification.

## Conformance

Public no-value byte vectors bind header/endian/length/digest construction to the
published Survivor consensus vectors. Checks include an empty carried history and
a complete payment prefix longer than one native group; both bind exact X.
Negative cases cover every fixed field, count/length overflow, truncation, wrong
pin/genesis, changed expected X, footer replacement, recomputed-digest invalid native
tails and false tips. Initial rejection preserves local head/revision/coins/pool.
Refresh must preserve full X while independently changing evidence, including an
input missing from the new selected history without fabricating a credit.

Ordinary CLI checks export/import a real owner payment, reconstruct a fresh
recipient, complete its separately authorized onward spend and cold-replay the
result. Larger history/resources, independent implementations/custody, physical
transport and all fast-layer G9-G11 obligations remain separate.
