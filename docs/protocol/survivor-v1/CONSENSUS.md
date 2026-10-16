# Survivor-first consensus and binary formats

## C01. Identity, units and arithmetic

The only baseline profile is `RLD-SURVIVOR-1`, version `1`, suite `1`.
It has no validator roster, quorum, founder privilege, region admission, checkpoints
that prevent reorganization, emergency signing key or discovery service prerequisite.
Mining and validating need no permission. Network identities confer no spending rights.

One RLD is exactly `10^24` runlai. The cap is `10^35` runlai (100 billion RLD).
All monetary amounts are unsigned integers in runlai, never floating point.
An accepted history starts with zero issued value and no outputs.

`u8`, `u16`, `u32`, `u64`, `u128`, `u256`, `u384` are unsigned integers of the stated
bit width, encoded big-endian in exactly width/8 bytes. Hashes and public keys are
raw bytes, not endian-reversed numbers. Concatenation is `||`. `bytes[n]` has exactly
n bytes. A vector is its specified count followed by exactly that many elements.
No padding, optional fields, duplicate fields, noncanonical integers, trailing data,
compressed consensus bytes, JSON or textual numbers occur in the binary encoding.
An enclosing length must match exactly. Arithmetic uses mathematical nonnegative
integers with intermediates wide enough to avoid overflow; range checks precede
encoding. Overflow never wraps, saturates a balance or partially changes state.

`H(tag, x) = SHA256(ASCII("RLD-SURVIVOR-1/") || ASCII(tag) || 0x00 || x)`.
Only the exact uppercase tags specified here are valid at their use sites.
`D(tag, x) = SHA256(H(tag, x))`. SHA256 means the 32-byte SHA-256 digest.
IDs, signatures and tree commitments use distinct tags. An implementation source
hash is a release audit input, not a consensus domain: independently written
implementations must compute identical identities.

## C02. Cryptography

Suite 1 uses SHA-256 and pure Ed25519 from [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).
Signatures are exactly 64 bytes `R || S`; keys are exactly 32 bytes. In addition to
the RFC verification equation, both A and R MUST have canonical compressed Edwards
encodings, lie in the prime-order subgroup and be nonidentity. Require `S < L`,
where `L = 2^252 + 27742317777372353535851937790883648493`; verify
`[S]B = R + [SHA512(R || A || message) mod L]A`. Noncanonical y, forbidden sign
encoding for x=0, torsion and identity points refuse. No ZIP215, cofactor-only,
prehash or context-signature substitution is permitted. This is a strict subset of
Ed25519 verification, specified to eliminate library-policy divergence.

Wallet, contact and release-signing keys are separate roles. Suite 1 is not
post-quantum and is not qualified for arbitrary stellar travel durations. A protocol
version field is not an implemented cryptographic migration. See O12 for upgrades.

## C03. Genesis and network binding

The genesis manifest is exactly 85 bytes:

| Field | Encoding | Requirement |
|---|---|---|
| magic | bytes[8] | ASCII `RLDSGEN1` |
| version | u16 | 1 |
| suite | u16 | 1 |
| network_kind | u8 | 0 = no-value test; 1 = monetary adoption |
| network_nonce | bytes[32] | Independently chosen nonzero network discriminator |
| started_at | u64 | Unix seconds, `<= 2^64-1-14400` |
| initial_target | u256 | Exactly `LIMIT = 2^248-1` |

`chain_id = H("GENESIS", manifest)`. Genesis has height 0, timestamp started_at,
base_target and target LIMIT, cumulative work 0, no miner or transactions and an
empty UTXO set. Its ID is chain_id; it is not a mined block. Its state root is
computed by C09 using issued=0. Nodes MUST pin the exact genesis bytes and chain_id
through their own authenticated installation/adoption process. Learning a manifest
from a peer does not adopt it. Network_kind is immutable. There is no in-place
test-to-mainnet conversion or allocation/import field.

The manifest itself requires no online signer. A monetary release must authenticate
the manifest through its separately reviewed release procedure; that authentication
does not give its signers block vetoes. No monetary manifest is supplied here.
Genesis nonce/time are instance identity inputs, not unresolved algorithm choices.

## C04. Transfer encoding and authorization

An outpoint is `transaction_id:bytes[32] || output_index:u16` (34 bytes).
The unsigned transfer `U` is:

```
version:u16 = 1
chain_id:bytes[32]
owner:bytes[32]
input_count:u16                 // 1..32
inputs:outpoint[input_count]    // strictly increasing by raw 34-byte order
output_count:u16                // 1..8
outputs:(owner:bytes[32], amount:u128)[output_count]
fee:u128                       // at least 1 runlai
valid_through_height:u128
```

Output order is the signer's order, and determines the output index starting at 0.
Every output amount is positive and `<= cap`; every owner is a C02-valid public key.
Input duplicates refuse. One owner signs all inputs; mixed-owner/group/scripted
transfers are not part of version 1. No change output is implicit.
`transaction_id = H("TXID", U)`. The signature message is
`ASCII("RLD-SURVIVOR-1/TRANSFER") || 0x00 || U` (not the digest alone).
The complete transaction `X = U || signature:bytes[64]`.
Maximum size is 1638 bytes; minimum is 248 bytes. A framing length does not enter
transaction_id or the signature. Signature bytes do enter the block's transaction
root. There is no signature replacement, fee bump or cancellation authority from
an unsigned client request.

At candidate height h all inputs must exist in the **parent** UTXO set, belong to
owner, have maturity_height <= h, and not be consumed by another transaction in the
same block. Require `h <= valid_through_height`. Sum(inputs) must equal
sum(outputs)+fee, checked in mathematical integers and each sum <= cap. Apply all
signatures and checks before mutating the candidate state. Transactions cannot spend
outputs created in their own block. Descendant transfers require a later block.

The default expiry for interstellar payments is `2^128-1` (no effective expiry
within this version). A sender may explicitly choose a smaller height after seeing
the risk that remote inclusion becomes impossible. Expiry is a consensus-height
condition; elapsed wall time, transport timeout and receipts never cancel a spend.
A new conflicting signed transfer is an explicit owner action and remains subject
to branch selection; it is not a guaranteed refund.

## C05. Blocks and exact validation order

The header is exactly 268 bytes:

```
version:u16 = 1, suite:u16 = 1, chain_id:bytes[32], parent:bytes[32],
height:u128, timestamp:u64, base_target:u256, target:u256,
miner:bytes[32], transactions_root:bytes[32], state_root:bytes[32], nonce:u128
```

`block_id = D("HEADER", header)`, interpreted as an unsigned big-endian u256 for
proof of work. The complete block is
`header || transaction_count:u16 || (transaction_length:u32 || X)[transaction_count]`.
Count is 0..128, total block size <=262144 bytes. Transactions are strictly ordered
by transaction_id raw bytes; repeated IDs refuse. Each X must satisfy C04 bounds.
`transactions_root = H("TRANSACTIONS", transaction_count:u16 ||
(transaction_length:u32 || X)[transaction_count])`. There is no separate coinbase
transaction in this vector. Miner is a C02-valid public key.

Validation against an already fully validated parent is:

1. Check byte/count bounds, versions, pinned chain, canonical encoding and keys.
2. Require height=parent.height+1, `1 <= height <= 2^128-101`; obtain ancestor
   timestamps and base targets from that same branch, never another selected branch.
3. Verify C06 intrinsic timestamp and exact base_target/target, then proof of work
   `integer(block_id) <= target`. Check C07 local clock eligibility separately.
4. Check the exact transaction root, ordering, all transfers and disjoint inputs
   against the parent. Construct tentative resulting outputs and fees.
5. Add the exact C08 reward output, compute issued and C09 state root; compare the
   supplied root and verify monetary conservation.
6. Compute cumulative work and stage this complete branch state. Only then may C10
   and O02 atomically install it. An invalid tail changes no selected state.

Missing parents/bodies mean WAITING_FOR_HISTORY, not valid, spendable or permanently
invalid. A header-only chain is a synchronization hint, not ledger authority.
All checks apply equally to locally mined blocks, received blocks, replay and restore.

## C06. Difficulty, timestamps and survivor recovery

Constants: spacing=600 seconds; window=144 blocks; recovery_gap=14400 seconds;
future_allowance=7200 seconds; minimum target=1; maximum target=LIMIT.
For a parent at height p, let `M` be the timestamps of that parent and its preceding
ancestors, at most 11 values, including genesis if reached. Sort them; median is
element floor(len/2) with zero-based indexing. A child timestamp t must be strictly
greater than both parent.timestamp and this median. Timestamps represent integer
Unix seconds; overflow refuses. Miners normally use max(local_time,parent_time+1).

Compute base B for the child:

```
if p == 0: B = LIMIT
else if p % 144 != 0: B = parent.base_target
else:
    // exactly the preceding 144 mined blocks, heights p-143 through p
    elapsed = timestamp[p] - timestamp[p-143]
    expected = 143 * 600 = 85800
    bounded = min(343200, max(21450, elapsed))
    B = min(LIMIT, max(1, floor(parent.base_target * bounded / 85800)))
T = LIMIT if t - parent.timestamp >= 14400 else B
```

The header must carry exactly B and T. Products use at least 275 bits. Recovery
depends only on signed-by-work branch timestamps, never peer count, a node's claim
to be alone, a directory, emergency committee or locally selected configuration.
Recovery does **not** reset base difficulty. Its block contributes only its actual
low work; at the next window boundary its elapsed time participates normally.
A weak survivor may therefore mine one recovery block per gap until base difficulty
falls. Coinbase maturity can consequently take many days. Recovery is not a promise
of a payment within four hours or mining income at normal-network speed.

At LIMIT a uniformly distributed header hash succeeds with probability exactly
1/256 per distinct trial; failure after n independent trials has probability
`(255/256)^n`. A surviving miner with positive sustained computation and enough
clock/resource progress can eventually extend its local history under these
assumptions, without cooperation. This is probabilistic liveness, not a deterministic
bound or proof that an arbitrary broken machine can mine. The nonce is varied and
the timestamp/template can change; duplicate trials do not add probability.

The rule permits timestamp manipulation, waiting attacks and cheap private recovery
branches. Work selection prevents counting a recovery block as its inherited hard
base work, but does not prove security against those attacks. Timestamp consistency
does not prove elapsed physical time. The profile MUST NOT borrow Bitcoin confirmation
probabilities without a new analysis of this exact rule and network conditions.

## C07. Clock eligibility and delayed delivery

Intrinsic block validity never uses receipt time. A node with reliable integer local
Unix time now may activate a fully validated block only when
`timestamp <= min(2^64-1, now+7200)`. A future block is deferred and reevaluated as
the clock advances; it is not permanently invalid or silently discarded as old.
There is no maximum age for a delayed block or a historical signature valid under
its consensus suite. Every ancestor must be fully validated and eligible before
selection. If the local clock becomes untrusted or moves backward, preserve prior
state and suspend mining/new activation until it is reliable again. Do not roll a
chain backward solely because the wall clock moved. Cold replay validates intrinsic
rules, then marks a future selected tip CLOCK_WAIT before enabling mining/spending.
Clock eligibility is a local admission condition, so temporarily different selections
under clock skew are allowed. A first boot needs a usable clock, not an Earth server.

## C08. Issuance, reward identity and conservation

Era length L=200000 blocks. Set reserve R0=cap. For era e starting at block eL+1,
set `Be = 0 if Re=0; Re if Re=1; floor(Re/2) otherwise` and `R(e+1)=Re-Be`.
Let `q=Be div L`, `r=Be mod L`. At zero-based slot j=0..L-1 the subsidy is
`q+1 if j<r else q`. This distributes exactly Be without rounding away reserve.
For height h>=1, e=(h-1) div L and j=(h-1) mod L. Cumulative issuance is
`cap-Re + (j+1)*q + min(j+1,r)`. For h=0 it is 0. Once reserve reaches zero,
all subsequent subsidies are zero; implementations may terminate the recurrence
then rather than iterate to an enormous height.

The sole reward identifier is `H("REWARD", chain_id || parent_id || height:u128 ||
miner || transactions_root)`. Its output index is 0. Its amount is subsidy plus
all fees, its owner is miner and its maturity_height is h+100. If the amount is
zero, no reward output is inserted. Collisions with a retained outpoint refuse
the block; there is no overwrite. Reward identity deliberately excludes nonce and
state_root to avoid a circular commitment. Two otherwise matching competing headers
may share reward identity; they never create two rewards in one selected history.

Transfer output outpoints are `(transaction_id,index)`, with maturity_height=h.
At every accepted state:

```
sum(all UTXO amounts, including immature outputs) == cumulative issuance(height)
0 <= cumulative issuance(height) <= cap
```

Fees move value, not mint it. The sum is checked after every block and cold replay.
Only the selected history's rewards count. Adding balances or issuance across
partition branches is forbidden. Unselected outputs, pending transfers and transport
custody are separate observations, never additional assets. There are no burns,
exports, escrow issuers, regional mint rights or timeout refunds in this baseline.

## C09. Deterministic state commitment

Sort all UTXOs by their raw 34-byte outpoint. A record is
`outpoint || owner:bytes[32] || amount:u128 || maturity_height:u128` (98 bytes).
Its leaf is `H("UTXO-LEAF", record)`. Construct the binary tree with this exact rule:

```
tree([]) = H("UTXO-EMPTY", empty_bytes)
tree([record]) = H("UTXO-LEAF", record)
tree(records with n>1):
    k = largest power of 2 strictly less than n
    return H("UTXO-NODE", tree(records[0:k]) || tree(records[k:n]))
state_root = H("STATE", chain_id || issued:u128 || record_count:u128 || tree(records))
```

No duplicated last leaf or commutative sorting of child digests is allowed. Record
count is u128; each positive amount and cap constrain its actual possible size.
Generation may use incremental indexes, but their result must equal this definition.
A root, balance, inclusion path or peer snapshot alone cannot initialize validation
state. Version 1 defines full replay from genesis, not stateless snapshot adoption.
This complete ordered commitment prioritizes a simple interoperable definition;
efficient insertion and full-history execution require separate implementation work.

## C10. Work, ties and reorganization

For each valid mined block `w = floor(2^256 / (target+1))`. Genesis contributes 0.
Sum w along the branch in u384. With C05 height and target>=1 the sum is <2^383;
intermediate calculations must nevertheless be checked. Never use height, claimed
work, base_target, signatures, peer count, location or receipt count as work.

Among complete, eligible, validated histories select the greatest cumulative work.
For exactly equal work select the smallest tip block_id in raw lexicographic byte
order. This deliberately differs from first-seen tie behavior: independently
replaying the same complete eligible set produces the same selection. Mining a
smaller tie ID is possible and is part of the attack model. Arrival order confers
no finality. During missing evidence or skew, peers need not select the same tip.

There is no automatic maximum reorganization depth. Find the common ancestor,
fully validate the winning suffix against its own ancestry, compute new state, and
atomically replace selected tip/state under O02. Remove all losing suffix effects,
including issuance, fees, maturity and dependent wallet credits. A valid old branch
is not an authenticated finality incident. Its blocks may remain stored as history.
Reconsider detached transactions under O05; never merge two branch ledgers.
If sufficient history/resources are unavailable, report REORG_WAIT and preserve the
current state as stale; do not label the unvalidated winner accepted or create a
permanent local checkpoint. Resuming requires validation of the missing evidence.
An unvalidated claimed-work hint cannot force a miner to stop extending its best
fully validated eligible history while resources allow. Mining on that history may
continue during remote synchronization, with the competing-history uncertainty
shown. A local storage/clock failure is a separate reason to suspend mutation.

No number of confirmations is absolute finality. Eventual common selection requires
eventual delivery of sufficient valid history and comparable clock eligibility;
continued convergence/security also needs appropriate mining and network assumptions.
An indefinitely partitioned universe is allowed to have indefinitely divergent
views. A physically destroyed branch's unreplicated data cannot be reconstructed.

## C11. Invalid, unsupported and incomplete input

Malformed/oversized/noncanonical bytes, wrong chain/version/suite, invalid signature,
PoW/target/root/issuance, double spend, immature spend and expired spend are INVALID
for that exact object and context. An unknown parent is WAITING_FOR_HISTORY; a valid
future timestamp is CLOCK_WAIT; an exhausted local resource is RESOURCE_WAIT.
These conditions are not interchangeable. Retrying a transient condition must not
evade intrinsic validation. Transaction invalidity can be branch-dependent; a
conflict on one branch does not prove invalidity on every branch. Error handling
must preserve acknowledged durable data and leave monetary state unchanged.

Unknown versions/suites are UNSUPPORTED and cannot be mined, selected or credited
by a version-1 node. No fallback to an older verification algorithm is allowed.
Optional diagnostic text is local and nonnormative; canonical error categories
used by the operations API are fixed in O11.
