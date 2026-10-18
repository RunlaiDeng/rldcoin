# Native fast escrow: no-value execution candidate V1

This is an incompatible, unadopted execution candidate, RLD-FAST-ESCROW-1.
It does not upgrade Survivor-1, change its85-byte genesis/ordinary block bytes,
create monetary value or migrate stores, keys or balances. Ordinary participation,
owner authorization, C08 issuance and asynchronous ordinary intent remain required.
The [fee certificate component](FAST_MINER_FEE_CLAIMS_V1.md) remains a supplied-
context verifier; this candidate derives its context from actual executed funding.
Retainer delegation/acknowledgment, durable owner reservations, ordinary fast
network operation and independent qualification are not supplied by this engine.

## Genesis, blocks and work

Integers are unsigned big-endian. A113-byte genesis is:

```
ASCII("RLDFAST1"):bytes[8]
version:u16=1 || suite:u16=1 || network_kind:u8=0
discriminator:bytes[32] != zero
start_time:u64 || initial_target:bytes[32] = 2^248-1
challenge_blocks:u64=2016 || challenge_seconds:u64=172800
max_active_channels:u32=1024 || max_slots_per_payer:u64=1000000
```

Unknown constants/versions, monetary network kind and old genesis formats refuse.
All hashes below use `SHA256(ASCII("RLD-FAST-ESCROW-1/") || label || 0x00 || bytes)`
unless explicitly reused as a primitive. Genesis ID uses label GENESIS. Blocks
retain the268-byte Survivor header layout, but version is2, suite1, chain is this
new genesis ID, body is ordered operations and state commits actual escrows too.
Block ID/work is SHA256 of the domain-separated HEADER digest of the268-byte
header. Nonce search must actually satisfy the full target. No header/old work
can authorize changed operation bytes. TRANSACTIONS hashes the full body.

Retain nominal600-second/144-block target rules, median-of-up-to11 timestamp,
14400-second maximum-target recovery, cumulative work and7200-second local future
eligibility from the shared native arithmetic. Recovery receives its actual work.
The maximal valid eligible work wins; equal work chooses the smaller tip ID.
All branches must be independently replayed from this pinned fresh genesis.
No baseline state, caller balance or decoded snapshot initializes execution.

Body is `count:u16 || (length:u32 || operation)*count`, at most128 operations,
each1..4096 bytes, complete block270..262144 bytes. Operation IDs use label OP
over complete operation bytes; strictly increasing IDs, no duplicates. Mining
templates sort by this ID; exact transactions/proofs are never rewritten.

All inputs and channel references come from the parent state. A block may touch
each existing channel at most once; funding cannot close in the same block.
Ordinary outputs/action change cannot fund another same-block action. Complete
fallible decoding, signatures, ownership, arithmetic, roots and resource checks
precede mutation. Invalid blocks leave the entire ledger unchanged.

## Operations and signatures

Every operation begins with its one-byte kind, included in its complete OP hash.
Kind0 is `0 || exact_C04_bytes`; all ordinary transfer rules/signature domains,
positive fee, expiry and deterministic C04 output IDs remain unchanged, under
this new chain ID. It cannot spend an output already locked by funding.

Kind1 opens a channel. Unsigned bytes U, excluding the kind, are:

```
version:u16=1 || suite:u16=1 || chain:bytes[32] || nonce:bytes[32]!=zero
owner_A:bytes[32] || owner_B:bytes[32]        // strict lexicographic order
principal_A:u128 || principal_B:u128        // sum P positive
N_A:u64 || f_A:u128 || N_B:u64 || f_B:u128
operation_fee_A:u128 || operation_fee_B:u128 // each positive
change_A:u128 || change_B:u128
expiry_height:u128
input_count_A:u16 || input_A:bytes[34]*count_A
input_count_B:u16 || input_B:bytes[34]*count_B
```

Each count is1..32, keys strictly ordered within each list, and lists disjoint.
Each owner's mature parent inputs must exactly equal that owner's principal,
N_i*f_i, explicit positive operation fee and signed change. Both N are1..1000000
and f positive. P+E_A+E_B and every checked sum are <=10^35 runlai. Owner keys
must be distinct valid strict Ed25519 points. Both owners sign
`tag(OPEN) || U`; append signature_A64 then signature_B64. Change returns only to
its actual funding owner. Initial payouts are the signed principal contributions.

Funding change must retain at least N_A+N_B+2 runlai per owner for prospective
one-runlai close/challenge/settlement operation costs. This is an actual free
output, not an unspent fee-escrow refund. A complete wallet must reserve the exit
budget and disclose inclusion/censorship/fee assumptions. The kernel cannot stop
an owner deliberately spending its own free exit budget; fee solvency and durable
wallet reservations remain full-product obligations. Claim submitters may fund
their own operation fees; escrow does not grant delegated ordinary spending.

Open ID is the full OP hash. Its change output indices are0 for A and1 for B;
zero change would be omitted, but the required exit budget makes both positive.
Locked P/E disappear from the ordinary UTXO set, and active channels cannot exceed
1024. There is no founder admission, fixed base signer or fee-retainer mining gate.

Kinds2(close),3(principal challenge),4(fee claim),5(settle) share unsigned action A:

```
version:u16=1 || suite:u16=1 || chain:bytes[32] || nonce:bytes[32]!=zero
open_operation_id:bytes[32] || actor:bytes[32]
fee:u128 || change:u128 || expiry_height:u128
input_count:u16 || input:bytes[34]*count
certificate_length:u16 || certificate:bytes[length]
```

Counts1..32, inputs strictly ordered. All mature inputs belong to actor and sum
exactly to fee+change; fee is positive. Append the actor's strict signature on
`tag(ACTION) || kind:u8 || A`. This signature authorizes only its exact operation.
Action change index0 is actor-owned when nonzero. A close requires actor to be a
channel owner and no previous close; certificate length0 selects the originally
jointly authorized funding allocation, otherwise252. Principal challenge and fee
claim require252. Settlement requires0. Any valid actor may pay to relay a proof
or finalize an eligible settlement; this grants no ownership of the locked money.

## Inclusion identity and fee context

The fee component's funding identity is `hash(FUNDING, chain ||
actual_funding_block_id || open_operation_id)`. Its ordered owners, miner key,
P/N/f are derived from actual funding execution. The miner is the exact funding
block's reward key, not a peer/caller-selected beneficiary. Changing that block,
miner, rates or either owner invalidates an old certificate signature domain.

There is no self-referential block hash in a post-state root. The funding block's
committed escrow record binds its OP ID, exact opening bytes, parent ID, height
and miner. After successful block verification, its actual block ID is retained
as derived inclusion metadata. This metadata is reconstructed only by complete
native header/body replay and is never accepted from a serialized escrow/hash.
It is excluded from that block's state-root encoding; all underlying committed
birth fields and the exact full block independently bind it. Future signed claims
bind the actual block ID through the context. Compact-snapshot initialization is
not supported. A sibling re-inclusion requires fresh fast authorizations.

Each state uses the component's exact252-byte certificate and228-byte context.
Additionally, q=k_A+k_B with checked u64 addition. Sequence0 must be the initial
funding split with zero counters. A normal off-chain payment must verify its full
previous/new state, exact one-step payer counter and principal delta; the engine
cannot infer such a history merely from an arbitrary jointly signed final split.
Both signatures nevertheless authorize the complete principal allocation and
the named fee ranges. Payment/invoice custody and real completion counting remain
separate from native admissibility of a jointly authorized settlement statement.

## Fixed closing windows, principal and fee rights

First close at h_c/t_c fixes deadline height h_c+2016 and time t_c+172800 with
checked arithmetic. Settlement requires both h>deadline_height and
timestamp>deadline_time. Claims/challenges require a later block and remain
eligible until both bounds have passed. No replacement state resets either bound.
Time bounds address rapid block production; they do not prove elapsed time under
deep reorg, dishonest clocks, stale funding or withheld history. Fast completion
still requires fresh monitoring and declared work/inclusion/clock assumptions.

Principal challenges require a strictly greater sequence and replace only its
jointly authorized payout statement. Same-sequence different payouts are refused
by this minimal executor; durable owner anti-rollback and complete conflicting-
state handling remain required before fast service. Fee claims, including a
lower-sequence certificate, update each independent fee floor by max and never
replace principal allocation. Close and principal challenge also incorporate
their own fee claims. All complete signatures/context checks run on every proof.

Settlement pays principal_A/B at output indices1/2, unused fee reserves back to
their respective original owners at3/4, and exact fee-floor total to the funding
miner at5. Zero amounts are omitted; all IDs use the settlement OP hash. Principal
and refund outputs mature at settlement height, usable only by a later block.
Miner fee output matures at settlement height+100. It is distinct from the
containing block's ordinary reward (issuance plus positive operation fees), which
also matures at h+100. Escrow is removed once; a second settlement cannot spend it.
At every block, ordinary UTXO amounts plus all active locked P/E equal exact C08
cumulative issuance. Claims are rights against locked money, not extra supply.

STATE commits chain, exact issued amount, the unchanged native UTXO tree primitive,
and ordered active-channel records. Each record is `OP_ID || opening_length:u32 ||
opening_bytes || birth_parent:bytes[32] || birth_height:u128 || birth_miner:bytes[32]
|| closing:u8 || [close_height:u128 || close_time:u64 || principal_certificate_length:u16
|| principal_certificate || fee_slots_A:u64 || fee_slots_B:u64 ||
proof_length_A:u16 || proof_A || proof_length_B:u16 || proof_B]`.
Bracketed fields exist only when closing; zero-length principal certificate means
initial split and zero-length fee proof means zero floor. Each proof is complete.
The ordered records are encoded as `count:u32 || (record_length:u32 || record)*count`.
STATE hashes `chain || issued:u128 || UTXO_count:u128 || UTXO_tree:bytes[32] ||
encoded_channel_records`. Every old fee proof is reauthenticated before numerical
reuse; no cached counter supplies value authority.

## Required scope beyond the engine

The separate read-only command is
`rld-fast-escrow-candidate GENESIS_FILE EXPECTED_CHAIN_HEX BLOCK_ARCHIVE`.
An archive contains only repeated `block_length:u32 || exact_complete_block`,
at most262144 blocks/256 MiB; genesis is independently pinned and at most113 bytes.
Inputs must be regular non-symlink files. The native process streams one bounded
block at a time, performs full execution with its actual observed local clock,
and emits native branch tip/root/work, issued/liquid/locked amounts and explicit
no-value/read-only/unqualified flags. Truncation, a wrong pin or excess bounds
refuse without creating node state. The tip refers only to the replayed branch;
the command does not compare other histories or establish independent freshness.
No serialized ledger, supplied coin table or private key input is accepted.

Only fresh no-value genesis and complete raw blocks may initialize this executor.
Intrinsic history validation and local future eligibility remain separate; mining
jobs obey the local clock, and a service must not select an ineligible tip.
Full branch replacement must replay the winning branch; old locks, claims,
refunds and rewards vanish together. Signatures cannot recreate orphaned funding.
Archives, process interruption, independent latest-state custody, native wallet
requests and ordinary network lifecycle need separate implementation/qualification.

An independent retainer's durable acknowledgment and timely proof inclusion are
still completion conditions. No acknowledgment format/service is activated here.
Do not accept fast invoices from an offline or unqualified retainer. No elapsed
deadline refunds a C04 transfer or provides a stellar round trip. Mass-exit capacity
must fit real canonical bytes/signature/operation capacity within both windows
under predeclared minimum honest inclusion/work assumptions. The1024 active bound
is a finite candidate cap, not evidence that all simultaneous exits are safe.
G1-G11, native lifetime/history, physical and independent gates remain open.
