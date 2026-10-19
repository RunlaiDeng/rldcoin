# Native ordinary transfer authorization

This is a private no-value session control for existing kind0 ordinary transfers
in RLD-FAST-ESCROW-1. It changes no accepted genesis, transaction, signature,
issuance, work or maturity rule. No monetary adoption or state migration follows.

`transfer_prepare` contains selected `tip` and typed `plan`: owner32, ordered
inputs (1..32 canonical34-byte references), ordered outputs (1..8 objects with
owner32 and positive integer amount), positive fee, expiry height and evaluation
timestamp. IDs use lowercase hex; integers use canonical decimal strings. Unknown
fields refuse. Outputs are exact explicit destinations and amounts, including any
owner change; no route/retainer can replace them or silently calculate new change.

The native unsigned bytes retain C04: version1:u16, chain32, owner32, input_count:u16,
ordered references, output_count:u16, ordered(owner32, amount:u128) outputs,
fee:u128 and expiry:u128. Review uses the actual selected fast native ledger,
existing strict decoder and full nonmutating shared ordinary execution, checking
ownership, input maturity, sum, expiry and resource/timestamp rules. A supplied
balance or decoded ordinary ledger never supplies funding authority.

The review binds SHA256(`ASCII("RLD-FAST-ESCROW-1/TRANSFER-REVIEW") || 0x00 ||
selected_tip32 || evaluation_timestamp:u64 || 0x00 || unsigned_C04`). The leading
0x00 is the existing operation kind. Review reports exact outputs, input value,
fee and C04 transaction ID. Output references use C04 TXID, distinct from the
pool's hash of the complete signed operation.

Only `onchain_sign`, with exact persisted preparation/request/review/selected tip,
approved=true and the actual owner's O13 encrypted key, may sign. It uses the
unchanged `RLD-SURVIVOR-1/TRANSFER` domain over unsigned C04 bytes and retains the
complete `kind0 || C04 || signature64` in the caller reply before release. Secure
native password input, independent latest caller heads and full cold replay remain
mandatory. Existing escrow actions and their serialized bytes remain unchanged.

A successful preparation reserves all exact inputs against both transfer and
escrow preparations, including after a failed approval, restart, timeout or reorg.
The same exact intent can be re-reviewed at a new evaluation timestamp; changed
destinations, values, fee or expiry cannot reuse its reservation. No timeout or
receipt releases a signed or prepared input. This is deliberately bounded by the
existing caller capacity, not a claim of scalable reservation garbage collection.

Recovery requires the exact predecessor caller head, request ID and action digest.
It can return an already retained signature without loading a key; an interrupted
unsigned request cannot first-sign during recovery. Every retained preparation
and signature is revalidated against its actual historical native selection.
Wrong bindings, altered bytes/signatures, stale/orphan backing and insufficient or
immature inputs refuse. Normal pool retention, peer carriage, own-template mining
and full native admission remain separate from signing and from spendability.

A retainer may use a genuine received ordinary output to pay its own claim's
ordinary operation fee only after explicit authorization by that output's owner.
A custody delegation alone grants no such spending rights. Funding a retainer
is a separately owner-authorized ordinary transfer. Protocol payment fees retain
their exact miner allocation, and ordinary CPU mining remains permissionless
without a retainer account, payment or prior balance. This interface supplies no
guarantee that a recipient will preserve or spend its funds on future claims.
This funding path does not itself provide continuous monitoring, timely inclusion, consumer consent,
independent custody/security, joint escrow opening, scalable archival/mass exit,
physical routes or composed local-latency/daily100M G1-G11 qualification.
