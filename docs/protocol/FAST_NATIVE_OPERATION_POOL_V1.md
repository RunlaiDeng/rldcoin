# Signed native operation custody and local pool mining

This component extends the private [payment session](FAST_PAYMENT_SESSION_V1.md)
and [data peer adapter](FAST_PEER_NETWORK_V1.md) for the separate no-value native
escrow candidate. It changes no accepted genesis, monetary opcode, proof-of-work,
issuance, owner signature, challenge window or miner maturity rule. Ordinary
Survivor-1 and old private state remain separate. It does not activate a monetary
network or authorize migration.

## Signed data and permanent retention

The key-free `pool_submit` execute action contains the exact current selected
`tip` and complete signed native `operation` as canonical lowercase hex. Normal
native decoding and every required owner/actor signature are checked before a
new caller intent. This checks syntax and authorization bytes, not current funds,
eligibility, guaranteed inclusion or a usable payment. Missing dependencies,
conflicting inputs and expired operations can still be retained signed data.

The ordinary caller journal persists the exact request, operation and original
local observation time, then a verified data-only reply. Pool replies have no
native/actor effect, review or newly created authorization. Successful retention
requires the actual selected context for that request; a peer cannot supply it.
Cold startup fully replays native history and validates all signed pool records,
their caller bindings, effects and resource bounds. Record hashes never supply a
ledger or replace signatures.

At most512 unique complete operation identities and2 MiB of their raw bytes are
retained within the existing32-MiB caller journal and65536-request bound. Duplicate
bytes reuse the first successful local queue time; every caller request still
consumes journal space. Completed/included entries remain retained. Capacity
refuses before a new intent; there is no pruning, expiry-based deletion, reset of
queue age, cancellation or release of an owner's separately reserved inputs.

Exact pending-request recovery takes the separately retained predecessor caller
head, request ID and action digest. It can finish retaining the existing signed
bytes after a durable intent, without loading a key or signing. A stale selection
is recorded as rejected and never becomes a successful pool entry. A completed
reply is returned unchanged. Wrong bindings, changed signatures and damaged
journals refuse without truncation. Process interruption recovery does not supply
independent latest-state, power-loss or copied-key custody qualification.

## Versioned operation carriage

Peer packet kind6 contains this exact big-endian frame:

```
version:u16=1 || suite:u16=1 || chain32 || operation_length:u16 || signed_operation
```

Operation length is1..4096; complete frame size is39..4134. Its operation uses the
existing native signature domains, and its chain must match both frame and peer
admission. Unsupported version/suite/kind, wrong chain, malformed length, trailing
bytes or invalid complete native signatures refuse. The normal packet signature,
fresh mutual TLS connection binding and durable data response are still required.
Existing kinds1..5 and all packet/box bounds are unchanged. Older peers explicitly
refuse unknown kind6; no downgrade, implicit compatibility or state conversion is
provided. The nested frame is RLD-FAST-NATIVE-OPERATION-CARRIAGE-1.

The [separately assembled public byte vector](fast-native-operation-carriage-v1-vectors.json)
uses labeled public no-value codec keys and a fictitious ordinary input. Its
valid signatures demonstrate byte interoperability, not funding or admission.
Receiving/acknowledging a packet does not queue a caller action or advance a
trusted caller head. `peer_pool_submit` is a separate explicit private command.

## Own-template mining and native admission

`mine_pool` takes current caller head, miner public key, canonical timestamp,
attempts1..4096, scan_limit1..128 and explicit refresh. It builds a template from
the actual current native ledger. A process-local rotating scan visits retained
entries, skips exact selected-history inclusions and greedily tries each remaining
operation together with those already selected. Every trial uses normal complete
native template validation. Missing inputs, conflicts, expiry, state/window or
other refusal is reported as deferred; the original signed entry is retained.
Unscanned entries are counted separately. An empty valid template remains possible.

A nonce job continues only for the exact selected tip, miner, timestamp and
already constructed operation set. New submissions do not silently restart its
search. Explicit refresh rebuilds it; selection/miner/time changes also rebuild.
Each search is bounded by the declared attempts. The manual exact-operation job
and pool job each retain at most one bounded template. Neither is serialized or
initialized from a peer's balance/cache. The scan cursor is a process-local
scheduling hint; restart can revisit earlier entries without resetting queue age.

A found block returns complete bytes, candidate identity and the canonical native
admission action digest. One process-local candidate is retained. Discovery does
not mutate the caller/native journal, spend an input or grant a reward.
`admit_candidate` requires its exact identity, unchanged current parent, current
caller head and a new request ID, then uses ordinary full native admission. A
replacement candidate, changed parent or restart requires rebuilding or using the
existing exact native-request recovery as appropriate. Loss of a response never
authorizes repeating a debit or skipping native checks.

Pool inclusion observations walk the actual selected ancestry of already fully
native-executed complete blocks, compare exact operation IDs and bytes, and check
the actual retained native prefix before and after. A reorganization can return
an included entry to RETAINED without changing its signature or original time.
INCLUDED is conditional selected-history inclusion, not independent freshness,
irrevocability or mature reward. Local queue age is not the original payer's F02
completion clock. Status reports next-block eligibility as unknown and never
infers maturity from a pool row.

## Private control commands

Every command supplies the exact latest session `head`:

- `submit_authorized(request_id, sign_request)` retains an existing complete
  `onchain_sign` result; it never loads a key or first-signs.
- `pool_status` observes retained operations and exact selected inclusions.
- `pool_operation(operation)` returns exact retained signed bytes.
- `mine_pool(miner, timestamp, attempts, scan_limit, refresh)` searches locally.
- `admit_candidate(request_id, candidate)` performs normal native execution.
- `peer_operation(operation, destination)` queues retained signed bytes as kind6.
- `peer_pool_submit(packet, request_id)` retains received kind6 after local checks.
- `peer_block(block, destination)` queues an exact retained native block as kind1;
  the destination still needs separate normal `peer_import`.

These controls do not automate external latest-head custody, owner approval or
incoming monetary execution. Native claim inputs still need the spending owner's
explicit prior authorization, operational liquidity and timely block inclusion.
Continuous challenge/fee monitoring, independent operators/custody, discovery and
multi-hop/physical routes, ordinary-hardware resource qualification, scalable
archival, mass exit and composed local-latency/daily100M G1-G11 remain required.
