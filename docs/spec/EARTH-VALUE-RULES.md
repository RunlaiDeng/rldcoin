# Earth source and destination value rules

Status: adopted rule text for the next direct Earth genesis. This file is committed in the exact implementation source set. The published source and its tests define the full serialization and state transition details; this document states the safety rules that operators must check before activation.

## Birth and supply

Earth starts at height 0 with empty block history, zero issued RLD, zero coins, zero channel escrow, zero reserved challenge fees, and zero exports. The four genesis validators sign the source PoW adoption and the direct value adoption. No balance, mining reward, service reserve, key authority or pending command is imported from a retired network. Source and destination chain IDs, genesis roots, rule hashes and the exact source commitment are pinned by the adopted nodes.

The first source value block is height 1. Blocks use SHA-256d proof of work, bind parent, chain, height, timestamp, target, miner, command root and resulting state root, and select the valid branch with greatest cumulative work subject to installed source-finality checkpoints. The target is fixed at genesis, bounded by the source limit, and retargeted every 144 blocks toward a 600-second interval. The initial subsidy is 250,000 RLD per block; each 200,000-block era releases half of the still unissued reserve, with exact integer accounting and a 100-billion-RLD total cap. A mined reward or fee output requires 100 additional source blocks before spending.

## Source value transitions

A valid signed transfer consumes mature, unspent source outputs and creates bounded recipient, change and miner-fee outputs atomically. Channel opening consumes a mature source coin into one escrow, and a separate signed reservation locks a mature coin for a possible challenge fee. A receiver checks the funded channel and its reservation before accepting a payment. Each payment state carries the exact channel and increasing sequence and requires both parties' signatures; a receipt is bound to that state and invoice. Persistent payer, receiver and watchtower records must survive restart and exact retries.

A unilateral close exposes its submitted state for 2,016 blocks. During that period a higher sequence with both signatures can replace a stale state. An on-chain challenge consumes its bound reserved fee atomically. After the deadline, settlement conserves all value and returns an unused reservation to its owner. A failed command cannot partially change balances, escrow, exports or the state root.

An export permanently removes the amount from source spendable supply and commits an ordered proof in the source state. Delivery timeout alone never refunds an export, because a destination may already have imported it. The source only installs a unanimous checkpoint certificate for a selected block with at least 12 confirmations. Once installed, a conforming source node rejects every branch that does not descend from the highest finalized checkpoint, regardless of its proof-of-work total.

## Destination value transitions

The destination genesis binds the exact Earth source identity, source adoption, four finality keys, source policy, destination signer and zero native issuance. An ordinary unfinalized import has no authority. An accepted finalized import must include the exact export bundle, source membership proof and four-signature checkpoint certificate covering that export on the selected source ancestry. Import IDs are unique; retries do not mint again. An imported coin is not spendable until six destination blocks include its import. Destination transfers require valid signatures and conserve imported value, change and fees. Destination blocks have their own SHA-256d ancestry, state roots, replay and cumulative-work selection.

The source certificate prevents a normal competing source branch from erasing an imported export. It does not stop key theft, a conflicting certificate signed by the same four keys, a nonconforming node or a destination reorganization. Such a contradiction stops value service and requires a published incident decision; software must not silently claw back funds already spent at the destination. All four current keys have one owner, so this is an operator trust boundary rather than independent finality.

## Verification boundary

Node startup and replay reject mismatched IDs, signatures, roots, source commitments, noncanonical inputs, corrupt durable records and unsupported histories. Public status is operator telemetry. Independent operation, outside review, production fault exercises and eventual channel settlement are separate release evidence, not consequences of this rule hash alone.
