# Earth genesis PoW context

This is the signed context for a fresh, empty Earth network. The required history bytes are exactly `[]`. No earlier ledger, PoW block, service reserve claim, wallet output, channel, export or import can be replayed into this chain. The new genesis manifest and its four validator keys are independently pinned by every joining node.

The context binds the manifest, Earth zone identity, empty initial ledger root, start time, initial mining target, this specification and the compiled implementation-source commitment. All four sorted genesis validator keys sign the same purpose-separated context statement. It assigns zero RLD to persons or services. The full 100-billion-RLD supply starts unissued. An operating permit, prior-chain key or status response cannot authorize the context.

This context creates only the empty height-0 anchor. It does **not** mine a preliminary block. The separately signed Earth value-rule adoption binds that exact anchor and authorizes the first monetary block at height 1. No old PoW runtime is deployed or released as a node for this context. A node must reject a nonempty anchor when it verifies the Earth value adoption.

The initial target is chosen from a published measurement and fixed by the signed statement. The admissible target ceiling is `00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`. A miner cannot select its own initial difficulty. The adopted value-block rules carry forward the target and adjust after every 144 blocks toward a 600-second interval, using the last-minus-first timestamps and a one-quarter to fourfold clamp. Signed source finality limits deep reorganization of finalized value; proof of work alone is probabilistic.

The exact coin types, subsidy schedule, maturity, transfers, channel escrow and export rules are specified by the separately signed unified-value rule hash. This context does not issue a reward, run a trial chain, or permit cross-region import on its own.
