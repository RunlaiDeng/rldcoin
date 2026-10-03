# Earth direct value adoption

Four genesis validators authorize the Earth value rules directly from a new, empty height-zero genesis. There is no preceding reward block, imported trial-chain balance, predecessor commit, channel, export or destination import. The first source value block is height 1.

The statement is canonical compact JSON of `EarthSuccessorAdoptionStatement` in declared field order, prefixed by `RLD-EARTH-SUCCESSOR-ADOPTION\0`. Its ID is SHA-256 of those bytes. Every validator in the genesis PoW adoption signs the same statement with Ed25519. Four sorted signatures and an exact locally accepted statement ID are required.

The statement binds the fresh genesis manifest pin, signed PoW rule adoption ID, empty anchor, chain ID, Earth value-rule hash, exact implementation-source commitment and transition-preview ID. The preview commits zero cumulative work, zero issuance and zero personal allocation. Both the PoW adoption and preview are reverified before accepting signatures. Nodes reject a mined predecessor block, nonempty history or another source commitment.

Only Earth value blocks may extend the adopted anchor. An adoption signature does not prove independent operation, wallet readiness, receipt latency, watchtower recovery or outside security review; those need separate evidence.
