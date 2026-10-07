# Fixed 3-of-4 hybrid quorum candidate

Core verification-only API in `crates/rld-core/src/hybrid_quorum.rs`. Caller supplies a separately authenticated four-member roster and per-member current trust/nonce/epoch observations. Exactly three sorted distinct member indexes independently verify Ed25519 AND ML-DSA-87 on one Finality intent; shared classical or PQ keys anywhere in the configured roster refuse. All four three-member subsets qualify locally, and an unavailable nonvoting fourth does not lower the threshold.

V10 six related tests passed48.787071/120. Add seventh case for every valid subset; final V11 all284 Core tests and six-package all-target strict passed55.979042/300 on Core182d728ef48. These are RAM-only fresh no-value signing fixtures, not independent operators. No old Native/Runtime/value stores reopened, network, funds or adoption. Earlier failures and qualifications remain historical.

Whole public quorum is bounded32KiB before parsing; canonical encoding retains all three complete individual envelopes. Decode never verifies signatures or grants finality. Bad decoded Ed/PQ proofs, duplicate/unknown members/fields, alternate JSON, missing votes, mixed intents, wrong configured identities, role/root/nonce/horizon/trust all refuse. No protocol aggregation or native quorum replacement.

Measured full public envelope29679B, three dual signatures14073B, four dual public keys10496B. Current single candidate TLS cap12288B does not fit; that cap and every existing native/ledger/network limit remain unchanged. Existing single-wire/Core277/TLS composition evidence does not qualify whole-quorum delivery. Next is explicitly bounded fragmentation/reassembly with same packet cap, complete root and negative cases. Full transaction/archive/resource/independent/PQ adoption/physical/whole-goal qualification remains open.

Controllers are immutable source-only audit snapshots. They name original paths and refuse existing outputs; do not run them against retained failed custody.
