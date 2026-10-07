# Hybrid authorization and renewal reference fixtures

This source-only bundle records actual bounded controllers and all failures. It includes no secret keys, private inventories, ledgers, binaries or caches. Dated controllers are exact audit sources, **not rerun launchers**: their unique outputs and original budgets must remain preserved. Reproduce the public Core tests directly in a fresh supported workspace; no original local private fixture is needed.

```sh
cargo test -p rld-core --lib --locked --offline --target-dir target/value-tests-rust198-opt1 --config profile.test.opt-level=1 --config profile.test.debug-assertions=true --config profile.test.overflow-checks=true hybrid_authorization::tests:: -- --test-threads=1
```

Use Rust1.98.0. The public vectors and their pinned provenance are in `vectors/pq-hybrid-authorization-v1/`. Genuine renewal keys are freshly generated only in test memory and never written or printed. Public signing previews and decoding grant no authority.

Provider V1 PASS0.180233; policy V2 PASS0.102904, cumulative0.283137 of original60; independent Rust/OpenSSL interoperability V3 PASS45.073423/120; exact NIST acquisition V4 PASS17.243802/30 (not execution); external pure ML-DSA-87 SigVer group5 cases61..75 V5 PASS2.317741/120, all15 in both implementations. This is not complete FIPS204, CAVP/FIPS140 validation or external review.

Core V6 strict FAIL14.821360 retained (three needless test allocations); direct correction, no warning exemptions. V7 six related tests PASS55.527748/120. V8 full275 and workspace strict PASS91.651247/300 at181source518c6e77; V9 actual bounded wire adds two tests/27 malformed cases, full277 and workspace strict PASS84.375414/300 at181source4070549a. No ignored/filtered tests in full scopes. Final public qualification is `docs/operations/evidence/core-hybrid-bounded-reference-v2-qualified-profile-20261007.json`; actual source, immutable test binary, compiler manifest and controller are separately bound.

Both Ed25519 and ML-DSA-87 must verify identical canonical bytes. Caller-authenticated roots, purpose, expected nonce and finite logical-epoch horizon are required. Revoked/broken/unavailable originals stop acceptance. Joint renewal requires all four old/new signatures, consecutive crypto/key epochs, the exact predecessor and retained caller-lock/consumed-export commitments. Returning a new candidate anchor does not install ledger state or prove durable custody. Replay and a competing successor refuse against the already advanced anchor; independent conflict resolution remains open.

The ledger/era suite gate still refuses hybrid declarations. Candidate Core code does not qualify actual PQ transactions, consensus, quorum/archive wire sizes, adopted genesis, independent reviewers/custody, KEM transport or a physical stellar link. Old legacy-value67/Core267/regionalhead-v16 evidence stays bound to its historical sources; no unchanged long tests were rerun. Frozen paper/PDF/site unchanged.
