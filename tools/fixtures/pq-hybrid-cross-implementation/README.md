# Hybrid authorization and finite renewal candidates

These standalone Rust tools link the actual `rld-core` verification-only candidate.
They never adopt a ledger suite or install finality, signer locks or consumed IDs.
The caller supplies trusted policy, observations and latest heads independently.

Use Rust 1.98.0 and the checked-in standalone lock:

```sh
cargo metadata --locked --offline --no-deps --manifest-path tools/fixtures/pq-hybrid-cross-implementation/Cargo.toml
cargo build --locked --offline --manifest-path tools/fixtures/pq-hybrid-cross-implementation/Cargo.toml
```

An unavailable offline dependency is a real prerequisite, never a test PASS.
Each program's source explains its bounded positional file inputs; input files
must be private regular files, not symlinks. `rld-hybrid-*-core-candidate` verifies;
`rld-hybrid-*-public-fixture-candidate` creates only fresh no-value public examples
from RAM keys. Never use an old failed custody directory or fixture signing keys.

`public-examples/ORIGINS.json` records four complete historical public policy/wire
examples and original SHA-256 values. They contain no private keys. Quorum examples
originated on Core182 d728ef48; renewal examples on Core182 ee1f46b6. Example policy
is not independent trust, and retained examples do not transfer old qualification
to changed code. The real full regression remains in `crates/rld-core`.

The ML-DSA-87 and ML-KEM-768 KAT comparators use fixed fips204 0.4.6 and fips203
0.4.3. The corresponding OpenSSL comparators live in
[the C fixture tools](../pq-tls-candidate/README.md). These are known-answer
comparators, not production entropy or real-key services. See
[verification and remaining gates](../../../docs/operations/VERIFICATION.md).

`rld-hybrid-renewal-archive-core-candidate` takes an independently trusted initial
anchor, separate caller latest-head/ordered observations, and owned private archive
directory. It uses directory-FD-relative no-follow leaf reads, at most64 entries,
32768 bytes per entry and2097152 bytes total. Valid output is only a candidate
anchor; it never installs state. Missing/malformed/path/size inputs exit2; actual
Core refusal exits1. The new public-fixture generator takes fresh anchor path,
fresh caller metadata path, one empty owned private output directory and count1–64.
All signing keys remain RAM-only; outputs are public test material.

The current two-entry cold scope passed after a retained fixture-width failure,
within the original120-second budget. It does not qualify a64-entry valid archive,
independent witness/custody, long horizons or production adoption.
