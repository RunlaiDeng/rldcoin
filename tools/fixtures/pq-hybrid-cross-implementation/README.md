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
within the original120-second budget. A separate source-bound scope then verified64 complete real renewals (1581531B),
with the caller retaining the latest head; a63-entry valid prefix refused. Actual
cold read took0.309571 seconds with5193728B process peakRSS on the measured host.
A retained first byte-size prediction failure is not a passing scope. This remains
a finite same-controller observation, not independent witness/custody, long horizons
or production adoption.

`rld-hybrid-archive-manifest-core-candidate` takes a separate caller-authenticated
policy/current observation, canonical binary manifest and detached dual-signed
public envelope. Bounds are8192/4389/12288 bytes respectively; private owned
regular no-follow files are required. Dedicated ARCHIVE_MANIFEST purpose binds
all ordered sizes/roots. Exit0 verifies only the manifest authorization; it does
not verify entry signatures, install state or consume a nonce. Core refusal is1,
file/input unavailability is2. Its RAM-only public generator takes manifest input
and two fresh public output paths; generated policy is test data, never trust.

Core1835d1691dc full293 and strict passed. Actual offline V33 retained a wrong
expected return code for a truncated manifest (Core refused1, fixture expected2).
V34 corrected only that expectation, reused17 prior passing cases/strict/build
and completed remaining guards in the original120-second cumulative27.532662.
Epoch2 signatures accepted at independent current7/8 and refused at9; wrong
scope, nonce, unavailable/revoked/broken authority and either bad half refused.
These observations grant no physical horizon or authenticated ledger adoption.

The renewal-archive reader also accepts the explicit optional suffix
`--authorized-manifest <separate-policy> <manifest> <detached-envelope>`.
In this mode it verifies manifest dual authorization, exact currency/region and
entry count, then hashes each ordered complete entry as read under the same owned
directory descriptor, and finally runs actual Core four-signature renewal checks
against the separate initial anchor and latest observations. It never learns
those heads/locks from the manifest. Ordinary mode retains its original output.
A valid manifest signature cannot rehabilitate an invalid inner renewal signature.

The current combined V36 scope passed in3.152514 seconds, original120 cumulative
3.912544 after retained V35 syntax failure before signing/transport calls. All64
real entries reached era/key_epoch/nonce65 and unchanged caller/consumed roots;
a complete freshly manifest-authorized archive with one bad inner PQ half refused.
No nonce/state installation, TLS, Native or old failed custody was involved.
