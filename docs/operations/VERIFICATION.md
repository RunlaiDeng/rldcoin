# Verification and qualification boundaries

Use the reviewed source and pinned dependencies. Keep generated keys, node,
caller, signer, wallet, transport and TLS state private. Never reopen a stopped
failed fixture for replacement qualification. Changed Native source requires
fresh signed no-value genesis and currency; old value and custody do not migrate.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true cargo test --workspace --locked -- --test-threads=1
cargo run --locked -p rld-cli --bin rld-maintenance -- scan-documents --root .
cargo run --locked -p rld-cli --bin rld-maintenance -- check-rust-only --root .
mkdir -p tmp
cargo fmt --manifest-path tools/regional-ledger/Cargo.toml --check
cargo clippy --manifest-path tools/regional-ledger/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path tools/regional-ledger/Cargo.toml --locked --bin rld-regional-ledger-candidate
fixture_temp=$(mktemp -d "$PWD/tmp/rld-native.XXXXXXXX")
chmod 700 "$fixture_temp"
TMPDIR="$fixture_temp" \
RLD_EXPORT_ARCHIVE_CANDIDATE_CLI="$PWD/tools/regional-ledger/target/debug/rld-regional-ledger-candidate" \
CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
cargo test --manifest-path tools/regional-ledger/Cargo.toml --locked -- --test-threads=1
```

The source guard rejects distributed Python files, active Python launch entries,
Chinese source text and escaped Chinese code points. Private historical source
snapshots and stopped experiment stores remain outside the distributed source
set; preserving them does not enable Python in the current runtime. Former
standalone reference models and campaign drivers are retired, including their
Python tests. Rust regression tests exercise actual native implementations.

[Native source evidence](../../tools/source-evidence/README.md) documents source
snapshots, embedded implementation checks and Cargo SBOM. Record the actual
binary, source, controller, profile and independent input commitments privately.
Cache reuse grants no authorization or qualification. Report actual CI state;
pending, absent or unavailable runs cannot establish a pass.

[Regional Native](../../tools/regional-ledger/README.md) describes the Rust mesh,
BFT lifecycle and explicit unsupported companion profiles. Tests create fresh
public no-value fixtures. Finite local tests are separate from ordinary-payment
maturity/finality, complete sustained fault/load, independent custody/rollback,
cross-device power-loss, long history, complete cryptographic adoption and
physical-route qualification. All whitepaper gates and original thresholds stay
mandatory; no test count, transport receipt, file edit or source cleanup closes them.

[Hybrid public adapters](../../tools/fixtures/pq-hybrid-cross-implementation/README.md)
and [OpenSSL fixed-corpus tools](../../tools/fixtures/pq-tls-candidate/README.md)
remain verification-only. Both signature halves, exact configured identities,
ordered policy, independently retained whole commitments and all byte bounds
remain required. Subset vectors do not qualify full standards or production keys.

Historical source-bound failures, old receipts and interrupted artifacts remain
unchanged. A fresh passing regression cannot reconstruct a missing historical
terminal observation or replace a failed full profile.
