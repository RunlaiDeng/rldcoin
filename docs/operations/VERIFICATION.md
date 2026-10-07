# Stable verification and qualification boundaries

Use a fresh checkout of the reviewed source. Keep generated keys, ledger/config,
caller/owner/voter/witness state, logs and build outputs outside the public tree.
Never reuse failed signed fixtures. Offline checks require the existing pinned
public dependencies; missing dependencies remain unavailable.

## Source, vectors and CI

```sh
python3 -B -m unittest discover -s tools/source-evidence -v
python3 -B -m unittest discover -s tools/implementation-source -v
python3 -B -m unittest discover -s tools -p test_pq_public_carriage_candidate.py -v
python3 -B -m unittest discover -s tools -p test_pq_public_archive_candidate.py -v
cargo metadata --locked --offline --no-deps
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test -p rld-core --lib --locked --offline
```

`tools/implementation-source/verify.py` recomputes Core's complete build-bound
inventory from Cargo manifests/lock/toolchain, crates, vectors, spec and docs/spec.
Compare an independently selected commitment and actual binary's embedded
manifest. A matching digest does not attest binary honesty or authorize adoption.
CI uses fixed Rust1.98.0/OS/arch/job/profile/lock and complete source keys;
cache reuse is acceleration only. Record actual CI state: absent runs are not PASS.

## Minimum counterexamples and regression

Core's real `hybrid_authorization` tests exercise dual-signature policy, four-signature
Old/New renewal, strict complete wire decoding, bounded ordered renewal archive,
stale retained latest-head refusal and unchanged initial anchors. `hybrid_quorum`
exercises exact configured three-of-four, distinct key halves and common intent.
They use RAM-only no-value signing keys. Filtered tests are related regressions;
full Core testing is a separate scope. These APIs are verification-only candidates.

[Hybrid Rust adapters and public examples](../../tools/fixtures/pq-hybrid-cross-implementation/README.md)
and [OpenSSL KAT/TLS tools](../../tools/fixtures/pq-tls-candidate/README.md)
retain complete stable source. The one-case ML-KEM runner accepts pinned cached
NIST public test sources and two separately selected actual binary hashes. It
retains failures locally and never grants production algorithm/adoption authority.
ML-DSA public vectors remain in `vectors/pq-hybrid-authorization-v1/`.

[Regional Native](../../tools/regional-ledger/README.md) retains its actual source,
lock, codec/history/authorization tests and CLI. Create `tmp` before its existing
unit fixture checks. The portable `regional_paged_fault_*` driver/prepare/terminal
models can be run by explicit test filename; they do not construct Native/Runtime,
sign, open sockets or grant real fault qualification. Checkout-root substitutions
are a new controller source: old full profiles stay bound to their original hashes.
Historical `regional_channel_missing_leader_drill.py` requires exact retained local
reports and source/binary pins; it is not a portable CI or recovery entry. Missing
prerequisites must refuse. Do not run it on old custody to verify tree cleanup.

## Evidence, deadlines and remaining gates

Run the smallest falsifiable reproducer, then related regressions, then a justified
full scope after a relevant source/controller/input/environment change. Stop at the
original deadline/first guard; no warning exemptions or raised maturity/quorum/caps.
Retain actual source, binary, controller, environment, complete outcome and failures
separately. Public tree simplification leaves all immutable old evidence, including
failed scopes, locally recoverable; absence of a public log is not qualification.

[Current status](../PLAN_STATUS.md), [master plan](../RLDCOIN_MASTER_PLAN.md) and
[clause mapping](../WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md) preserve all frozen
S/R/I/A–G/N/P obligations. Independent clients/review/custody, long history and
resource/funding models, arbitrary-region value composition, authenticated PQ/epoch
adoption, physical routes and fresh zero-allocation genesis remain separate gates.

## Finite multi-object archive carriage

`tools/pq_public_archive_candidate.py` keeps the original12288-byte packet and
32768-byte object bounds. A canonical ordered manifest binds at most64 distinct
complete entry SHA512 values/sizes, at most2097152 bytes aggregate; the receiver
retains the expected manifest SHA512 independently. Missing objects/pieces remain
unavailable; duplicate, mixed, altered or changed-root inventories refuse. This
pure byte layer never authenticates caller policy or installs a ledger anchor.

A finite64-entry signed example was reassembled from reversed manifest/pieces and
read by the actual unchanged Core cold adapter. A complete byte-valid altered-PQ
archive still failed actual Core validation. This is same-host in-memory packet
carriage plus complete cold files, not actual network/TLS relay, independent
custody, asynchronous physical-route qualification or adopted monetary rules.
