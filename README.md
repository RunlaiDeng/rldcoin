# RLDCOIN

RLDCOIN develops a peer-to-peer payment protocol for regions separated by long
communication delays. It combines local ledger validation and payment autonomy
with asynchronous, authenticated relay of cross-region evidence.

[Website](https://rldcoin.com) · [Whitepaper](https://rldcoin.com/whitepaper) ·
[Protocol specifications](docs/spec/README.md)

This is a development source tree containing no-value candidates. It does not
constitute a qualified mainnet or an operational interstellar payment service.

## Source layout

- `crates/`: consensus-domain types, authorization, issuance, local payments,
  cross-region value rules and command-line utilities.
- `tools/regional-ledger/`: a separately built regional ledger and ground node
  runtime, including persistent history, wallet and relay interfaces.
- `spec/`, `docs/spec/`, `formal/` and `vectors/`: wire contracts, specifications,
  models and public verification vectors.
- `tools/`: reference verifiers and explicitly scoped development fixtures.

The [implementation acceptance contract](docs/WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)
and [implementation boundaries](docs/PLAN_STATUS.md) describe the obligations
that remain before adoption. The whitepaper and its
[freeze receipt](docs/WHITEPAPER_FREEZE_RECEIPT.json) are normative references.

## Building

The repository pins Rust **1.98.0** in `rust-toolchain.toml`. Install that toolchain
with Cargo, rustfmt and Clippy. The ground Python runtime also needs Python 3.12
or later and the dependencies in
[tools/interstellar-mesh-requirements.txt](tools/interstellar-mesh-requirements.txt).

From the repository root:

```sh
cargo build --workspace --locked
cargo build --manifest-path tools/regional-ledger/Cargo.toml --bins --locked
```

Add `--offline` when the selected target's pinned dependencies are already cached.
The regional package is separate from the root workspace. Build outputs use each
package's default `target` directory unless explicitly overridden.

## Running

The root `rld` executable provides offline key and signing utilities. To inspect
its interface without creating or signing anything:

```sh
./target/debug/rld --help
./tools/regional-ledger/target/debug/rld-regional-ledger-candidate --help
```

A regional node requires an explicitly initialized, authenticated fixture ledger,
its currency and authority, and separately configured neighbor identities. See
[regional node setup and commands](tools/regional-ledger/README.md). Ordinary
startup includes bounded relay; a relay receipt is separate from ledger import,
maturity and spendability. Use fresh private fixture directories and public test
keys only; never convert an old test ledger into a monetary network.

## Testing

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
mkdir -p tmp
cargo test --manifest-path tools/regional-ledger/Cargo.toml --locked
python3 -B -m unittest discover -s tools/implementation-source -v
python3 -B -m unittest discover -s tools -p test_permanent_import_index_candidate.py -v
```

The [verification guide](docs/operations/VERIFICATION.md) covers reference tools,
public vectors and qualification boundaries. Match each check to its actual
source and declared scope; a component result does not qualify the complete
protocol, independent custody or physical routes.

## Contributing

Use [issues](https://github.com/RunlaiDeng/rldcoin/issues) for reproducible,
non-sensitive bugs and proposals, and submit focused pull requests with the
problem, resulting behavior and relevant verification. Review existing interfaces
and preserve wire compatibility, safety checks and normative acceptance limits.
Keep credentials, generated keys, private ledger state, build outputs and
internal experiment journals out of public changes.

Security-sensitive findings follow [SECURITY.md](SECURITY.md). A private reporting
channel must be established with the maintainer before sending sensitive details;
do not disclose them in public issues.

## License

RLDCOIN is released under the [Apache License 2.0](LICENSE).
