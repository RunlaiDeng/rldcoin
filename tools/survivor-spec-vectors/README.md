# Survivor-1 public specification vectors

This bounded Rust tool generates and checks public **NO-VALUE** examples for the
[candidate contract](../../docs/protocol/survivor-v1/README.md). It is not a node,
wallet, transport service, independent security review or adopted ledger profile.
It never reads production keys or starts a network. Its deterministic signing
inputs are the publicly disclosed RFC8032 test inputs; they cannot secure assets.

```
cargo run --locked --manifest-path tools/survivor-spec-vectors/Cargo.toml -- check docs/protocol/survivor-v1/vectors.json
cargo test --locked --manifest-path tools/survivor-spec-vectors/Cargo.toml
```

The signature interoperability test requires an `openssl` executable with Ed25519
support. It checks a valid and an altered public message using a second crypto
implementation; it is not an independent complete consensus implementation.

`generate PATH` writes examples only to a new file; `check PATH` reconstructs the
examples and compares the entire JSON value. The oracle implements the specified
binary/hash/arithmetic examples and a finite chain parser/replayer. Tests exercise
rejection and boundary cases. It does not implement storage, user interfaces,
encrypted backups, physical adapters or all acceptance campaigns. Two code paths
in this tool are not two independent implementations.
