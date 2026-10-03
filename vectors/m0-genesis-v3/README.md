# V3 candidate birth fixture

This is a new public-only fixture, not an official or usable genesis. Its name
is `V3-DISPOSABLE-CLI-ONLY`; role keys derive from deliberately known test seeds
(32 repeated bytes: founder 1, validators 2..5, notaries 6..9). No private keys
are included. Such identities must never be used for a real network.

`manifest.json` is a complete signed V3 declaration. Its separate SHA-256
sidecar fixes the exact fixture bytes. The runtime genesis CLI reconstructs its
whole initial Ledger and verifies its genesis root. The Python verifier
independently derives the canonical signing/birth/constitution bytes and
Admission genesis, verifies the Ed25519 signature, and rejects eight mutations.
It does not independently replay the full Ledger or implement a node.

```sh
(cd vectors/m0-genesis-v3 && shasum -a 256 -c manifest.json.sha256)
python3 -B tools/m0-genesis-v3/verify_manifest.py vectors/m0-genesis-v3/manifest.json --exercise-negatives
cargo run --locked -p rld-cli --bin rld-genesis -- verify --manifest vectors/m0-genesis-v3/manifest.json
```

This fixture covers the V3 birth encoding only. It does not allocate upgrade
command tags, freeze an activation protocol or establish E-02 completion.
All earlier vector files retain their original bytes and meanings.
