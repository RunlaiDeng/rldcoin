# Rldcoin

A clean Rust implementation of **Rldcoin: Interstellar Peer-to-Peer Payments**.
The canonical mechanism paper is [spec/WHITEPAPER.md](spec/WHITEPAPER.md), bound by
[its publication receipt](spec/WHITEPAPER_RELEASE.json). The paper's SHA-256 is
`252a280044856a599c4a7fb1e7913d08776aa79f172db64275339be760662639`.

RLD is the only native payment and fee currency. The lifetime issuance budget is
**21,000,000 RLD**, with **10^24 atomic units per RLD** and **zero initial allocation**.
Mining and placement use public Argon2id work. A relay acknowledgment, coupon,
proof, configuration signature or solved hash does not itself issue money.

This repository was rebuilt from an empty worktree. The former implementation
and private state were moved to the owner's macOS Trash. Existing remote Git
history is preserved; no legacy ledger or key migration is supported.

## Build

Install Rust 1.98.0 and the official RISC Zero Rust guest toolchain 1.88.0 with
`rzup install rust 1.88.0`. The monetary proof profile pins RISC Zero 3.0.6.
Building the local prover also requires CMake and platform C++ tools. On macOS,
install Xcode and its Metal toolchain. The build helper explicitly selects
Metal 3.1 for the pinned vendor kernels when the installed compiler defaults to
Metal 4; it does not modify vendor sources or skip kernels.

```sh
# macOS, including both real guest programs and local succinct prover
./tools/build-macos.sh

# Linux with its standard C++ build toolchain
cargo build --release --workspace --locked

# Command descriptions; these do not start a network
./target/release/rld --help
./target/release/rld-prover profile
```

`rld-prover profile` prints the actual compiled native/controller image IDs and
verifier commitments. A currency descriptor must use this exact profile. Native
and controller receipts are real succinct receipts; development/fake receipts
and unresolved assumptions are refused. Changing the guest relation changes its
image ID and requires a distinct explicitly approved currency descriptor.

## Components

- `crates/protocol`: canonical CBOR, monetary types, ordered-map proofs,
  exact issuance work, native transitions, independent terminal controllers,
  authentication, succession and recursive verification relations.
- `crates/node`: durable replay, encrypted local signing custody, PBFT,
  signed and pinned-TLS contact carriage, bounded fragments, offline bundles,
  public signed-operation API, persistent native-history index and independently
  scheduled bounded proving lanes.
- `crates/cli`: wallet signatures and balances, ordinary CPU mining, placement
  work, payment/service/family drafts, evidence extraction, operator tools,
  cancellation and disconnected carriage.
- `methods`: actual RISC Zero native and controller guest programs.
- `crates/prover`: local proof generation and final independent verification
  before releasing the receipt.

See [operator instructions](docs/OPERATIONS.md),
[implementation boundaries](docs/IMPLEMENTATION.md) and the
[initial build record](docs/BUILD.json). Later source-bound compile receipts
live in `docs/builds/`; they do not retroactively qualify earlier source.

## Current boundary

This is an experimental implementation, not a launched monetary network. No
network keys or genesis were generated during this rebuild. No old balances or
keys are imported. Compilation is not runtime verification or a security audit.
The owner requested source review and compilation without a new local test
campaign. Sustained capacity, complete large-history storage, independent key
custody, physical stellar links and mainnet operation remain unqualified.
