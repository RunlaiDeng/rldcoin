# Regional native ground candidate

This separate Rust crate implements bounded native regional ledger, owner,
signer, BFT, evidence, history, wallet and contact interfaces. It is a no-value
ground candidate. All current whitepaper acceptance gates remain mandatory;
finite models and local tests grant no monetary adoption or independent qualification.

Build with `cargo build --locked --manifest-path tools/regional-ledger/Cargo.toml`.
Use `rld-regional-ledger-candidate --help` and each subcommand's `--help` for exact
arguments. The global ledger directory, authority and currency are explicit.
Default ordinary startup and `contact-node` run the Rust contact lifecycle in
process; no interpreter, library bridge subprocess or runtime fallback is used.

## Native contact lifecycle

`contact-mesh init --state NEW_DIRECTORY --network HEX --region HEX --label LABEL`
creates a fresh private transport identity. `inspect`, `tls-identity`, `enqueue`
and `tick` use an explicit `--config` file. Enqueue also requires the exact native
frame `--file` and configured destination `--destination`. Transport status and
custody receipts do not grant native ledger acceptance or spendability.

The config uses `RLD-CONTACT-MESH-V3`, `network`, `state` and explicit `contacts`.
The Rust private state is `RLD-RUST-CONTACT-RUNTIME-V1` in
`native-mesh-state.json`. Legacy `mesh-state.json` refuses unchanged. Automatic
ordinary startup creates `transport/native-config.json` only in a fresh scope;
a retained legacy config refuses. Old failed stores must not be converted.

Contacts pin independent peer identities, literal endpoints and TLS certificate
SHA-256; advertisements never supply endpoint or trust authority. TLS 1.3 is
required for the TCP adapter; plaintext mode currently refuses. The fresh signed
challenge, request, exact exchange, both nonces and signed response remain bound.
Outgoing carriage rotates durably before a connection. Mesh locks are released
before socket waits. A verified response requires local durable custody.

Native directory spools support the plain and bounded zlib adapter. Every
received complete envelope authenticates before deduplication; original retained
bytes remain unchanged. Duplicate custody still synchronizes retained storage
before acknowledgment. Complete native ledger evidence is verified independently
of mesh authentication. Routing discovers candidate neighbors asynchronously and
does not create physical contact, instantaneous global state or finality authority.

Bounds remain 16 contacts, 64 advertised nodes, 256 active messages, four transits
and sixteen receipts per exchange, 20 MiB exchange, original native frame/payload
bounds, 4,096 archive files and 256 MiB archive storage. Completion-only archival
starts at 32 and handles at most sixteen entries; pending unreceipted evidence
remains active. The native active shared-frame codec and exact immutable transit
witness retain their own unchanged bounds and full authentication requirements.

## BFT companion

`contact-node --bft-config FILE` accepts ordinary
`RLD-REGIONAL-BFT-NODE-V1` and origin `RLD-REGIONAL-BFT-ORIGIN-NODE-V8` configs.
Validator key, ordered admitted validator identities, separate native signer
journal, caller head, retained archive and native ledger binding are explicit.
The runtime retains pending consent before signing, publishes the exact native
response/head before release and recovers pending work without first-signing.
An optional independently retained `startup_native_history_head` is checked
against full native replay before signing or recovery.

Every complete received envelope authenticates and synchronizes certified
dependencies before body deduplication. Native policy selects proposals,
prepare/commit/timeout actions and accepts complete certificates. Queued owner
submissions are typed native inputs; enqueue alone never debits. Three ordered
configured votes out of four remain mandatory where the signed Admission rules
require BFT; legacy thresholds are never lowered.

Each broadcast retains up to three current consensus messages and a maximum
of four envelopes overall. One local owner submission that lacks an exact
durable originated packet for any configured validator precedes historical
retries. After first origination for all destinations, it returns to ordinary
rotation. Cold authenticated mesh records preserve this distinction; missing
peer receipts still retain normal retransmission. Local origination grants
no peer custody, ledger acceptance, debit, maturity or finality.

Ordinary candidates include pending imports from fully Native-authenticated
contact records as well as owner submissions. Complete-origin profiles also
retain their separate complete-history import selection. Proof receipt and
candidate construction grant no credit: the destination must install its
admitted finality certificate and reach signed maturity before onward spending.
Permanent import tombstones suppress a second import of the same export;
every proposed command still executes under current Native safety checks.

The Rust companion currently refuses joint-epoch and role-lifecycle companion
config formats. Their native verification/signing CLI APIs remain available;
removal of the old campaign driver does not qualify their autonomous lifecycle.
No old full-cycle or fault result transfers to the changed Rust runtime.

During actual Native or transport OS lock contention, the contact status reports
`progress_observation_available: false` with a diagnostic and no height, round
or mesh progress. The node retains evidence and retries through full Native
verification after release. Only the exact Native lock refusal and the current
OS adapter's contention errno qualify; proof, permission and other I/O failures
remain errors. A missing observation grants no ledger or signing authority.

## Verification

Create `tmp`, then run `cargo fmt`, strict `cargo clippy --all-targets`, and
`cargo test` with this manifest. Use an owned mode0700 canonical temporary
directory and explicitly pin the current built CLI through
`RLD_EXPORT_ARCHIVE_CANDIDATE_CLI`; the [verification guide](../../docs/operations/VERIFICATION.md)
provides complete commands. Run fixture tests serially to preserve bounded
process startup and pacemaker observations. The test profile uses optimization level one
with debug assertions and overflow checks enabled. Tests exercise native value,
incident, finality, archive, custody and exact encoding behavior; transport tests
also reject corrupt later envelopes, unsafe paths and cold corrupted state.

Full ordinary payment and onward maturity, sustained faults/load, independent
operations and anti-rollback custody, cross-device power loss, long-history/era
execution, cryptographic adoption and physical links remain separate gates.
Retain exact source-bound failures and private stopped stores. This source change
requires fresh signed no-value fixtures and never upgrades an adopted network.
