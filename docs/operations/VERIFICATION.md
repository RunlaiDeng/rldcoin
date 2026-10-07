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
python3 -B -m unittest discover -s tools -p test_pq_public_archive_spool_candidate.py -v
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

## Public packet custody candidate

`tools/pq_public_archive_spool_candidate.py` supports explicit `init`, `accept`
and `complete` commands. Every cold open requires a separately retained expected
manifest SHA512. Only an empty owned private directory can be initialized.
The caller's root is never learned from local packets. Full valid manifest arrives
before entry admission. Exact duplicate receipt rechecks bytes and fsyncs the file
and directory. Partial input cannot create a completion output directory.

Owned no-follow regular inputs, an OS file lock, immutable no-replace hard-link
publication, complete file and directory fsync before receipt, and retained failure
residues bound this candidate. All retained files count toward256 files and the
derived public-packet gross-byte limit; this does not change any existing Native,
mesh, entry or aggregate protocol cap. Only a current operation's successfully
committed temporary link is removed; older failed residue remains. Receipt means
durable received bytes, never valid inner signatures, a ledger head, value or refund.

The bounded multi-process example stops after half of193 packets, refuses incomplete
publication in a fresh process, receives the remainder in reverse order, repeats
exact custody, and reconstructs64 complete entries for actual Core. Injected write
and directory-fsync failures release no receipt and retain residue. This proves
those process/filesystem paths only; hardware power loss, concurrent independent
custody, sustained adversarial load, real contacts and monetary adoption remain
unqualified. No old failed signed custody is reopened or pruned.

The C TLS archive-spool mode described in the fixture README couples its explicit
archive receipt to actual pinned spool admission. A complete finite64-entry scope
used193 real loopback TLS sessions, process-cold partial refusal, reverse completion
and actual Core. Foreign entry and actual256-file capacity refusal issued no
archive receipt; retained raw transport bytes are a separate custody layer.
This uses fresh fixture credentials only and does not qualify long-delay key
validity, independent operators, adopted nodes or physical routes.

## Offline authorized manifest and inner archives

The Rust manifest adapter and explicit authorized-manifest renewal-archive mode
verify separately authenticated policy/freshness, complete ordered roots/bytes,
then real inner four-signature renewals and independent latest heads. Their
fixture README describes bounded inputs. Neither mode installs ledger state.

`tools/pq_archive_manifest_reference_candidate.py` implements separate Python
canonical decoding and actual OpenSSL dual verification without Core. It requires
an independently selected absolute backend and SHA256, separate policy, manifest,
envelope, and fresh scratch under an owned private parent. It retains only public
verification inputs. Result0 verifies finite manifest authority;1 refuses;2 is
unavailable. This does not verify inner entry signatures or grant nonce/state,
independent-author/operating custody, complete protocol or adoption qualification.

`tools/pq_renewal_archive_reference_candidate.py` independently decodes canonical
complete renewal policies/proofs, reconstructs Old/New signed payload and head
commitments, and verifies both Ed25519/ML-DSA87 halves for each role using the
selected OpenSSL backend. It requires separate trusted initial anchor, caller
observations/latest-head, private owned entry directory and fresh public scratch.
Original limits64/32768/2097152 remain. Missing trust, retired/expired originals,
stale prefixes, half rotation, changed locks/consumed roots and any bad half refuse.
It does not import Core, sign, consume nonce or install its returned candidate head.

The finite2-entry23-case scope and actual64-entry/256-half cold verification agree
with their separately source-bound Core observations. The latter measured complete
valid data, valid63-prefix refusal and a complete bad-last-PQ archive; it is not
proof of independent authors, complete protocol, long-history or adopted custody.
