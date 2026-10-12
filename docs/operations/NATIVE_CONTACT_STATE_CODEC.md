# Native shared-frame state codec

The ordinary mesh state path uses `RLD-NATIVE-CONTACT-STATE-CODEC-V1` in the
matching sibling native library. Its disk image remains
`RLD-CONTACT-ACTIVE-SHARED-FRAME-V1`; frame objects remain
`RLD-CONTACT-ACTIVE-FRAME-V1`. This is no automatic conversion or value migration.
`interstellar_active_state.py` retains the independent Python packing and
reconstruction algorithm for explicitly selected tests, never as a failure
fallback.

## Bounded local interface

`rld_contact_state_codec` accepts canonical control JSON of at most 8,192 bytes
and a separate immutable payload of at most 64 MiB. Controls bind its exact
length and SHA-256. The response binds the control digest and native source
identity; the existing release function frees each returned buffer exactly once.
The CLI and library identities must match. A rejected oversized payload pointer
is not read.

Ground development and test builds compile the pinned `sha2` dependency at
optimization level one with debug assertions and overflow checks enabled. This
changes the build profile, not the SHA-256 algorithm, canonical bytes or any
authentication/bound requirement. Actual compiler and executable bindings are
still necessary; a faster hash does not authenticate a record.

`Begin` accepts the complete state metadata with an empty message map and a fresh
caller-selected 32-hex operation token. `Transit` accepts one complete canonical
transit and its exact message ID. `Finish` returns the bounded compact image and
its complete canonical digest. `Abort` releases transient storage, including
after a lost response. A duplicate begin refuses without replacing the existing
operation. At most eight operation contexts are retained; no context is saved to
disk or used to initialize a ledger. Failed appends prevent finish. A finished
operation cannot remove a newer context that reused its token.

The existing ceilings remain 64 MiB per complete image, 256 messages and 20 MiB
per complete expanded transit. A caller may select a smaller bound, never a
larger one. Frames retain their existing bounded ASCII Base64 alphabet and
padding check. This codec does not introduce a new frame decoder or authenticate
its payload. Packing processes one expanded transit at a time rather than
serializing the entire expanded message map.

## Exact reconstruction before authentication

Rust checks canonical JSON, duplicate-key refusal, exact image and record shapes,
configured network/node ownership, every complete frame object commitment and
all referenced frame IDs. Equal frames share only exact immutable string bytes.
Every record keeps its original metadata, ordering/multiplicity, complete
expanded length and SHA-256. Decode reconstructs and checks each complete
transit separately, including later records that reference an earlier frame.
Missing, altered or unreferenced frames refuse. No peer cache supplies bytes.

The decoder returns a checked compact image. Python assembles its shared
immutable strings and passes the complete original state to ordinary mesh
authentication. Codec results explicitly report `authenticated: false` and
`ledger_authority: false`. A digest, decoded image or operation token grants no
signature, custody, native acceptance, caller-head, signing, finality, maturity,
spendability, refund or freshness rights. Every complete transit, archive and
native ledger dependency still follows its normal verification path.

## Publication and remaining work

The caller retains its OS lock, capacity checks and exact selected index bytes.
[Native storage](NATIVE_CONTACT_STORAGE.md) owns actual staging, synchronization
and atomic publication. Codec failure prevents that publication; lost filesystem
responses retain their existing refusal and cold-authentication obligations.
Single and batch packet admission share the publication-before-adoption path.
Their in-memory state advances only after successful publication. A lost
publication response can still leave a complete new disk image; the caller must
close/reopen and fully authenticate it, never infer rollback from old memory.

Python still provides ABI input/output encoding, shared-string assembly, complete
mesh authentication, deferred intake, outgoing scheduling,
service orchestration and remaining wallet flows. Independent Python tests remain
necessary. [Spool publication and inventory](NATIVE_CONTACT_SPOOL.md) are native;
complete caller authentication still follows every reconstructed record.
This codec does not qualify power-loss or cross-device custody,
independent operations, sustained full fault profiles, long history, PQ adoption,
physical routes or mainnet. Changed native source requires a fresh signed no-value
genesis; old value/custody and stopped failure stores are never migrated or
reopened for replacement qualification.
