# Native BFT caller custody

The ordinary and complete-origin ground companions use Rust for existing BFT
caller-state reads, publication and pending-response recovery. The caller file
remains separate from the native ledger, signer journal and runtime archive.
Python still owns the companion lifecycle, scheduling and transport. Explicit
joint-epoch and role-slot profiles retain their separate initialization and
custody implementations until those workflows are migrated; a native refusal
never selects the former ordinary implementation as a fallback.

## Interface and durable order

`bft-client-read --head-file PATH --signer-dir PATH --expected-key KEY
--runtime-format FORMAT` reads an existing caller file. It does not initialize a
head, adopt an observed signer head or authorize signing. The five fields remain
`format`, `binding`, `head`, `pending` and `outbox`, with the original sorted ASCII
JSON encoding. Binding includes currency, region and signing key. The supported
formats are `RLD-REGIONAL-BFT-NODE-V1` and
`RLD-REGIONAL-BFT-ORIGIN-NODE-V8`; the latter requires the explicit signed
complete-origin network admission. Independent role and joint profiles refuse
this interface.

`bft-client-store` adds `--file PATH --expected-state-sha256 HASH`. The file carries
one proposed complete caller state, bounded by the original 8 MiB limit. The
separate argument binds the exact canonical previously retained state; a digest
never substitutes for reading that state or authenticating native history.
Unknown fields, duplicate keys, lost typed fields and noncanonical stored bytes
refuse. The native ledger lock and a separate caller-file lock cover checking and
publication; actual signer inspection keeps its own lock during full replay.
Private files and locks require the current owner, private permissions, no
symlinks and no hard links. Caller directories cannot overlap the ledger or signer.

Before signing, the caller retains the exact pending request at the current
separately retained signer head. The normal native signing operation still
independently authenticates the current parent, quorum locks and request. Only
an exact fully authenticated journal response can advance the caller head and
become its outbox. Publication writes and fsyncs a private temporary file, renames
it and fsyncs the directory before returning. Failed publication residue is
retained and never adopted as authority.

The companion releases an outbox only after complete native envelope validation
and durable local runtime retention. Clearing the caller outbox also checks the
exact native response and current caller/signer head. This file operation does
not acknowledge transport custody, recipient acceptance or finality. The
companion's lifetime locks and durable runtime archive remain necessary.

## Recovery

`bft-client-reconcile` accepts the existing complete caller state through `--file`
and requires equality with the retained file. It accepts no key input and cannot
first-sign. It calculates the next caller state; `bft-client-store` publishes that
state separately. Paged recovery may finish publication of an already retained,
fully authenticated original native response under the existing recovery rules.
Every original request, response, signer lock and journal dependency remains.

An unsigned pending request can clear only when complete native inspection proves
that its separately retained head is unchanged. A retained original response
recovers its exact message and current head. Unknown, changed or corrupted native
custody refuses and preserves the pending caller record. Response loss after
caller publication is handled by reopening the exact caller file and retaining
its original outbox before clearing it. No timeout releases a signer lock or
creates a replacement signature.

## Boundaries

The independent Python caller algorithms are retained in a test-only reference;
production never imports them. Public no-value fixtures exercise both formats,
paged recovery and caller publication boundaries. They do not establish
independent custody, power-loss durability, all-state/head rollback protection,
concurrent copied-key custody, long history, BFT reconfiguration, physical routes
or mainnet qualification. Original ledger, history, archive and transport bounds
remain unchanged. A changed native implementation requires fresh signed no-value
fixtures; no older state or value is migrated.
