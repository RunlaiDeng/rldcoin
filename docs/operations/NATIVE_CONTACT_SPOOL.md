# Native contact-spool publication

Ordinary directory carriage uses `RLD-NATIVE-CONTACT-SPOOL-V1` in the matching
native sibling library for inventory and immutable publication. The independent
Python syscall oracle remains in `interstellar_spool_reference.py` for explicit
tests. Native failure never selects it as a fallback.

## Bounds and bytes

The typed `rld_contact_spool` ABI accepts canonical control JSON up to 8,192 bytes
and separate encoded/original payload pointers, each under the existing 20-MiB
exchange ceiling. Two local pointers do not increase any network or ledger cap.
Controls bind both whole lengths and SHA-256 values; responses bind the control
and native implementation. CLI/library identities must match. Free each returned
buffer once with the existing native release function. Oversized pointers refuse
without reading payload memory.

Inventory keeps 256 entries and 64 MiB of charged bytes; smaller caller bounds
can only refuse more. Exact pending names remain
`.rld-spool-pending-v1-<target>-<reservation>-<nonce>.tmp`. Partial regular files
charge the whole reservation. A pending name disappearing before metadata read
still charges its entry/reservation in that observation. Other unknown names,
directories, symlinks and oversized pending files refuse. Pending files are never
returned as receivable input.

The explicit `RLD-CONTACT-SPOOL-ZLIB-V1` adapter charges expanded header size,
but that header grants no authentication. New publication and duplicate comparison
decode one bounded RFC1950 stream, require exact EOF/consumption and complete
original length/SHA-256, and reject trailing, concatenated or partial streams.
No dictionary or format fallback is admitted. Plain carriage compares exact
original bytes. Neither codec results nor inventory authenticate evidence.

One private operation-local payload witness computes digests from the complete
actual inputs. Identical plain inputs may share a digest only after every byte
compares equal. Complete decoded bytes must compare to that same input before
reusing its digest for header checks. Responses reuse these already computed
digests; no witness survives the call, crosses the ABI or supplies unchecked
state, signatures, custody or ledger authority.

Ground dev/test builds compile the pinned RFC1950 implementation and checksum dependency at
optimization level one with debug assertions and overflow checks enabled.
The pinned shared arithmetic-helper dependency also uses level one with those
checks retained; random generation, entropy sources and signatures are unchanged.
This changes the executable profile, not the checksum, stream checks, format,
original bytes or resource/durability limits. Actual source and executable
bindings remain necessary; a faster checksum never grants authenticity.

## Native carriage codec

Ordinary encoding, decoding and header inspection use the separate
`RLD-NATIVE-CONTACT-SPOOL-CODEC-V1` interface. Its `rld_contact_spool_codec`
ABI accepts canonical controls up to 8,192 bytes and one separate input pointer
up to 20 MiB. Controls bind the complete input length and SHA-256. Encode uses
fixed level one and a 32-KiB RFC1950 window. Encoded and expanded bounds remain
independent; an incompressible result exceeding the original ceiling refuses.

One private call-local witness derives the complete actual input digest before
checking caller metadata. Encoding reuses that same derived digest only for its
unchanged input. Decoding checks the complete actual output digest against the
container, then reuses that derived digest in its output receipt. No witness or
unchecked caller digest crosses calls, initializes state or grants authority.

The unchanged container retains its original length and whole-byte SHA-256.
Python and native encoders may produce different valid compressed streams;
each decoder must reconstruct the exact original bytes. Exchange signatures,
canonical file identifiers, challenges and replies remain bound to those original
bytes. Header inspection supplies capacity metadata only. The explicit Python
codec oracle is separate and never selected on native failure.

The native result contains a small implementation/control-bound receipt and a
separate bounded output buffer. Release both unchanged buffers exactly once with
`rld_contact_crypto_free`, including empty failure payloads. The bridge checks
complete output length/SHA-256 before releasing bytes to its caller. Refusal
returns no partial output. Decode uses the declared size plus one refusal byte,
requires exact stream consumption and digest agreement, and performs no JSON,
signature, custody or ledger acceptance. Codec results explicitly carry
`authenticated: false` and `ledger_authority: false`.

## Publication and failures

Rust inventories and operates through one retained no-follow directory descriptor.
Admission reserves two names and twice the larger encoded/original size for staging
and its public hard link. Exclusive `0600` staging receives complete bytes, then
file/directory synchronization. A hard link publishes without replacement. Native
`File::sync_all` retains stronger Apple flushing.

Existing files must decode to the independently supplied complete original bytes.
Their inode is retained and file/directory synchronized. Competing publication
cannot overwrite them. After a new link, the recipient may consume the public name
immediately: the publisher synchronizes the directory without reopening that name.
Only after success is this operation's pending name removed, followed by another
directory synchronization.

Write, collision, link, synchronization and cleanup failures refuse success and
preserve their existing residue. There is no unconditional cleanup of interrupted
partial files. Later inventory charges all residue; restart/republishing does not
remove it automatically. Lost results may leave installed bytes but grant no
acknowledgment. Fresh complete validation and actual custody remain necessary.

## Authentication and remaining work

Results report `ledger_authority: false` and `custody_acknowledgment: false`.
Opaque IO does not verify exchange signatures, routes, native dependencies,
finality, maturity, ownership, spendability or refunds. The ordinary caller retains
all those checks before receipt/value release.

Python still performs complete mesh authentication, deferred intake,
outgoing scheduling, service orchestration and remaining wallet flows. Native tests
use separately compiled failure/interruption seams; production exposes none.
Same-host process interruption does not qualify power-loss, cross-device or
independent custody. Sustained full faults, long history, cryptographic adoption,
physical routes and mainnet remain separate gates. Changed Native source requires
fresh signed no-value fixtures; old value/custody and stopped failures are never
migrated or reopened for replacement qualification.
