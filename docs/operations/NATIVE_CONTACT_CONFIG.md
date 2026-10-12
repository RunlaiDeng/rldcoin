# Native independently configured contacts

`RLD-NATIVE-CONTACT-CONFIG-V1` validates ordinary configuration fields, identifiers,
contact capacity/shapes, TCP endpoints and retained spool-path uniqueness through
the matching contact crypto ABI. Operations are nested under `Config` and return
only checked configured input. `interstellar_config_reference.py` retains the
original Python endpoint/contact predicates and constructor contact block for
explicit comparison. Native refusal has no Python fallback.

## Fields, identity and endpoints

The configuration retains exactly `format`, `state`, `network` and `contacts`
under `RLD-CONTACT-MESH-V3`. Header checks precede the existing state-directory
operation; network identifier checks keep their original position afterward.
Actual native file-identity inspection and the Mesh lock still precede contact
construction. A syntactically valid network or peer identifier is not a ledger
admission or independent identity authority.

Contacts remain a list of at most 16 entries; smaller caller limits can only
refuse more. Each peer is lowercase 32-byte hex, distinct from the current native
transport identity and all earlier configured peers. Exact supported shapes are
duplex spool, unpinned or pinned TCP, explicit single-direction spool and the
existing bounded compressed-spool forms. Unknown fields/adapters refuse. The
one-way adapter is permitted only for exactly one spool direction.

TCP hosts remain literal IPv4 strings of at most 15 ASCII address characters;
hostnames, IPv6, leading-zero and malformed forms refuse. Ports are actual
integers, never booleans/floats, from 1 through 65535 for contacts. Explicit listen
selection additionally permits port zero and the unspecified address. Multicast
and `255.255.255.255` refuse in either mode. Existing reserved unicast behavior
is unchanged. Optional configured certificate fingerprints remain exact canonical
hex; actual TLS policy/negotiation, validity and pin checks remain separate.

## Native directories and original failure order

The bridge assembles only checked peer/host/port/pin or spool fields. It binds all
returned fields to the independently supplied configuration and never learns an
endpoint, pin, direction or permission from advertisements or incoming carriage.

Spool directories use the existing native descriptor-based nofollow operation in
original contact order and inbox-before-outbox order. Both directions must differ;
all configured spool paths must be distinct. Path objects retain the existing
lexical normalization and absolute-directory rules. This is no inode-alias
equivalence, filesystem conversion or new directory-security qualification.

Do not preflight the entire configuration in place of that sequence: a later bad
contact or directory failure retains earlier created directories and any failure
residue. Existing state-directory creation, native lock/identity inspection,
archive/state checks, cursor reconciliation, advertisement signing and state
publication keep their original order. Constructor failures still close the
original lock without deleting prior data or inventing custody.

## Result and authority

The common native receipt binds exact control bytes and implementation. The
configuration result also binds operation, exact checked values and literal
`configured_input_only: true`, `ledger_authority: false` and
`custody_acknowledgment: false` flags. The bridge uses the current crypto provider
per operation and checks complete normalized contact and endpoint bindings.
No configuration witness or mutable-result cache is introduced.

Configured identity and candidate routing remain separate from physical contact,
transport receipt, native ledger acceptance, finality, import, maturity and
spendability. This interface changes no quorum, timing, issuance, history,
exchange/frame/archive or scheduling bound and grants no signing/value rights.
Routing, scheduling, service and remaining wallet/runtime functions still need
migration. Finite same-host checks do not qualify independent custody/security,
full faults/load, long history, cryptographic adoption, physical routes or mainnet.
Changed native source requires fresh signed no-value fixtures; failed stores and
old candidate value never migrate.
