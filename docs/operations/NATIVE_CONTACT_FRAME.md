# Native opaque evidence frames

The ordinary `make_frame` and `inspect_frame` entry points use the matching native
sibling library through `RLD-NATIVE-CONTACT-FRAME-V1`. The explicit Python oracle
in `interstellar_frame_reference.py` remains independent; native refusal never
selects it as a fallback.

## Bytes and bounds

The `rld_contact_frame` ABI accepts canonical controls up to 8,192 bytes and one
separate bounded input. Payloads retain the 3-MiB ceiling; complete frames retain
4 MiB plus 4,096 bytes. Smaller caller limits can only refuse more. Queue limits,
transport capacity, native history limits and admission rules are unchanged.

Construction and inspection reuse the existing native `contact::Frame` canonical
ASCII fields and domain-separated message-ID kernel. All six existing kinds,
lowercase identifiers, exact payload SHA-256 and canonical padded Base64 remain
bound to the same complete original bytes. Construction is opaque: it does not
authenticate the payload or admit it to a ledger.

Inspection checks the complete canonical frame, route, payload and message ID.
Regional control frames additionally require the existing V2 or complete-origin
V3 envelope fields, exact region/currency/export bindings and at most four origin
references. Native bounded unique JSON parsing rejects duplicates and unsupported
encodings or nesting; no alternative parser is selected after refusal. Valid
native control envelopes still require their normal complete native authentication.

## Receipt and buffer ownership

Controls bind the actual whole input length and SHA-256. The small receipt binds
the exact control and native implementation plus complete frame/payload lengths,
SHA-256 values and message ID. CLI and library implementation identities must match.
The separate byte buffer contains the complete constructed frame or decoded payload.
Release both unchanged returned buffers exactly once through
`rld_contact_crypto_free`, including empty failure payloads. Oversized pointers
refuse without reading their payload memory; failures return no partial bytes.

The bridge checks complete result bytes against the receipt before returning
them. For inspection it assembles the frame dictionary from the already checked
original bytes only after successful binding. This assembly performs no payload
authentication. No frame, ledger, signature or hash witness survives the call.

## Authority and remaining work

Results explicitly report `authenticated: false` and `ledger_authority: false`.
Opaque framing and regional-envelope field checks do not verify native certificates,
dependencies, signatures, finality, maturity, ownership, spendability or custody.
The existing complete native ledger/BFT checks remain mandatory after carriage.
Construction never signs, reserves inputs, refunds, installs blocks or acknowledges
durable custody. Lost codec responses do not grant any of those rights.

Python still provides ABI encoding/assembly, mesh authentication orchestration,
deferred input, outgoing scheduling, service orchestration and remaining wallet
flows. This migration does not establish sustained fault/load, independent security
or custody, long history, cryptographic adoption, physical routes or mainnet.
Changed native source requires fresh signed no-value fixtures; old value, custody
and stopped failed stores are never migrated or reopened for replacement qualification.
