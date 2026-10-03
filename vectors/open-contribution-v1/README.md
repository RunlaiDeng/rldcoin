# Open contribution V1 frozen vectors

Status: `PURE_MODEL_ONLY / NOT_RUNTIME_ACTIVE / VALUE_CAP_0`

This corpus is the first R7.2 implementation gate.  It contains 12 complete
schema objects and 60 cases: accepted cases A01 through A14 and 46 rejected
cases that cover every frozen first-error class plus multi-fault precedence.

- `vectors.json` SHA-256:
  `2eac220d8a23d8f2b0b447c128f7d07a5e3cab2baf236f3f6aea0a18ef901bf5`
- canonical payload SHA-256:
  `0c88b0b4e22237005dba15c6c27e000e4d719c495e3e475761a2c6f4a7e3e813`

The Python generator is authoritative only for producing this static file.
Python, Go and Rust each pin the file and payload hashes and independently
recompute the covered wire bytes, IDs, signature, Merkle roots, access work,
branch decision, nullifiers, ticket/claim outputs, 1000-candidate committee
summaries, M0-M5 founder slots, offline behavior, supply conservation and
first error.

Passing this bundle is not evidence that the admission network, ledger
commands, consensus integration, WAL/checkpoint, signer/witness, censorship
stall, or live multi-operator system exists.  Those remain later gates.
