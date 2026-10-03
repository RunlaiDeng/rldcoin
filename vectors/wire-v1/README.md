# RLD-WIRE-V1 vectors

`vectors.json` is a frozen, content-addressed conformance bundle for the
candidate wire profile in `spec/wire/README.md`.

`commands.json` is a separate content-addressed bundle for the adopted command
profile in `spec/wire/COMMANDS.md`. It preserves `vectors.json` unchanged and
contains accept vectors for all 19 consensus and all 30 production variants,
plus command-payload decoder and tamper rejections.

`stake-state-resource-v1.json` is the frozen R6.15–R6.17 resource schema bundle.
Its whole-profile metadata remains conservative because resource envelopes,
bonds, accounting admission, node routing, economics, dynamic membership and
mainnet use are disabled. R6.17 adopts only policy-governance tags 18/19, and
Rust checks their adopted command bytes exactly match this bundle. The original
V1 bond/pool bytes remain present, while append-only V2 records retain the
policy, owner, sponsor authorization, persistent-byte charge and per-policy
conservation data required for replay audit.

- `vectors.json.sha256` is SHA-256 of the complete `vectors.json` file; the
  verifier checks the exact sidecar line before parsing JSON.
- Every case has `case_id = "sha256:" + SHA256(canonical_json(case without
  case_id))`.
- `payload_sha256` is SHA-256 of canonical JSON for the complete `payload`.
- Canonical JSON uses UTF-8, sorted object keys, no insignificant whitespace,
  and no NaN/Infinity.
- Accept cases freeze source values, canonical wire bytes, purpose preimages,
  and SHA-256 digests.
- Reject cases freeze the input mode and the stable rejection class.

The bundle includes u128 boundaries, heights above u64, all prioritized object
schemas, cross-network/Zone/genesis/era mismatch, leading-zero and overflow
inputs, duplicate/reordered/unknown fields, duplicate JSON keys, non-NFC text,
optional-binding failure, truncation, trailing bytes, and signature-domain
substitution.

Regenerate only when the candidate specification intentionally changes:

```sh
python3 tools/independent-verifier/build_vectors.py
python3 tools/independent-verifier/build_command_vectors.py
python3 tools/independent-verifier/build_stake_resource_vectors.py
```

Normal CI must use `--check`, not regenerate the expected results.
