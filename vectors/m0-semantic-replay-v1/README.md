# Pinned-genesis candidate semantic replay fixture

`history.jsonl` contains 35 canonical local interchange frames: one 3-of-4
certified heartbeat, 33 Admission source headers including exact sidecar bytes,
and a 3-of-4 certified **dormant candidate** tag28 checkpoint. It starts from
`../m0-genesis-v3/manifest.json`; all signing identities are the deliberately
known test seeds described there. It has no production secrets or live authority.
`expected.json` pins the supplied genesis hash and the exact final height/root.

The CLI independently executes the verifier in its own process using the same
Rust implementation. The result is not an independent-client qualification,
signer authorization, production snapshot, hardware recovery proof or M0b.

```sh
cargo build --locked -p rld-cli --bin rld-genesis
python3 -B tools/m0-semantic-replay/verify_cli.py --binary target/debug/rld-genesis
```

The test invokes the actual CLI for the complete history and 11 raw-input
failures: wrong genesis pin, truncated valid prefix, wrong final head, missing
confirmation, unreplayed anchor, torn frame, insufficient quorum, substituted
sidecar, unsigned inner field, duplicate inner field and unknown frame version.
It also checks that the command never changes the input file.

Each frame is the exact compact typed JSON followed by one LF. Duplicate,
unknown/default-omitted fields, alternate whitespace/order/numbers, unsupported
versions and oversized frames are rejected. This local format adds no consensus
tags or schemas and changes no earlier vector. U128 values are decoded directly
without an intermediate JSON number representation.

Local limits are 16 MiB/frame, 128 MiB/transcript, 16,384 input frames,
4,096 distinct certified commits, 32 MiB retained serialized commits, 4,096
source headers, 8,192 source entry occurrences and 64 MiB unique sidecar bytes.
These are verifier capacity limits, not new consensus limits. A larger valid
history may stop at this local boundary; no evidence is pruned and no larger
deployment qualification is claimed. Both the initial pin and expected final
head must come from a separately verified source to make this an operator check.
