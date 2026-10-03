# Earth regional transfer tools

These operator tools live outside the signed consensus source set and link to
the exact source and destination rule libraries from the Earth source archive.
They do not alter either chain's rules or genesis identity.

`rld-earth-f-import` replays a local copy of the source chain, verifies the
signed genesis and adopted source identity, installs a signed source finality
certificate, and constructs a destination `FinalizedImport` command for one
already included export. It fails if the certificate does not cover the export.
Submit the generated command to a destination node only after checking its
source checkpoint and destination chain ID.

`rld-earth-f-spend` signs a destination transfer using the import recipient's
owner-only key. It derives the import output from the destination chain ID,
source chain ID, and export ID. Submit only after the destination reports the
import mature and spendable. A signed command is not proof of inclusion.

Build from the Earth source archive with the pinned Rust toolchain:

    cargo build --release --locked --manifest-path tools/earth-f-import/Cargo.toml
