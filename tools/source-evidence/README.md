# Native source evidence

Build `rld-maintenance` with `cargo build --locked -p rld-cli --bin rld-maintenance`.
`rld-maintenance snapshot create --root ROOT --output NEW_DIRECTORY` captures
Git-visible source, including uncommitted files, under `tree/` with a canonical
`RLD-SOURCE-SNAPSHOT-V1` inventory. Exact contents, normalized 0644/0755 modes and
sorted relative paths are committed. An uncommitted tree is not a published commit.

`rld-maintenance snapshot verify --snapshot DIRECTORY --manifest-sha256 HASH`
checks an independently retained manifest pin and the complete file set, modes,
sizes and hashes. Unknown fields, extra/missing files, symlinks, unsafe paths,
noncanonical JSON and capacity violations refuse. Limits remain 10,000 files,
256 MiB per file, 512 MiB total and 4 MiB manifest. Interrupted capture retains
its incomplete marker and does not grant snapshot authority.

`rld-maintenance implementation-source --root ROOT --manifest MANIFEST
--expected-commitment HASH` recomputes the Core build inventory. The manifest and
commitment must come from an independently selected actual native binary.

`rld-maintenance cargo-sbom --metadata METADATA --lock LOCK --source-commit COMMIT
--source-tree-sha256 HASH --output NEW_FILE` binds SPDX package metadata to the
exact Cargo lock inventory. Generate metadata with `cargo metadata --locked`.

Capture excludes ignored credentials and generated caches, refuses runtime/key
paths and scans known credential patterns without printing matching content.
These heuristics do not replace explicit public-source review. Local compiler,
dependency cache and build environment are not hermetic. Digest agreement does
not authenticate a publisher, prevent whole-install rollback or establish
independent reproducibility, signing authority, adoption or mainnet permission.
