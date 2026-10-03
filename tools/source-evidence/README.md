# Local source evidence

`source_snapshot.py create --root <Git-worktree> --output <new-directory>`
retains Git-visible source files, including uncommitted work, under `tree/` and
writes a canonical `RLD-SOURCE-SNAPSHOT-V1` inventory. It hashes exact contents,
normalized 0644/0755 permissions and sorted relative paths. The manifest records
Git facts without pretending an uncommitted tree is a published commit.

`source_snapshot.py verify --snapshot <directory> --manifest-sha256 <hash>` checks
the inventory pin, complete retained file set, permissions, sizes and hashes.
Missing/extra/changed files, symlinks, unsafe paths, duplicate/noncanonical JSON,
unknown fields and resource-limit violations fail closed. Limits are 10,000
files, 256 MiB per file, 512 MiB total and 4 MiB manifest.

Capture excludes generated caches and Git-ignored files, refuses runtime/key
paths and runs a heuristic credential scan without printing matching contents.
This detects known PEM/token/literal-JSON secret patterns, not every possible
secret. Ignored local credentials are not copied. Review the source inventory
before any public release; a passing scan is not proof that source is public.

M0 new installations use `RLD-M0-INSTALLED-ARTIFACTS-V2`, compile this retained
tree into a separate temporary Cargo target directory, verify the snapshot
again, and bind both source manifest/tree hashes and all five binary hashes.
The source and manifest remain inside `artifacts/source` across backup/restore.
Old V1 installs remain identifiable as legacy source-unbound candidates; changing
a V2 record to V1 while retaining source evidence is rejected. No existing
consensus/genesis format or frozen wire corpus is modified.

The local toolchain, Cargo dependency cache and inherited build environment are
not hermetic. Hash consistency does not authenticate a publisher, prevent a
host administrator replacing the entire installation, or prove reproducible
builds. The manifest explicitly records `hermetic:false` and
`independently_reproduced:false`. Formal source history, independently repeated
builds, signed releases and external anti-rollback evidence remain open gates.

Checks:

```sh
python3 -m unittest discover -s tools/source-evidence -v
RLD_M0_E2E_EVIDENCE_DIR=/new/public-evidence-directory ./deploy/verify-m0-mainnet.sh
```

The optional E2E destination retains only installed artifacts, the public
disposable genesis/benchmark and the result report. It never copies keys,
runtime state, signer configuration or backups. The default fixture is destroyed
after stopping its processes. The report describes one local operator, not a
stranger or independently controlled node.
