# Reviewing public changes

Public commits contain source, build configuration, public test vectors and
necessary interfaces, design contracts, security notes and adoption boundaries.
Internal per-run outcomes, source/binary/controller inventories, host/task metadata,
timings and next-experiment schedules remain outside the public tree. Renaming a
report or embedding it in a design document does not change its classification.

Before staging, supply an explicit file selection with a public content kind and
specific purpose for each blob to `tools/review_publication_content.py`. The
publication entry must call its `review` function before any Git mutation. The
full tracked-document scan and negative/positive unit cases also run in CI.
These detectors assist human review; they cannot decide whether an experiment
journal is necessary engineering documentation.

Review every new reachable blob version since the actual remote parent, including
intermediate or deleted versions. Exclude private credentials, generated seeds,
ledger/config/signer/owner/caller/TLS state, binaries, build outputs and internal
logs. Public fixture keys and signatures must carry an explicit no-value origin.
Do not delete local failures or rewrite historical results to enable publication.

Stage only the reviewed changes. Check the exact remote parent and target ref,
then use an ordinary non-force push of the reviewed commit. Disable tag following
and mirror behavior; do not push unrelated branches or alter repository access.
Read back the exact remote commit and tree. Retain publication receipts locally
and report the actual CI state; absent or pending runs do not establish success.

Publication does not grant mainnet, monetary adoption, independent review/custody,
physical-route or complete-protocol qualification. Preserve frozen normative
materials and all acceptance requirements. Reuse valid source-bound checks rather
than repeating successful long tests solely for a documentation correction.
