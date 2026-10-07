# Verified-stage publication

Owner instruction, 2026-10-07: “每次完成一个东西 应该推送最新代码到github”.
The sole implementation author applies this after each stage's necessary checks,
using the existing authenticated `origin` and existing `main` at
https://github.com/RunlaiDeng/rldcoin. There is no new approval gate for that ordinary
push. Historical no-push records describe their own recording time.

1. Finish the bounded stage and retain real failures, deadlines and unmet gates.
   Reuse valid unchanged source-bound checks; do not rerun long tests to publish.
2. Review the exact staged sources and necessary public evidence. Inspect **every
   new reachable blob version** from remote main to the proposed commit, including
   intermediate/deleted files. Exclude credentials, keys/seeds, private
   ledger/owner/voter/TLS/node/config/keyless state, binaries, tmp/target and large
   archives. Public no-value verification vectors contain public keys/signatures,
   never generated private bytes. An unsuitable ancestor blocks publication;
   report the file/category, without rewriting history or deleting local state.
3. Commit only that reviewed stage, pin its full commit SHA and check the remote
   is an ancestor. Ordinary push only that SHA to `refs/heads/main`. Disable tag
   following/mirror behavior for the command; never force or push all branches.
   Old rldcoin-genesis historical branches remain local and outside this refspec.
4. Read back remote `main` and confirm the exact target SHA. Record the push result
   and actual CI URL/state in the task receipt; pending or absent CI is not PASS.
   Existing CI has three read-only jobs (source/vectors, workspace, regional).
   A failing relevant check selects a concrete repair, with no warning exemption.
5. Resume the authorized single development mainline. A pushed candidate, finite
   fixture PASS or CI PASS does not establish adoption, mainnet, independent
   review/custody, complete PQ integration, physical routes or the whole goal.

The initial backlog publication reviews baseline
`1ea8457f31ebd4bda677096e20707365bca1456a` through frozen source tip
`97c716f4d267b1e96c75cd912b6957ea359b454e` (106 linear commits), followed by this
workflow-only commit's separate review. Its public audit is
`docs/operations/evidence/stage-publication-history-review-20261007.json`.

Historical qualifications remain exact: regional head-v16 uses Core171 de74/CLI
bef4, value V13 uses Core177 bc623, era V11 uses Core177 ffb05, and hybrid V9 uses
Core1814070549a (277 tests plus strict checks). TLS has six bounded observations
across a failed V2 and remaining-two V3; **no single six-case passing stage**.
Publishing these records preserves those limits. Frozen Markdown/PDF/receipt,
website, monetary/consensus parameters and all S/R/I/A–G/N/P requirements remain
unchanged.
