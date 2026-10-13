RLD-REGIONAL-BFT-COMPLETE-ONWARD-HISTORY-FIXTURE-V1

Explicit authority-signed no-value receiver admission for complete two-hop
history A to B to C. Exactly three distinct admissions share independently pinned
currency and trust. A is the currency origin under original paged BFT; B uses
COMPLETE-ORIGIN-HISTORY-V1; only C uses this new profile. Its separate signature
domain and rule commitment do not convert old stores, keys or currency.

CompleteOnwardHistory is a flat typed value containing the complete original
A-to-B origin proof and every B certificate from genesis through a finalized
tail, plus the exact B-to-C export identity. It contains no recursive proof,
Ledger, sender balance or cache initializer. A permits local Spend and the named
export to B, without imports or channels. B permits local Spend, the exact A
Import and the named export to C, without other routes, channels or epochs.
The complete A and B certificate count together stays within4096; the whole
encoded object stays within8MiB. All original native limits remain mandatory.

Replay B from independently verified genesis through the ordinary Native kernel:
first execute its complete A proof, then every B certificate, including every
later tail. Verify all signatures, parent witnesses, owner commands, maturity,
issuance, permanent imports and complete export provenance. Compare complete
overlapping A and B bodies against the receiver's already-executed history.
Future retained records, amount equality and matching proof tails grant no
authority. Original origin-only entrypoints keep their exact profile restrictions.

Only this complete execution can supply the B tail and the exact A dependency
anchors needed by its export. Install them together after checking every overlap
and the complete retention bounds. Pending imports pin their entire closure,
not just B's checkpoint. Existing64 active anchors,8MiB native objects and
4096-file/256MiB complete private archives, including residue, are unchanged.
Persist every original A and B byte in the typed event. Cold and historical replay
execute the whole event from genesis; no persisted native state initializes it.

Expose all A and B certificates to full retained-history conflict scans. A bounded
routing admission precedes independent conflict authentication; a genuine conflict
must remain durable even when a later value/signature error refuses the input.
A forged signature cannot manufacture an incident. Acknowledgement, exact retry
and pending task output require current native health and safety for A, B and C.
An incident never selects a payout, clears quarantine, erases a debit or refunds.

Evidence receipt creates no credit, local finality or spending permission. The
unchanged local Native rules require a separately certified Import, permanent
deduplication, original maturity, complete provenance and actual owner approval.
The explicit exporter selects the earliest certified B export prefix only after
complete current native replay, preserving the original A proof used by B.

This entry implements Store/library evidence handling, not a new contact or BFT
network envelope. Existing origin network profiles and default startup scheduling
do not adopt it. General ancestry graphs, converging sources, returns, carried
channel histories, epoch handoff, independent custody/security, normal-load
latency, target-scale archives, physical routes and mainnet adoption remain
separate requirements. The finite two-hop boundary does not shrink those goals.
