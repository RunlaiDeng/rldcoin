# Candidate receive rotation after the last selected packet ID

The compatible-incident ordinary payment run failed its original final 600-second
gate. Stopped Native replay confirms five height-11 era-2 prefixes with 300
conserved, two included owner payments and the third still reserved/pending.
The exact source and all private stores remain retained. Full transport inspection
and source Native checks found five current-parent envelopes on carrier 2 with
destination packets and signed transport receipts but no retained Native body:
the round-5 proposal, one round-5 timeout and the two round-6 prepares plus one
commit. Receipts grant no ledger or signing rights. This does not reconstruct
all prior scheduling or prove a unique failure cause.

The new scheduling-only candidate keeps two process-local 64-character packet
IDs, one each for the existing novel and background classes. It selects the
sorted successor of the last selected ID, wrapping the ring. Successful removals
and newly inserted lower IDs therefore cannot shift a numeric rank past the next
waiting packet. The two nonempty classes retain two slots each; spare capacity
still goes to the other class, within the unchanged four slots. Changed complete
proof bytes on an existing body remain novel. Non-BFT selection and the durable
complete-tick/offer/destination cursor are unchanged.

The IDs schedule only. They are not serialized, cannot initialize Native state,
grant receipts, authorize deduplication, select a value or release a signature.
All selected transit/receipt and complete Native envelope checks remain on the
ordinary path. Failed authentication still retains evidence; no native signing,
threshold, timer, capacity or socket limit changes. Restart clears just this
ordering observation and keeps full cold checks. Use fresh private fixtures;
do not restart, rewrite or migrate the failed run.

Six new ordering checks pass, including removal-induced rank skipping, lower-ID
insertion/wrap, independent complete class rotations, changed-proof/ordinary
traffic fairness, single-class/restart behavior and unchanged non-BFT filtering.
Together with eight cold-role and nine phase checks, 23 local checks actually
passed. This is a bounded scheduling model result, not ordinary payment or
full-fault qualification. The real two-handoff Native reception/proof-variant
regressions also actually passed (two tests, 51.263 seconds): full cold Service
reception checks new votes/submissions, changed valid proof bytes and an invalid
later proof, without replacing original retained bytes or altering caller heads
and ledger. A new frozen full regression/ordinary cycle remains separate.
