# Candidate receive rotation after the last selected packet ID

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
