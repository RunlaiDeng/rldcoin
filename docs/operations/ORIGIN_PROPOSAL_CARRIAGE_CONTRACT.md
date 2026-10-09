# Origin Proposal carriage boundary

The base Origin runtime may publish a complete local Proposal immediately after
Native signing, its separate caller head and its complete retained envelope have
all returned successfully. The subsequent local Prepare is a separate Native
operation. A refusal or lock contention in that operation must not withhold the
already authenticated Proposal from ordinary neighbor carriage.

This boundary applies only to the current Origin runtime without a joint epoch
ceremony. It grants no authority from a queued command, an incomplete signing
response, a packet identifier or a transport receipt. Failed Proposal signing or
retention does not enter early carriage. The normal pending-intake guard still
precedes every signing request.

Early carriage consumes the same four-item enqueue selection as the ordinary
runtime tail, including any recursive Native phase reobservation within that
contact unit. A failed attempt consumes that unit's opportunity; the next ordinary
unit can retry retained evidence. The directory adapter moves its original
bounded outgoing batch before local Prepare and does not add a second batch at
the tail. The TCP adapter keeps its existing worker and attempt scheduling.
Recipient ordering, background slots and all packet, archive and payload bounds
remain unchanged. A given batch need not include every configured neighbor.

Transport publication does not authorize Prepare, Commit, finality, import or
spending. Each recipient retains actual custody and independently authenticates
the complete envelope and its dependencies through Native before using it. A
failed publication preserves retained evidence and caller state. No timeout
request is postponed or ignored by this boundary, and no phase clock, admission
threshold or Native signing rule is changed.

Ground tests of this boundary do not qualify ordinary four-validator liveness,
the complete payment cycle, sustained fault profiles, independent custody,
long-history execution, physical routes or adoption of the Native candidate.
