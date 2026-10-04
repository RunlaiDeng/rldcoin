# Local mesh admission turns candidate

The ordinary Service selection and TCP mesh contexts share one process-local
admission lease. No socket wait holds that lease or the Mesh lock. A fully
validated ordinary open gives a waiting TCP attempt the next turn; a TCP open
returns preference to a pending ordinary selection. Waiting actual outgoing
owners and active inbound handlers alternate their TCP preference as well.
This scopes only these contexts: startup, direct enqueue/broadcast and other
processes still use the actual native OS lock and can cause contention.

The one ordinary intent belongs to the actual Service thread. At most three TCP
waiters represent two bounded inbound handlers and one actual outgoing owner.
Only that live outgoing owner retains scheduling demand after an exhausted
attempt. A closed socket handler removes its ticket; dead owners are forgotten.
Release the local lease after Node close, and clear ordinary intent before Native
CPU. Node construction failure releases the lease without recording a validated
grant. Stop clears pending tickets and still joins actual custody workers.

Keep the original 0.2-second local acquisition attempt and three-second socket
deadline. Full signature, schema and file validation after acquiring the OS lock
can take longer; the attempt limit is not a total CPU bound. Expired sockets
receive no custody. Grants, tickets and class markers are scheduling metadata,
never transport receipts, Native adoption, owner signing or finality rights.
Nothing is serialized and no evidence, threshold, Native rule or capacity is
changed. Rebuild the native executable from the exact new frozen checkout so
its embedded companion path executes this code. Use fresh transport and private
fixture directories; failed payment source/value/custody remains stopped.

The exact prior frozen source reproduces a one-test negative: after a real
ordinary selection, another pending selection again excludes TCP even though
the first already completed. New tests exercise the same Service interface,
repeated foreground requests, actual outgoing-owner timeout retention, dead
inbound tickets, outgoing/inbound turns, constructor refusal, expired sockets,
ordinary CPU beyond the acquisition budget and actual pinned-TLS custody.
These are local scheduling/custody checks. They do not reconstruct the previous
failure's exact scheduling or uniquely explain it; only a fresh ordinary payment
cycle, separate complete cold validation and fault scope can qualify progress.

A signal can arrive while ordinary selection is awaiting admission. That exact
local stopping refusal has its own type. The main loop accepts it as graceful
only after the installed SIGINT/SIGTERM handler has stopped the loop; unexpected
runtime stopping, corrupt evidence and Native/custody failures remain errors.
Context cleanup completes and the actual workers join before ownership release.
Real child tests cover the signal boundary, unchanged Native journal, evidence
refusal and stopping without a signal. The prior failed ordinary run is retained
as failed; this repair needs its own frozen build and fresh ordinary fixture.
