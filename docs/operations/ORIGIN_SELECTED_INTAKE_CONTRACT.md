# Selected Native input and signing order

The Origin contact companion persists the packet IDs of each selected BFT input
before attempting Native authentication. A typed Native lock refusal leaves the
input pending. OS errors and lost responses also leave the outcome unknown. An
unknown outcome cannot release a new signing request, including Timeout. The
signing check precedes caller-head review and the Native request.

`RLD-BFT-INTAKE-PENDING-V1` contains at most four ordered, distinct packet IDs and
at most 8 KiB. It binds the exact runtime, configured Native authority, ledger and
transport directory. It contains no decoded payload, ledger or signature. Writes
use private atomic replacement and directory synchronization; a failed write
freezes the current process's signing path. Native retained-response recovery
still uses its separate caller head and cannot first-sign.

Pending IDs take the existing four-attempt receive budget before new inputs.
Transport custody must reconstruct the original complete frame, authenticate its
transit and matching receipt, and perform full Native authentication again. An
absent or damaged retained input leaves signing blocked. A complete Native or
structural refusal closes that attempt without acceptance credit. Only successful
complete reception clears the pending ID before recording reception success.

Cold startup retains the pending IDs and performs the ordinary Native checks.
Existing Origin progress without the sidecar refuses unchanged: create a fresh
no-value fixture rather than convert an old failed store. Changed bindings,
malformed metadata and capacity excess also refuse without rewriting old state.
The sidecar does not establish independent freshness, all-state rollback
protection, ledger acceptance, signer lock authority or value rights.

The phase clock, quorum, maturity, payload, archive and history limits remain
unchanged. Delayed complete certificates remain eligible for full Native checks.
This local scheduling contract does not establish ordinary network payment
completion, sustained fault liveness, independent custody or protocol adoption.
