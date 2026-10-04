# Bounded ground BFT process observations

`RLD-BFT-PROCESS-OBSERVATION-V1` is diagnostic telemetry in the ordinary
companion's existing `regional-contact-status.json`. It never enters signed
consensus, transport custody, caller heads or recovery. Native/Core are unchanged.

Each Runtime starts a fresh process-local sequence and keeps at most 128 events,
1,024 canonical bytes per event and 192 KiB per snapshot. Up to 32 native operation
names accumulate call/failure counts and total/maximum elapsed time. Mutable
objects and oversized fields are refused by the diagnostic ring. Evicted events
and rejected diagnostic rows are counted; absence is unknown, never height zero.

The ring records completion of ordinary full-envelope reception (public exact
envelope/body identities only after native authentication and synchronization),
existing distinct-vote searches, phase context/round and elapsed timer age,
sign request/release boundaries, and tick completion/failure. A failed reception
records no authenticated envelope identity. Signature release still follows the
original separate pending/head/outbox publication path. It adds no native check,
vote, recovery, timer reset or extra receive slot. Incoming envelopes, proof
variants and native quorum/signature checks retain their original validation.

Contact events separate TCP, mesh selection, native reception/outgoing and
consensus durations. They stop before final status-file publication and the
ordinary interval sleep; they are not total wall-clock tick deadlines. The ring
is omitted from ordinary console output. A stopped status contains only its last
bounded ring. An external read-only recorder must identify each process sequence,
count gaps and report its own capacity refusal; it cannot reconstruct missed
events. Local clocks/status files are unsigned same-host observations, not
independent freshness or custody/physical-link qualification.

Use new no-value directories for ordinary reproduction. Preserve failed sources,
reports and private stores. Keep the original 20-second configured round timer,
600-second height observations, signed thresholds and all capacity bounds.
Timing evidence can locate a scheduling path; it cannot change a failed run's
verdict, authorize an old sealed-round Commit or qualify full BFT fault liveness.

The following BFT-only contact-order candidate consumes retained incoming
evidence, runs its one ordinary native consensus tick and durably broadcasts
the result before its one ordinary outgoing TCP batch. New replies remain
retained and are consumed next tick; the asynchronous server still requires
complete durable mesh custody before acknowledging. Non-BFT order is unchanged.
No receive slots, contact attempts, transit/receipt batch sizes, signature limits,
round timer or local-height deadline are added or increased. A real native
regression intercepts that sole socket attempt: the old order observes zero
native votes there; the new order observes exactly two, separate retained head,
clear pending/outbox and fully checked queued Commit frames, without a repeat
signature on the next tick. This is a local request/carriage regression, not a
real socket or complete ordinary-cycle pass. Fresh frozen reproduction is required.
