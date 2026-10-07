# Lock refusal must not suppress native timeout carriage

The new supplemental scheduling candidate tries complete current/future proposals
through ordinary native signing. Only that exact native lock refusal may take
the alternate path. The exact pending Prepare review must still exist with no
response outbox. Existing recover-only reconciliation must prove the separately
retained head unchanged and clear only the unsigned review. A recovered response,
changed head, missing review, invalid signature, unrelated refusal or recovery
error refuses this path. Never reset a timer, alter a native lock or count a
rejected request as a phase advance.

After all such rejected candidates, the unchanged round timeout can release a
native-signed Timeout carrying the durable prepare QC. No Python lock prediction
authorizes a vote. Every new Prepare/Timeout still executes normal native
context/era/head/value/signing validation. No replacement proposal is generated
when a current-round proposal was already present. Complete delayed certificates
remain eligible before these branches, including in read-only mode.

The existing native timeout codec accepts three or four distinct ordered active
votes. The companion now passes all retained votes, capped at those four keys,
instead of dropping the fourth before native verification. Native authenticates
every signature/high QC, rejects mixed contexts/conflicts and selects the
highest verified prepare QC. Prepare/Commit and epoch quorums do not change.
All evidence, counters, capacity and deadline limits stay unchanged.

Two actual native regression cases prepare and commit a real QC, carry a valid
conflicting later proposal, verify unchanged native signer inventory/caller head
on rejection, and release the original current/future round timeout with the
same lock. They also test the four-vote certificate's highest QC. Mechanical
cases cover unrelated refusals, wrong reviews and recovered-head/outbox changes;
they grant no native authority. These checks, a fresh exact default-driver build,
ordinary payments, stopped cold and fault scope are pending at preparation.

Native/Core remain exact to the activation-observation implementation. Use new
private no-value fixtures and compile the correct default driver for this changed
ordinary companion; never resume or copy a failed payment source, refund inputs,
requeue an owner request, lower a lock/quorum or extend an observation deadline.
This ground scheduling change does not qualify sustained Byzantine liveness,
independent custody or physical/interstellar operation.
