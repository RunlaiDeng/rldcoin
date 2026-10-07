# Outbound neighbor rotation contract

For a fixed configured neighbor set, advance the batch origin by the smallest
step at least the batch width that is coprime to the neighbor count. This avoids
permanently assigning every neighbor the same position in repeated batches.

Prepare and durably rotate the exact exchange before connecting; bind the fresh
challenge and require complete local custody of the authenticated reply before
suppressing retransmission. Endpoints, pins, authentication, socket/lock bounds,
per-round capacity and cancellation remain independent requirements. Rotation
alone does not guarantee scheduling, recipient maturity or sustained liveness.
