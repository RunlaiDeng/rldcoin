# Resource and funding requirements

Declare CPU/RSS, disk/fsync, complete authentication/replay, per-hop bytes,
backlog and recovery-service budgets separately. A stopped read-only measurement
is not an active-node benchmark or a sustained throughput commitment.

Given admission rate r, disconnection D and burst B, backlog capacity must cover
rD+B plus replicas, metadata, failed residue and margin. Recovery must exceed
ongoing admission; refusal occurs before custody commitment. Capacity pressure
never refunds an export or deletes evidence. Validators, relays and archives
require explicit payers and funding; starting a node grants no reward authority.
