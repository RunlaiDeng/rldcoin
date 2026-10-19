# Explicit trusted-file control of peer custody heads

This no-value local control profile makes unattended data-custody progress
recoverable without inferring a latest head from the peer journal. The operator
explicitly supplies a private trusted head-file path. Its integrity/latest-state
is a local trust assumption, not independent freshness or all-state rollback
protection. Wallet/caller/native authority remains separate; this is no monetary
adoption, state conversion, continuous fee service or G1-G11 qualification.

Controlled custody uses the existing RLDFPEER header with local storage version2,
suite1. Its packet/TLS formats are unchanged. Legacy literal-head opening accepts
only version1 and cannot bypass version2 control. Binding uses fresh transport
state and a fresh separately selected head file; old private state refuses without
migration. Native supply, work, value/signature/window/maturity rules are unchanged.

The trusted binary snapshot is big-endian: RLDFHEAD8, version:u16=1, suite:u16=1,
peer_header_hash32, previous_snapshot_hash32, committed_peer_head32,
pending_record_length:u32, exact_pending_peer_record, snapshot_hash32. Snapshot
hash is SHA256 over the existing peer-domain CONTROL-HEAD tag plus preceding
bytes. A checksum detects corruption; full original peer authentication remains
mandatory. The head file is explicitly trusted input, never ledger authority.

A pending record is the exact already signed queue/receive/response record,
including its original index, prior head, observation time, complete payload and
digest. At most one record is pending. Snapshot size is at most144+89+262345 bytes;
the same bound applies to one publication candidate at path.next. A separate
private exclusive path.lock lease binds the exact peer header and stable inode.
The32-MiB peer journal,2048 permanent packet IDs and414-byte response reservation
remain unchanged. No pending/completed signed peer evidence is pruned.

Before appending a peer record, durably publish a snapshot retaining its exact
bytes and old peer head. Only after peer file/parent synchronization publish the
new committed head with no pending record. Each snapshot publication creates
path.next exclusively, synchronizes file/parent, verifies its exact predecessor,
renames it over the trusted head file and synchronizes the parent again. This
replaces control metadata; complete signed records remain in the peer journal.
An acknowledgment or retry suppression is released only after both publications
and original peer custody have completed. Errors suspend new acknowledgments.

Normal controlled startup requires an intact completed snapshot, no candidate
residue, exact header/config/material binding and complete peer replay matching
the trusted head. Missing, altered, replaced or torn files refuse unchanged.
Explicit recover-control can finish only a valid exact in-flight publication and
its already retained signed peer record. Full replay authenticates the existing
prefix and prospective complete record before any append/publication. The peer
must be exactly at its retained prior head or exact complete expected successor.
Unknown advances, damaged tails or mismatching snapshots refuse without repair,
truncation, head inference, new keys/signatures or sockets. Recovery preserves
the original queue time and all response capacity obligations.

Provisioning/control commands are bind-control ROOT CONFIG HEAD_FILE and
recover-control ROOT CHAIN HEAD_FILE. Ordinary session startup chooses explicitly
between --peer-head LATEST_HEAD and --peer-head-file TRUSTED_HEAD_FILE, always
with --peer-root ROOT. Status distinguishes the control mode; a data head or
receipt still supplies no ledger acceptance, owner approval or usable payment.

Process interruption consistency is distinct from power-loss/cross-device
durability, independent latest-state custody and all-state/head/key rollback.
Autonomous native ingress, funded monitoring, consumer operation, scalable
history/archive/mass exit and composed latency/daily100M remain required.
