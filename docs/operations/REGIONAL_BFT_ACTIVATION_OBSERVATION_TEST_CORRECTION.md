# Activation response test boundary

`Runtime.retain` authenticates and synchronizes certified dependencies before
handling epoch activation and body deduplication. A later bad observation response
must not be interpreted as undoing that earlier legitimate update.

Prepare the complete authenticated closing checkpoint before snapshotting runtime,
native journal and separately retained caller heads. Alter response fields only;
wrong request hash, index, currency, region, flags, format, epoch or proof count
must refuse without retaining the new activation body or mutating the snapshots.
Test setup corrections do not qualify a runtime, network or complete fault scope.
