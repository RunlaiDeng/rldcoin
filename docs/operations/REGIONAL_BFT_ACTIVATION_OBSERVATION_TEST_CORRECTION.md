# Activation observation test correction

The first complete process run executed 422 tests with 421 passes and one
failure in the new bad-reply test. Its setup had not synchronized the native-
authenticated certified dependencies into the companion observation cache.
`Runtime.retain` correctly performs that sync before it handles epoch activation
and before body deduplication. The test incorrectly required the preceding
legitimate cache update to be undone when the later observation reply refused.

The correction first authenticates and synchronizes the complete closing
checkpoint. It then snapshots the runtime state, native journal and separately
retained caller heads. Actual native verification and activation still run;
only the observation response fields are altered. Bad request hash, index,
currency, region, flags, format, epoch or proof count must refuse without
retaining the new activation body or changing those prepared files.

The single corrected case passed using the exact new native implementation.
The complete joint process module and actual Runtime custody checks remain
separate required checks. Failed-test private directories now remain retained
after owned processes close, without printing keys or private state.

This is a test setup/lifetime correction, not a runtime or native change. The
original 363-file source, source manifests, failed 422-test report/log and
native binary stay unchanged. A separate correction inventory binds the changed
test and this note; all native/core and ordinary runtime bytes must match the
original inventory before reuse. The earlier 173 native tests and strict check
are not rerun or described as new evidence. Any combined verification report
must identify the initial failure, the affected-module rerun and unchanged
implementation explicitly; it cannot claim a fresh all-422 green run.
