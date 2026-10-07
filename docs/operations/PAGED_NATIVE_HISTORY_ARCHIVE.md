# Ordinary paged Native ledger images

The existing private history archive and restore entry points recognize the
explicit signed paged BFT Store and emit the distinct
`RLD-NATIVE-PAGED-BFT-HISTORY-ARCHIVE-V1` format. The original legacy archive
format remains separate. Neither is an adopted network or independent recovery
qualification.

A paged image includes its signed canonical ledger header, complete event
manifest and original pages, the zero incident guard, complete retained incidents
and bounded damaged-incident residue. Its stream lock is an empty structural file;
it supplies no signing authority. Fixed native names determine the inventory;
paths supplied by an index are never traversed. Private keys, signer and owner
journals, caller heads and pending reviews, transport state and unrelated files
are excluded.

Sealing holds the original node lock and first opens the complete current Native
history from genesis under the separately supplied currency and head. The copied
image receives another complete Native execution, including owner commands,
certificates, imports, receipts and incident evidence. The original source and
copied inventory must match before publication. No serialized ledger or cached
receipt index initializes that verification.

Restoring authenticates the archive inventory and performs the same full Native
execution before creating a fresh target. It verifies the complete copied target
again before removing its durable `RESTORING` marker. Wrong currency, stale head,
mixed layouts, relabelled archive format, missing or modified bytes and incomplete
Native proofs refuse. An existing or interrupted target is retained and refuses
normal startup; no merge, cleanup or automatic continuation is supplied.

The original shared 4,096-file / 256-MiB ceiling remains in force. The complete
paged archive includes its canonical index, lock and interruption marker within
that ceiling, and each file retains the original 8-MiB bound. Existing legacy
limits are unchanged. Physical copying does not convert records into lossless
prefix storage or authorize an archival profile change.

The latest head must survive independently of the image's rollback domain.
A restored ledger does not restore signer locks, owner reservations or independent
latest-state witnesses. No new signing, refund, duplicate import, key migration
or custody reset follows from an archive digest. Independent rollback protection,
large-history recovery, resource funding, suite/epoch adoption and physical routes
remain separate mandatory acceptance conditions.
