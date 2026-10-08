# Complete origin history receiver profile

`RLD-REGIONAL-BFT-COMPLETE-ORIGIN-HISTORY-FIXTURE-V1` is a separate,
authority-signed, no-value receiver admission. It extends the fixed-validator
paged BFT profile for complete **origin-only** source histories. It changes no
issuance, quorum, fee, maturity or custody rule. Its rules commitment is
`paged_bft::rules_hash_for(paged_bft::ORIGIN_HISTORY_RULES)`; its admission uses a
distinct signing domain. Changing an old admission's label or rules commitment
without a fresh authority signature must fail. Existing currencies, custody and
failed fixtures do not migrate into this profile.

The typed `storage::CompleteOriginHistory` contains `source`, `destination`,
`export` and ordered `snapshots`. All identifiers use canonical lowercase
hexadecimal. The receiver independently pins currency, authority and admissions.
The source must be that currency's origin with the original paged rules; every
original source certificate, owner command and parent witness from height one
through the declared tail must execute from signed genesis. No serialized
`Ledger`, receiver working-set cache, sender summary or hash-only prefix is an
initializer. The exact export must exist in the fully executed tail and name
this destination.

The complete proof remains within the existing 8 MiB object bound and 4096
executed-identity ceiling. Active destination evidence remains 64 checkpoints;
pages remain sixteen events; whole private storage remains 4096 files and
256 MiB including residue. These are refusal ceilings, not a claim that every
combination up to a ceiling fits. Arbitrary foreign ancestry, epoch handoff and
target-scale recovery require additional implementation and qualification.

The fixed-head local CLI accepts **evidence only**:

```text
rld-regional-ledger-candidate --dir RECEIVER --authority AUTHORITY --currency CURRENCY \
  complete-origin-history-accept --file COMPLETE_HISTORY_JSON --expected-head NATIVE_HEAD

rld-regional-ledger-candidate --dir RECEIVER --authority AUTHORITY --currency CURRENCY \
  bft-pending-imports
```

`Store::accept_complete_origin_history` retains the complete typed event only
after Native verification and scans retained histories for authenticated source
conflicts. Exactly identical, already executed evidence is idempotent; tail
identity alone cannot suppress body verification. Conflicting certificates
remain durable incident evidence and quarantine the source rather than replacing
its branch. Existing liabilities and source debits remain intact.
The acceptance response describes this evidence operation only; the Native
recipient receipt remains the authority for actual import and maturity status.

`Store::complete_origin_pending_imports` derives local `Command::Import` tasks
from fully executed events. Each pending checkpoint remains an active dependency
until a separately certified local import records the permanent consumption
tombstone. The query refuses known incident sources and checks the retained
derived export again. Neither that queue nor successful evidence admission
credits a recipient. The ordinary destination voters must certify the import;
the original recipient must reach Native maturity before its separately pinned
wallet/caller lifecycle authorizes spending.

Transport byte receipts, source archive observations and opaque part assembly
are distinct from this evidence-admission interface. A historical source proof
does not establish remote current state, independent freshness or independent
custody. Receipt loss, expiry, verification failure and resource refusal cannot
refund or recreate the source debit. This profile cannot authorize real assets,
post-quantum adoption, independent security or physical routes; the full frozen
acceptance obligations remain applicable.

`tools/regional_origin_history_carriage.py` splits the original proof bytes into
existing bounded frames and retains only a complete, caller-bound reconstruction.
Its route/order checks are structural; it does not authenticate certificates.
The receiver must still invoke the fixed-head Native entry with independently
pinned genesis. Ordinary standalone BFT/contact envelopes retain their existing
bounded-proof contract. Local evidence admission and local durable signers do
not establish default Service/Runtime proposal carriage for long origin history.
