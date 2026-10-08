# Complete origin network profile

`RLD-REGIONAL-BFT-COMPLETE-ORIGIN-NETWORK-FIXTURE-V2` is a fresh authority-signed,
no-value receiver contract. Its rules hash binds the normative
`tools/regional-ledger/src/origin_network_profile.md` and the unchanged complete
origin-history V1 contract. No old private state, keys, currency or test value
migrates; current whitepaper requirements remain mandatory.

`RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3` adds complete typed `origins` to ordinary
consensus envelopes. Each receiving Native verifier independently executes every
source certificate from its pinned signed genesis, derives its source dependencies
in this call, then verifies original local evidence and consensus/value bodies.
Existing NETWORK-V2 has no `origins`; V3 and signed receiver V2 require one another.
Complete source histories are not serialized Ledger initializers or latest-state
witnesses. Ordinary envelopes remain within3MiB, whole objects8MiB, source histories
four per envelope and combined active dependencies64. Oversized wire inputs refuse;
opaque multipart carriage is a separate candidate, not an automatic bypass.

`bft-origin-network-observe-conflicts` and `bft-origin-network-sync` require an
independently retained current Native `--expected-head`. Signature-authenticated
incidents persist even if a body's admission fails, including conflicting complete
source histories in one envelope. Bounded route/count/byte admission and independent
conflict authentication precede whole-history shape/value checks: a bad later tail
cannot erase an earlier authentic contradiction. Both certificate sides still
authenticate; forged conflicts do not create incidents. Observation installs no
history or money.
Synchronization re-authenticates the original whole envelope, accepts complete
origin events, and installs local certified heights sequentially. Exact original
certificates already fully executed by current replay need no duplicate append;
every changed later signature or body still authenticates and takes the historical
conflict path. A refused multi-event synchronization can retain authenticated
prefixes or incidents; it is not a single atomic monetary transaction.

Fresh ordinary runtime configuration uses `RLD-REGIONAL-BFT-ORIGIN-NODE-V2` and its
matching separately retained caller-head format. Native current-finality observation
replaces the old bounded proof startup entry only for this explicit configuration.
Runtime reception preserves incidents before full body admission, rechecks each
complete wire at sync, and retains whole origin bytes with existing message/body
identity behavior. Shared byte storage never authenticates a proof. Cold startup
reconstructs the full original envelope and invokes Native verification again.
Existing512-message,64-reference and32MiB combined-state ceilings stay unchanged.

Native outgoing ordinary Vote/Timeout bodies at the exact current Genesis parent
carry no origin dependency when no local certificate is retained. Native still
fully replays and checks current proof material and source quarantine before
selecting that empty closure, then authenticates the signature, admission and
exact Genesis parent through the ordinary complete wire verifier. A vote or
timeout grants no value execution. Proposals, submissions, finality and every
non-Genesis parent retain their original complete dependency carriage. Each
incoming envelope authenticates every proof it supplies, even for a control body;
attached invalid or conflicting evidence cannot be hidden by this selection.
Current incidents continue through the ordinary contact path.

`bft-origin-network-receive-batch` accepts one canonical ordered request of up
to four complete origin wires under a separately retained exact Native head.
The existing OS lock and full cold open remain mandatory. Whole input and
response stay within8MiB, each wire within3MiB; complete expanded object and
history limits remain unchanged. Bounded admission precedes independent
signature authentication of conflicts across incoming objects and retained
history. An authentic conflict remains durable even when a later body or tail
refuses; forged signatures cannot create an incident.

Every complete envelope authenticates before the first synchronization. Each
subsequent ordered synchronization invokes the original whole-wire verifier
and full Native value/history execution again. Exact retries remain idempotent;
a repeated body never authenticates a later proof. Verified prefix changes or
incidents can survive a later I/O/refusal, as with individual sync, but no
partial success response grants authority. Response bindings include original
request SHA256, each ordered input SHA256 and its complete checked row, exact
currency/region, the actual final storage head and current Native context.
These observations grant neither independent freshness nor signing rights.

The ordinary origin Runtime initially selects this operation only for batches
with empty local carried evidence, ordinary bodies and no joint configuration,
within original message/input capacity. All other cases retain the existing
read-only response segmentation followed by individual synchronization.
Selection grants no authority; Native independently verifies the full input.
Once the mutating call is attempted, capacity refusal, response loss or any
other failure never falls back to the old path. Message retention occurs only
after the complete bound response is checked. Signer/caller journals remain
separate; an ordinary later tick independently rechecks custody and context
before any signature. Exact lock contention remains an unknown deferred
observation rather than receipt, ledger acceptance or height zero.

Ordinary source contact export selects the earliest complete finalized local
certificate prefix ending at an existing debited export. Full current Native
replay precedes selection; separately received evidence, contacts and receipts
cannot choose branches or initialize source state. The selected proof must still
execute completely from signed genesis and match the original debit. Missing
foreign dependencies refuse. The existing single-frame payload limit remains3MiB;
no history truncation or multipart substitution is permitted.

`contact-origin-apply` requires the explicit signed receiver profile and an
independently retained current Native `--expected-head`. It authenticates the
complete original canonical frame and admits evidence only; the ordinary BFT
queue supplies Import candidates. Relay acknowledgement is neither Import nor
maturity. Later retries re-authenticate complete bytes without duplicate append.

Import, quorum3-of4, maturity2, fees, permanent consumption, owner/caller custody,
conflict quarantine and source liabilities remain original Native behavior. Evidence
and relay receipts supply no monetary or voting rights. Arbitrary foreign ancestry,
long local histories, source signing custody, target-scale resource/recovery,
post-quantum adoption, independent operators/security, physical routes and mainnet
adoption require separate complete qualification.
