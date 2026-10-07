# Generic regional ledger candidate

The separate [selected-plan joint epoch candidate](../../docs/research/REGIONAL_BFT_JOINT_EPOCH_CANDIDATE.md)
adds explicit `--bft-joint` fixture admission. Old BFT first certifies the exact
new-set plan; durable activation then needs three ordered old and three ordered
fresh new approvals. It retains the all-four profile and all existing bounds.
Its ceremony is controller-carried, uses fresh no-value genesis and is not
independent or autonomous reconfiguration qualification.

An incompatible, bounded Rust implementation for white paper 1.11's onward and
return value transitions. It runs three native regional ledger stores, replays
signed owner operations and mined blocks, and uses explicitly installed unanimous
checkpoints. **Public fixture keys, no monetary value, no mainnet mode.**

The existing source/destination nodes and their signed genesis commitments are
unchanged. This supplemental candidate is separately built and started. It is
not a qualified regional consensus protocol or a migration path.

This source revision adds native random encrypted owner keys, complete encrypted owner-journal backup/fresh-directory restore, and local wallet backup controls. It retains interactive group proposal construction with fixed expiry across later owner reviews. It retains the loopback wallet interface with explicit native review, persisted signing/recovery, only-owned-input reservations and separate recipient stages. It retains default TLS relay, group approvals, [durable signer locks and joint validator epochs](../../docs/research/REGIONAL_SIGNER_EPOCHS_V1.md) and incident/quarantine policy. It creates a new fixture root; earlier source/report packages remain historical.

## Reproduce

Rust 1.98 or later is required. From the exact source tree:

```sh
cargo test --locked --manifest-path tools/regional-ledger/Cargo.toml
cargo clippy --locked --manifest-path tools/regional-ledger/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path tools/regional-ledger/Cargo.toml --bins
tools/regional-ledger/target/debug/fixture-campaign /absolute/NEW-fixture-directory
```

The campaign starts a separate native CLI process for every operation, using
three on-disk stores. It provides only Earth–Proxima and Proxima–Andromeda
contact transfers. Earth is not invoked while distant local payments and
onward exports execute. Each successful transition and evidence installation
replays all three stores and checks exact conservation. This is a ground
process/restart exercise, not elapsed years, independent owners or real links.

The report contains public currency/source commitments, export IDs, checks and
limitations. Node journals, contact files and other local state are not public
outputs. All signing seeds inside the campaign are deliberately public fixtures:
authority 1; initial validators 2–5, 22–25 and 42–45; new Earth validators 62–65; local owners/miner 10–14. All normal checkpoints use persisted native signer agents; the helper retains latest heads outside their directories. Adversarial conflict injection deliberately bypasses those agents with public fixture keys.

## Default network-node startup

After verifying and initializing a fixture ledger, ordinary startup enables
signed discovery and bounded relay in the same process lifecycle:

```sh
/absolute/rld-regional-ledger-candidate --dir /absolute/ledger --authority AUTHORITY_HEX --currency CURRENCY_HEX
```

A persistent, separate transport identity and queue are initialized or recovered
in the ledger's `transport/` directory. Without real neighbors the node waits;
there is no invented route, central registration or automatic mining reward.
Add authenticated adjacent contacts to `transport/config.json`, then
restart the same node. Alternatively provide `--mesh-config /absolute/config.json`.
Only local adjacent contacts are configured; distant routes are learned through
signed advertisements. A wallet-only client is not a full relay node.

Use `--transport-python /absolute/python` with the dependencies in
`tools/interstellar-mesh-requirements.txt`. The Rust launcher replaces itself
with the bounded Python contact runtime; native Rust replays and validates every
ledger application. Both sources must remain available in the build checkout.
`contact-node` remains a compatible explicit alias, but is not required.

Relay service requires no miner or signing key. An explicitly supplied
`--miner PUBLIC_KEY` additionally enables local import block production after
native evidence validation. Without it verified evidence stays pending until a
local block producer fulfills it; storage acknowledgments never credit value.
Normal checkpoints still require separately authorized native signer agents.

Each eligible neighboring path can carry the same signed packet ID, within
per-contact batch/byte bounds and signed hop limits. Permanent packet/import
deduplication preserves value when paths converge. New useful contacts can
extend reach or survive one relay loss; extra identities alone do not establish
consensus security. Full storage refuses new custody and retains existing data.
Default limits are 16 adjacent contacts, 64 learned nodes, 256 retained transport
messages/receipts, 64 MiB state, 16 hops and four application attempts per poll.
Qualified physical adapters, contact capacity and independent security qualification
remain separate gates.

## TLS 1.3 IPv4 ground contacts

Normal startup also opens a loopback listener on an automatically assigned port.
This listener and its outgoing TCP contacts now use TLS 1.3 by default; no
plaintext or older TLS fallback is attempted. The status includes its public
certificate SHA-256 and validity deadline. Independently exchange and pin both
the mesh identity and certificate hash for every adjacent peer before sending.
Use `--mesh-listen 127.0.0.1:PORT` for a stable local endpoint, or explicitly bind
an available IPv4 interface for an operator-configured network. No firewall,
public exposure or NAT traversal is configured automatically. Configure each
adjacent endpoint and independently pin its transport identity on both sides:

```json
{"contacts":[{"host":"127.0.0.1","peer":"PINNED_NEIGHBOR_NODE_HEX","port":39001,"tls_cert_sha256":"PINNED_CERTIFICATE_SHA256"}],"format":"RLD-CONTACT-MESH-V2","network":"CURRENCY_HEX","state":"/absolute/private/mesh"}
```

Addresses are literal IPv4 and ports are integers; no DNS, URLs or endpoints from
remote advertisements are followed. `tools/interstellar_tcp.py` uses bounded
length-prefixed canonical signed exchanges inside TLS. A signed fresh server
challenge authenticates its mesh identity and binds this connection. Each request
names its recipient, that challenge and a fresh client nonce; the signed reply
binds both nonces and the exact exchange hash. A captured request cannot be
replayed on a new connection to obtain returned evidence. Custody is
acknowledged only after complete verification and durable storage. A failed or
lost reply keeps the source evidence; duplicate delivery stays idempotent. Socket
waits hold no mesh lock. Persistent batch rotation gives later queued evidence a
turn even when early deliveries fail. Native Rust still determines every credit.

TLS uses a separate Ed25519 key and self-signed certificate committed together in
one owner-only, fsynced `tcp-tls.private.pem`; it never uses a wallet/finality key.
Certificate authentication checks the independently configured exact DER hash,
the exact mesh identity/network, self-signature and validity. Public CA/hostname
trust is not used. The signed connection challenge and request authenticate the
mesh peers after TLS; this is not TLS client-certificate authentication. Damaged,
symlinked, overly permissive or mismatched private material is retained and
refused. Restart preserves the certificate and key. New certificates last 90
days under the ground operator's UTC clock; expiry blocks new contacts, retaining
evidence and balances. Rotation, changed pins and recovery need independently
verified operator action; no silent trust update is performed. This policy does
not qualify stellar cryptographic horizons or delayed revocation.

At most two inbound workers and four outbound contacts per tick are admitted.
The outer wire frame is at most 20 MiB plus 4,096 bytes; its exchange remains
within 20 MiB. A three-second local attempt bounds ground connection waits;
it neither expires evidence nor refunds exports and is not a stellar RTT limit.
Local contact observations are process-local history, separate from advertised
routes, destination custody, native acceptance and spendability.

```sh
python3 -m unittest discover -s tools -p 'test_interstellar_*.py' -v
python3 tools/regional_contact_campaign.py --binary "$PWD/tools/regional-ledger/target/debug/rld-regional-ledger-candidate" --root /absolute/NEW-tcp-fixture --report /absolute/NEW-tcp-report.json --adapter tcp
```

The TCP campaign uses three actual native processes and loopback sockets with no
shared contact spools. Earth disconnects only after actual neighboring custody;
remote native imports, local payment and onward export then proceed without it.
A new return waits for restored contact. This same-host duplex adapter is signed
and TLS encrypted. Cross-host operation, independent cryptographic review,
one-way/radio/BPv7 links, contact schedules, hostile availability and physical routes remain
unqualified. Directory contacts remain available; standalone mesh `run` only
pumps those directories, while the normal native lifecycle runs both adapters.
For an explicitly selected ground experiment only, `--mesh-insecure-tcp` uses a
plaintext listener with unpinned TCP contacts and still requires signed connection
challenges. Pinned contacts cannot be used in that mode. It is never a fallback.

The 24 actual-socket checks include a transparent wire proxy, wrong/missing pins,
TLS downgrade/plaintext refusal, cross-connection replay, expiry and private
material failure, alongside the earlier relay/queue checks. Python's
[TLS API](https://docs.python.org/3.11/library/ssl.html) and cryptography's
[certificate API](https://cryptography.io/en/50.0.1/x509/reference/) provide the
underlying ground transport primitives; their use is not an independent review.

## CLI

Every invocation requires `--dir`, `--authority` and the exact `--currency` root.
A currency root is checked against the caller's trusted authority and the exact
build's implementation commitment. Region names alone cannot authorize a ledger.

- `init --bootstrap FILE --region LABEL`: verify an offline signed package and
  create an empty store in a new absolute directory.
- `status`: independently replay persisted state and return identity, local
  coins, maturity heights, permanent import IDs, export dependencies and finality.
- `wallet-init --owner PUBLIC_KEY --wallet-dir DIR`: create a new private,
  separately locked wallet journal; retain its returned head outside that directory.
- `wallet-view --wallet-dir DIR --expected-wallet-head HEAD`: report verified
  ledger amounts, currently available funds, reserved inputs and retained signed
  commands. A stale wallet head is rejected rather than displayed as available money.
- `wallet-prepare --file REQUEST --wallet-dir DIR --expected-wallet-head HEAD`:
  select owned eligible, unreserved inputs, calculate explicit change and return
  an unsigned draft plus its separate review commitment and wallet head.
- `wallet-sign --file REVIEWED_DRAFT --review COMMITMENT --key-file PRIVATE_FILE --wallet-dir DIR --expected-wallet-head HEAD`:
  recheck the exact local journal, incidents and draft under the ledger lock, then
  sign and validate using the actual native command rules, then durably record
  the exact command and reserve its inputs before returning any signature.
  The response's `commands` array is for a block producer; signing does not mine.
  Persist the returned new wallet head separately. Exact response-loss retries
  return the retained signature and head without reading a key or signing again.
- `wallet-recover --intent ID --wallet-dir DIR --expected-wallet-head HEAD`:
  recover an exact retained signed command with its current local inclusion state.
- `wallet-combine --file CONTRIBUTIONS`: combine one independently retained
  approval per actual input owner for the exact same intent. Return a command
  only after complete native authorization and current eligibility checks;
  this operation neither reads private keys nor changes wallet or ledger state.
- `wallet-receipt --file EXPECTATION`: verify the exact currency, source,
  destination, export ID, recipient and net amount against local evidence/import
  history. Report pending evidence, immature import, spendable original output,
  spent original output or quarantine separately. A spent output does not undo
  the import; its new change/payment is shown by `wallet-view`.
- `mine --miner PUBLIC_KEY [--commands FILE]`: verify signed commands, search for
  real fixture PoW and atomically commit one block.
- `statement`: output the actual local history and checkpoint signing statement.
- `finalize --file FILE`: check the active era's four ordered signatures and install
  the exact local checkpoint. Signatures are obtained separately.
- `signer-init --signer-dir DIR --key PUBLIC_KEY`: create a separate locked signer
  journal; retain its returned head outside that directory.
- `sign-checkpoint --signer-dir DIR --key-file FILE --expected-lock HEAD`: persist
  the exact local signing lock before returning an approval and next head.
- `propose-epoch --validators FILE`: construct an unsigned handoff from the exact
  installed closing tip to a different ordered four-key set.
- `sign-handoff --signer-dir DIR --key-file FILE --expected-lock HEAD --file FILE`:
  persist consent and seal the old era; collect approvals from all old/new keys.
- `install-epoch --file FILE`: verify joint consent and install a durable era event.
- `signer-status --signer-dir DIR`: replay local signer state; the displayed head
  is not an independent monotonic rollback anchor.
- `incident --file FILE`: validate and retain an authenticated conflicting
  checkpoint pair without adopting either branch.
- `incidents`: export retained proofs for the next reachable neighbor.
- `recover-incident --file FILE`: restore exactly a guard/index-pinned proof;
  preserve damaged bytes and all quarantines.
- `proof`: output the retained signed checkpoint dependency archive; incident proofs are exported separately.
- `evidence --file FILE`: fully verify and atomically save an archive. This
  installs evidence only; it does not import value or alter local balances.

An authenticated conflict may be retained even while its accompanying value
archive is rejected; no value branch is adopted. At most 16 incident proofs are
retained separately. The persistent guard refuses restart when an observed proof
is missing or capacity prevents retaining it.

A proof archive's order is causal: previous checkpoints and import dependencies
must precede consumers. An incomplete or incompatible contact exchange is
rejected as a whole; the input file is never deleted. A later valid evidence
exchange may be supplied after the missing dependencies arrive.

## Local wallet interface

`wallet-app` is a wallet-only local client; ordinary full-node startup continues
its default relay lifecycle. It launches the supplemental Python bridge and
static browser UI, using native Rust for every view, review, signature, receipt,
combination and explicitly configured local block submission:

```sh
/absolute/rld-regional-ledger-candidate --dir /absolute/ledger --authority AUTHORITY_HEX --currency CURRENCY_HEX --transport-python /absolute/python wallet-app --wallet-dir /absolute/private-wallet --head-dir /absolute/separate-caller-head --owner OWNER_HEX --key-file /absolute/private-key.json
```

For an existing wallet, supply its separately retained latest
`--expected-wallet-head HEAD` on first client initialization. The caller-head
directory must be separate from the wallet directory. Optional `--miner PUBLIC_KEY`
explicitly enables ground local block submission; signing by itself never mines.
Without a key file the client is read-only for new signatures. Private fixture
key provisioning is separate; encrypted key creation, backup and hardware
custody are not implemented in this interface.

The startup URL contains a private, one-hour session capability in its fragment.
Use it only on this computer; the page immediately removes the fragment. No
external assets, browser key upload or arbitrary command/file-path API exists.
The server binds literal 127.0.0.1 only, checks the exact Host and POST Origin,
requires the capability, rejects duplicate JSON and framing fields, and sends
no-store/no-referrer/content-type/CSP protections. Input has a three-second
absolute read deadline and 2 MiB body bound; responses are at most 8 MiB.
One request is handled at a time; hostile local availability remains unqualified.
A new startup rotates the capability. Session/review expiry never deletes a
native signature, releases an input reservation or refunds an included export.

The page exposes available local and onward-export budgets after reservations,
immature and quarantined amounts, complete review of inputs/owners/refunds/fees,
local inclusion, recognized local export checkpoint and independently verified
recipient import/maturity. Known conflicts remain visible. Discovery, candidate
routes and custody are displayed as separate historical transport observations;
a saved process report is not proof of current liveness or destination credit.
Group proposals and individual signatures can be carried as bounded JSON files.
The client supports interactive proposal construction, separate owner review,
signature recovery and complete combination. Load 2-16 exact participant keys,
select up to 16 current native inputs and explicitly allocate every local payment
and refund. Peer private reservations are unknown. Amounts must balance exactly;
there is no automatic group change. Download the unsigned proposal from its
review screen; each owner independently imports and reviews it before signing.

`RLD-REGIONAL-GROUP-PROPOSAL-V1` binds the currency, region, exact intent ID and
full request, including one absolute `valid_through` height. Later owners preserve
that height instead of extending expiry or signing a different intent as the
local chain advances. A stale selection requires reloading inputs; a proposal
whose fixed expiry is past, altered or more than 32 local blocks ahead is refused.
`wallet-coins --owner SORTED_OWNER_HEX...` reads only public native ledger
ownership/eligibility; it opens no peer wallet and infers no peer reservations.

Before a clicked signing operation, the client durably saves its exact pending
review. After native signature persistence, it advances its separately retained
caller head before releasing the response. On restart, native `wallet-sign
--recover-only` can return an exact existing approval but cannot first-sign,
even with a key file supplied. If no new approval exists and native replay proves
the old head unchanged, the pending review is cleared and a new explicit review
is required. Ambiguity, corruption and persistence failure preserve records and
refuse further signing until reconciliation. A surviving client head rejects an
old wallet backup. Rolling back all local state together, cross-device coordination,
independent monotonic anchors, encrypted custody and reorganization remain unqualified.

## Wallet request and review

The current native wallet interface is a verified command layer with persisted
signed-intent reservations; the complete wallet UI, device recovery and external rollback
protection remain mandatory work. Single-owner requests select their own inputs
and automatic change; group requests use independent owner reviews and signatures.
Amounts below are integer runlai strings, never floating point or RLD decimals.

```json
{"owner":"OWNER_PUBLIC_KEY","inputs":null,"outputs":[{"owner":"RECIPIENT_PUBLIC_KEY","amount":"30"}],"remote":null,"fee":"1","valid_for_blocks":8}
```

For a remote payment, `remote` is
`{"destination":"EXACT_ADMITTED_REGION_ID","recipient":{"owner":"RECIPIENT_PUBLIC_KEY","amount":"80"},"destination_fee":"2"}`.
The remote amount is the gross source debit; the destination recipient gets
gross minus destination fee. Local fee, explicit outputs and change also count
in source conservation. Only finalized, mature, unaffected inputs are selected
for export; local spending does not require finality of already mature outputs.
Optional `inputs` permits at most 16 ordered unique IDs owned by this wallet.

Save the exact `wallet-prepare` response for review. The response exposes the
intent ID, input total, change, recipients, fees, domains and a local state pin.
Retain the displayed `review_commitment` separately and pass it to `wallet-sign`.
Do not derive approval from an untrusted replacement draft. Any ledger, evidence,
epoch or incident change requires a new preparation and review. A private key file
has shape `{"secret_key":"64_HEX_SEED"}` and owner-only file permissions;
symlinked, public-readable and mismatched keys are rejected. Keys never appear
in drafts or signed commands. The node revalidates commands again at inclusion.
No remote endpoint or returned transport receipt is required for local signing.

For a group, add `participants` containing all 2–16 actual input owners in
strictly sorted order, and explicitly name 1–16 sorted, unique input IDs and
every local payment/refund output. Their exact total must equal local outputs,
local fee and any gross remote payment. No automatic group change is assigned
to one participant. Each owner uses their own `owner` request value, wallet
directory, separately retained latest wallet head and private key; all other
intent fields must agree. The draft displays each input's native owner and
amount, all recipients/refunds, fees, domains and expiry for independent review.

Each `wallet-sign` durably retains only that owner's partial approval and reserves
only their inputs. Its `required_owners` lists the actual owner set;
`retained_approvals_complete=false` describes this wallet's retained partial
command, including after a combined command is included. It does not report
whether other owners have signed elsewhere. A partial command cannot form or
enter a block. Recover each owner's contribution without a private key using
`wallet-recover`, collect the single command from each response into a JSON
array, and pass it to `wallet-combine`. The combiner rejects missing, duplicate,
foreign, forged or differing intent approvals, and rechecks native eligibility
including expiry, spent inputs and quarantine. Returned `complete_owner_authorization`
means current native command authorization; inclusion still requires a block.

If a peer input is consumed by another local command, the whole old group intent
becomes impossible and each wallet releases its own still-unspent reservation.
Only native pre-inclusion expiry also frees unincluded reservations; signatures
remain retained. Inclusion releases reservations without refunding any remote
debit. Restarts replay actual input ownership and amounts at each retained
signing observation, preserving review descriptions after inputs are spent.
This is append-only fixture recovery; reorganization, cross-device custody,
independent rollback protection and complete wallet UI remain unqualified.

Receipt expectations have shape
`{"currency":"CURRENCY_ID","source":"SOURCE_REGION_ID","destination":"LOCAL_REGION_ID","export":"EXPORT_ID","recipient":"RECIPIENT_PUBLIC_KEY","net_amount":"78"}`.
Missing independently verified evidence returns an error; a transport receipt
alone cannot create a wallet credit. Local maturity and onward-export finality
remain separate. These local observations are not external monotonic anchors;
restoring all node state can still defeat local rollback detection.

## Pending commands and recovery

Every wallet operation checks the caller's separately retained latest wallet
head. The native CLI takes the ledger lock before the wallet lock. A reviewed
signature is saved with its command, inputs, observation and predecessor head
using private files, fsync and atomic replacement before release. Reopening
recovers a complete interrupted replacement only when it is one exact verified
extension; partial or incompatible bytes remain preserved and fail closed.
An exact lost-response retry or `wallet-recover` uses the retained signature.

`available` excludes inputs of `SIGNED_PENDING_INCLUSION` commands; `ledger.spendable`
is the raw verified ledger amount and is not the wallet's new-payment budget.
Local inclusion changes the record to `INCLUDED_IN_LOCAL_LEDGER`. If another local
command consumes an input, the old command can no longer execute and becomes
`INPUTS_CONSUMED_BY_OTHER_LOCAL_COMMAND`. Only an unincluded command whose next
possible local block is beyond `valid_through` becomes `EXPIRED_BEFORE_INCLUSION`.
The chain head must be at least `valid_through`; wall time, courier deletion,
transport receipts and remote silence never release a reservation.

This expiry applies to an owner command not yet debited into the ledger. An
already included export remains deducted forever under these rules; releasing
its wallet reservation neither refunds the export nor recreates any input.
Native inclusion still rechecks unspent inputs, signatures and height expiry.
All signed records remain retained, including included and expired commands.
At 128 records or 8 MiB the wallet refuses new signatures rather than pruning.

A surviving latest wallet head rejects a restored older wallet directory.
Retained creation/signing observations also reject older/forked node prefixes,
era/finality regression and disappearance of incidents observed at those points.
Read-only queries do not themselves persist new observation anchors. Joint
rollback of the wallet, ledger and every external head, copied-key bypass and
independent monotonic/device recovery remain unqualified. These rules rely on
the candidate's append-only local chain; they do not qualify future fork choice.

## Rules and limits

See [the frozen candidate specification](../../docs/research/REGIONAL_LEDGER_CANDIDATE_V1.md).
The fixture campaign issues 300 **runlai units**, not 300 RLD, in three origin
rewards after a zero-allocation genesis. Every other region issues zero.
Split/merge, multiple-owner inputs, explicit change and both local and destination
fees are integer-only. Export inputs require locally finalized creation history;
imported assets require local maturity and finality before onward export. A
return is a new export and import, with a new ID; no timeout or receipt refund
exists. Fees become explicit local outputs and never disappear from accounting.

Per store: 256 blocks, 64 retained snapshots, 4,096 coins/exports/import IDs and
8 MiB journal/evidence; per block 16 commands, per spend 16 inputs/outputs.
Limits reject new work and retain accepted evidence. There is no pruning.

The published revision-18 native prefix candidate removes repeated value execution
of an already completely verified exact checkpoint prefix. Its process-local
verified ledger is pinned to the exact currency and complete admission trust set;
incoming signatures, full prefix byte comparison, epoch/BFT predecessor checks
and execution of every new block remain mandatory. Cold replay reconstructs that
ledger from genesis; no serialized ledger cache or snapshot balance authorizes
value. Block acceptance stages the prospective anchor and complete new ledger
before mutation, so an invalid tail never advances finality. Preparing epoch
registry changes does not clone every retained value archive.

This is groundwork for layered long-term history, not a capacity increase:
256 blocks, 64 snapshots and existing byte/coin/dependency bounds still apply.
Crossing the first 200,000-block era, bounded active history with complete durable
archives, permanent import commitments, external latest-state protection and
independent recovery remain required. Native source changes alter the signed
implementation identity; use a fresh fixture genesis/currency, never old value.
The public revision-17 source and its observed reports remain unchanged.

The append-only chain has fixed cheap fixture PoW (one leading zero hash byte),
no timestamps, fork-choice or retargeting. Default node startup now enables the supplemental contact service. Four public
keys sign a monotonic checkpoint; separately locked signing agents persist before
releasing signatures and require caller-retained latest heads. Joint four-old plus
four-new handoffs fence validator eras without changing balances. There are no
BFT view changes or missing-signer liveness guarantees. Authenticated forks,
incompatible joint handoffs and old-era certificates past a closing fence are
durably retained and quarantine new related operations. Repair never unfreezes.
Consensus incident resolution, independent recovery/custody, channels, live wallet,
qualified real adapters, radio/BPv7 integration, independent archives and crypto
algorithm eras remain open. A surviving external latest signer head detects stale
signer backups; restoring all heads/state together or bypassing agents with copied
keys defeats that protection. An old complete ledger journal still replays as old
state without an external latest-state anchor. At most 16 validator handoffs and
128 signer requests are retained. See the new specification for exact assumptions.
Fsync/rename and an exclusive OS lock protect local commits, not hostile local
filesystem writers or arbitrary storage hardware. These remaining gates cannot
be replaced by the campaign's successful result.

## Encrypted keys and complete owner backup

Use a private absolute parent directory (owned, mode 0700). Every command below
also needs the existing `--dir LEDGER --authority AUTHORITY --currency CURRENCY`
global pins. Passwords are read from an echo-free local terminal, never arguments
or environment. For private automation, `--passphrase-stdin` reads exact UTF-8
bytes (12–1024, without newline/controls) from a bounded pipe. Never echo a real
password in a shell command or place private files in a publication directory.

```sh
rld-regional-ledger-candidate GLOBAL_PINS wallet-key-create --output /private/owner.enc.json
rld-regional-ledger-candidate GLOBAL_PINS wallet-init --owner RETURNED_PUBLIC_KEY --wallet-dir /private/wallet
rld-regional-ledger-candidate GLOBAL_PINS wallet-app --wallet-dir /private/wallet --head-dir /private/caller-head --owner PUBLIC_KEY --expected-wallet-head LATEST_HEAD --encrypted-key /private/owner.enc.json --backup-dir /private/backups
rld-regional-ledger-candidate GLOBAL_PINS wallet-backup --wallet-dir /private/wallet --expected-wallet-head LATEST_HEAD --encrypted-key /private/owner.enc.json --output /private/backups/new.enc.json
rld-regional-ledger-candidate GLOBAL_PINS wallet-restore --file /private/backups/new.enc.json --wallet-dir /private/NEW-wallet --expected-wallet-head SEPARATELY_RETAINED_LATEST_HEAD
```

`GLOBAL_PINS` is a placeholder for the three explicit global options above,
not a shell variable or implicit trust source. Creation returns only the pinned
currency/region/new public owner and never issues or funds assets. New signing
uses `wallet-sign --encrypted-key ...`; explicit legacy `--key-file` remains for
public fixtures and has no automatic fallback. `--recover-only` and exact stored
retries never unlock/read a key or first-sign. The wallet-app unlock requires a
local terminal; HTTP never accepts a passphrase/key/backup path.

The versioned envelope authenticates purpose, currency/region/owner, algorithm,
KDF parameters, salt and nonce. Fixed Argon2id v19 (64 MiB, t=3, p=4, 32-byte key,
16-byte random salt) follows the second configuration in
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html); AES-256-GCM uses random
12-byte nonces and 16-byte tags. Seeds, derived keys, plaintext buffers and KDF
memory use zeroization; AES key schedules enable zeroization. This does not
prove runtime/OS memory erasure, password entropy or independent security.

Backup includes the key, complete validated private owner journal, exact head
and current native history/finality/era/incident observation. Restoring requires
a **separately retained latest head**, compatible native replay and a fresh
wallet directory. It preserves original creation/history, partial consent and
only-owned reservations, writes `key.enc.json`, and refuses overwrite. It does
not restore/replace a caller-head directory or approve unresolved clicked
pending operations. A remaining `RESTORING` marker forbids opening/signing; keep
that failed target and restore the original backup into another fresh directory.
Encrypted files require owned private parent/file permissions, no symlinks or
multiple hardlinks, and bounded size. Every successful new signature needs an
updated backup and latest head; the UI clears its prior backup result on change.

A copied key plus rollback of all journals/heads remains unqualified. Hardware
custody, independent anti-rollback/security review, reorganization/cross-device
recovery, a complete sustained wallet product and stellar crypto remain required.
No real asset migration or I1–I12 completion is claimed. Reproduce the ground
CLI/HTTP checks with `python -m unittest discover -s tools -p test_regional_wallet_custody.py`; the bundled
transport Python/dependencies are still required.

## Explicitly admitted BFT ground profile

`contact-fixture bootstrap --bft` creates fresh no-value fixture admissions with
`RLD-REGIONAL-BFT-FIXTURE-V1` rules. This does not lower legacy unanimous quorum
or upgrade an adopted currency. Four equal validators use three distinct ordered
prepare votes and three matching commit votes for each next native block.
Signers retain prepared-QC locks before releasing commits. Certified timeouts
carry highest prepared values into deterministic next-round proposals.
Uncertified direct blocks are refused; blocks and finality install atomically.

The CLI workflow is `bft-init` (at genesis, each private signer separately),
`bft-candidate`, leader `bft-sign` Propose, each validator `bft-sign` Prepare,
`bft-quorum`, each validator `bft-sign` Commit, `bft-quorum`, `bft-certify`, and
`finalize --file`. Retain every returned signer head outside its journal and
pass `--expected-head` on each request. `--recover-only` cannot first-sign.
Old journal backups with surviving latest heads fail; rollback of all state,
heads and keys is not qualified. `bft-timeout-certificate` requires three signed
timeouts for the immediately prior round. Prepare/commit phase substitution,
minority, duplicate identities, changed values and old rounds cannot authorize
new votes. No time or receipt refunds are introduced.

Run the actual-process campaign using the Python transport dependencies:

```sh
python3 tools/regional_bft_campaign.py --binary tools/regional-ledger/target/debug/rld-regional-ledger-candidate --root /private/fresh-bft-fixture --report /private/sanitized-bft-report.json
python3 -m unittest discover -s tools -p 'test_regional_bft.py'
```

The campaign uses four stores/signers per region and a same-host controller
message bus, not an autonomous consensus network. Three actual voter processes
make progress with the initial leader offline, an offline replica catches up,
and real reviewed wallet payments import/mature under destination BFT finality.
Remote onward execution requires no Earth calls. Count one canonical history
per region in conservation, never replica copies. Native contact carriage can
store verified pending evidence without a miner; import commands still require
local BFT votes. Normal contact `--miner` cannot bypass those votes.

Automatic pacemaking, validator network gossip, independent custody, sustained
fault/partition recovery and BFT reconfiguration remain mandatory work. BFT epoch
proposal, installation and offline era-proof verification currently refuse
legacy joint handoff, including complete valid old/new signatures.
The candidate retains bounded rounds/journals/checkpoints. Keep all signer,
replica, key, caller-head and transport state private; publish only sanitized
reports and exact named source. See the [current regional finality specification](../../docs/research/REGIONAL_SIGNER_EPOCHS_V1.md).

## Revision 14: autonomous admitted-validator ground runtime

An ordinary fixture node still starts its relay. An explicitly admitted BFT
validator can additionally supply `--bft-config /private/validator.json` to the
same native startup command (or `contact-node`). The Python companion schedules
proposals, prepare/commit votes, signed timeouts and certified view changes;
every signature, quorum, proposal, block and incoming proof is independently
validated by native Rust. An ordinary relay or advertised region never gains
validator authority. This is a bounded same-host ground candidate, not an
adopted-network upgrade or qualified interstellar service.

Initialize `bft-init` separately and retain its returned latest head outside
signer, runtime and ledger backups. The private configuration has exact fields:

```json
{
  "format": "RLD-REGIONAL-BFT-NODE-V1",
  "state": "/private/runtime",
  "signer_dir": "/private/signer",
  "head_file": "/private/independent-head/head.json",
  "key_file": "/private/validator-key.json",
  "key": "ADMITTED_PUBLIC_KEY",
  "miner": "REWARD_PUBLIC_OWNER",
  "validators": [{"key": "SORTED_ADMITTED_KEY", "node_id": "PINNED_MESH_ID"}],
  "block_interval": 1,
  "round_timeout": 20,
  "stop_height": 5
}
```

The displayed strings are placeholders, and `validators` must contain all four
actual admitted keys in native order with four distinct configured mesh IDs.
Head-file schema is `{format,binding:{currency,region,key},head,pending:null,
outbox:null}` with the actual pinned currency/region/key and native returned
head. Files are owned, private, bounded, regular and without symlinks/hardlinks.
The head parent, signer and runtime directories require private permissions.
Head-directory and runtime locks prevent concurrent companion instances.
Configuring identity does not discover an endpoint: the mesh configuration still
explicitly pins IPv4 neighbors, carrier identities and TLS certificates.

The runtime persists exact caller requests before native signing and advances
the caller head before response release. Restart recovers only retained native
responses, never first-signs a pending request, and reconstructs public messages
from the validated native signer journal. Missing private keys disable new
signatures but permit authenticated carriage and certified catch-up. A delayed
complete certificate for the current parent remains eligible after a local
timeout. Native preparation locks and exact parent/value verification still
apply. Successful local phase persistence grants propagation time; arbitrary
peer traffic cannot renew the timer. Local timers are ground scheduling choices,
not refunds, remote freshness, physical RTT or a global progress promise.

`bft-submit --file SIGNED_COMMAND_ARRAY` durably queues one to four already signed
commands without ledger debit or block inclusion. The runtime reads bounded
native JSON, validates it natively, and packs canonical mesh bytes. Up to four
commands can enter a native candidate; stale commands remain retained without
rewriting signatures, intent or expiry. Incoming exports are native-validated
pending imports, not credits granted by carriage. `bft-network-check` validates
a typed envelope without changing ledger state; `bft-sync` installs only the
sequential certified native prefix; `bft-retained-messages` reads public signed
responses without first-signing.

The `regional-bft` control frame uses the same exact source/destination region.
Its legacy outer `export_id` field is only the SHA-256 of its payload, not a
monetary export. Mesh currency, configured region and independently certified
parent must match before native consensus consumption. Other payment frame
kinds retain their cross-region constraints. Only verified connection-bound
next-hop custody suppresses duplicate transits in an ephemeral bounded cache.
Source evidence stays durable; every 64 attempts, restart or cache saturation
forgets suppression and permits retransmission. Lost/refused replies or failed
local response custody do not suppress retries or become destination receipts.

Limits remain explicit: 32 native submissions, 512 companion messages/32 MiB,
3 MiB per control payload, four outbound enqueue operations per tick selected only from unsent message/recipient pairs (already queued archive messages do not consume that batch), 128 native
signer records, 32 rounds per slot and the existing mesh/native archival limits.
`stop_height` (0–64) is an explicit fixture signing pause, not a network stop or
permission to prune prior evidence; relay/catch-up continue. Capacity refusal
preserves prior evidence and funds. Full BFT epoch handoff remains refused.
Sustained faults, cross-region autonomous end-to-end value, independent
operators/custody, external monotonic anchors, real adapters and long-term
cryptography/storage qualification remain mandatory.

Reproduce without a controller producing votes or installing checkpoints:

```sh
python3 tools/regional_bft_network_campaign.py --binary /absolute/rld-regional-ledger-candidate --root /private/NEW-ground-fixture --report /public/sanitized-report.json
```

The fixture controller starts/stops nodes, submits a reviewed signed payment and
observes actual native state. Its private fixture root must never be published.

## Three-region autonomous campaign and scoped carriage

The current candidate uses `RLD-CONTACT-MESH-V2` / `RLD-CONTACT-TCP-V3`.
Source-signed receipt-routing certificates bind source, destination, packet and
frame; destination receipts carry that exact certificate. Authenticated neighbor
packet inventories request relevant receipts, while candidate return routes
allow asymmetric carriers without the original packet. Unrelated receipts are
not broadcast to every region. Inventories and receipts grant no ledger rights.
Old V1 private identities, configurations and retained mesh states are refused,
never rewritten or silently migrated. Create new private fixture transport
directories and independently exchange new identity/certificate pins, retaining
old states and software for verification. This does not migrate monetary assets.
All original resource bounds and durable refusal behavior remain in place.

Opening an unchanged mesh archive still validates retained routes, receipts,
ownership and bounds, but does not rewrite its file. Transit verification can
reuse at most 512 volatile witnesses for exact canonical bytes already fully
authenticated in this process. The key also binds network, contact sender and
recipient, format/domain and frame/hop limits. Changed bytes, changed limits,
eviction or process restart require full signature and frame validation again.
Only immutable visited-node tuples are cached, never keys, frames, native value
acceptance, mutable results or an unchecked archive. Certificates and contact
freshness are independently checked. An exact
repeated exchange is fully authenticated and explicitly syncs the retained file
and directory before custody acknowledgment; sync failure refuses custody.
Changed exchanges still use atomic durable replacement. This avoids spending
bounded contact time rewriting large unchanged archives and does not cache an
unchecked state, bypass verification, prune proofs or authorize a payment.

`contact-export` selects the earliest retained certified local history containing
the exact permanent export, and includes its independently verified dependency
closure: certified parents, block anchors, imported ancestry and epoch closings.
Duplicate retained checkpoints appear once in carriage; the native journal is
not pruned. Unrelated later history does not generate another transport frame.
Current authenticated incidents remain included, so a new known fault can still
change the frame and propagate quarantine rather than being hidden by caching.

A signing cap of zero starts a region as a relay and proof verifier at genesis.
It does not produce a proposal or vote, but can still install independently
certified catch-up. The three-region campaign uses twelve ordinary native
processes, adjacent pinned TLS gateways, actual owner-signed submissions and
explicit local signing caps. The controller refuses commands that sign votes,
construct certificates, apply carried proofs or install checkpoints:

```sh
python3 tools/regional_bft_multiregion_campaign.py --binary /absolute/rld-regional-ledger-candidate --root /private/NEW-three-region-fixture --report /public/sanitized-report.json
```

The requested trajectory is Earth → Proxima → Andromeda → Earth. All Earth
processes stop during remote import, maturity, onward payment and new return
export; a separately retained observation permits conservation checks without
querying Earth. Earth resumes as a relay before signing its new return import.
Receipt, import, maturity, original debit and new return ID are checked separately.
This command is an executable verification campaign, not a claim that a terminal
run has passed. Only its completed report proves the specific observed ground run.
Long-term liveness, independent custody/operators, full BFT handoff, physical
routes, archival/cryptographic horizons and exact production adoption remain open.

### Private native ledger images and fresh-target recovery candidate

`history-archive` seals the native ledger under its OS lock into a fresh private
`RLD-NATIVE-HISTORY-ARCHIVE-V1` directory. It carries the manifest, all retained
history objects (including unaccepted residue), complete authenticated incidents,
the incident guard and bounded damaged-incident residue. It refuses unresolved
`journal.next` rather than deleting it. Private keys, signer/replica journals,
wallets, caller heads/pending reviews, TLS and transport state are excluded.

```text
rld-regional-ledger-candidate --dir /absolute/private-node --authority PUBLIC_AUTHORITY --currency FIXTURE_CURRENCY history-archive --archive /absolute/new-private-image --expected-head SEPARATELY_RETAINED_LATEST_HISTORY_HEAD
rld-regional-ledger-candidate --dir /absolute/new-private-node --authority PUBLIC_AUTHORITY --currency FIXTURE_CURRENCY history-restore --archive /absolute/private-image --expected-head SEPARATELY_RETAINED_LATEST_HISTORY_HEAD
```

The exact latest head must survive outside the image's rollback domain. Restore
authenticates inventory and fully replays native currency, finality, ownership,
value, import identity and incident evidence before creating its fresh target,
then verifies the complete copied image again before clearing `RESTORING`.
Files are created privately and synchronized; existing or interrupted targets
are retained unchanged and refuse normal startup and incident recovery. No merge,
resume, signer or wallet custody restoration is offered. An archive digest is
an integrity observation, never signing authority or independent freshness.

History remains bounded at 4096 retained files / 256 MiB; each incident and
damaged-residue set is bounded at 16 files of at most 8 MiB. The complete image
also counts its manifest and guard, with an aggregate ceiling of 520 MiB + 32
bytes and 4130 retained files. Logical replay still refuses above 8 MiB, 256
blocks or 64 snapshots. All-head/image rollback, power-loss faults, copied-key
custody, independent operation and long-history qualification remain open.

Normal native creation now writes a compact `RLD-NATIVE-HISTORY-MANIFEST-V1`
`journal.json`. Its `history/` directory retains exact, immutable typed objects
for complete snapshots, epoch proofs and contact records, plus sixteen-event
pages. Page offsets, local height ranges and predecessor hashes are checked.
Cold open reconstructs the exact canonical journal and runs normal native
currency, finality, owner consent, value, permanent-import and incident checks.
Hash agreement never grants authority. Actual incident proofs remain in the
existing durable incident archive, committed by their exact native identities.

```sh
rld-regional-ledger-candidate --dir /absolute/private-node --authority PUBLIC_AUTHORITY --currency FIXTURE_CURRENCY history-head
rld-regional-ledger-candidate --dir /absolute/private-node --authority PUBLIC_AUTHORITY --currency FIXTURE_CURRENCY history-check --expected-head SEPARATELY_RETAINED_LATEST_HISTORY_HEAD
```

Retain the latest head separately before depending on it for rollback detection.
The pinned check acquires the native lock and refuses a different head or pending
incident before reconciliation. A current head query is a native observation,
not independent freshness. The ordinary unpinned open retains existing incident
recovery behavior. Neither command replaces signer/caller or wallet heads.

Every immutable object is durable before the manifest is replaced. Exact repeated
objects are fsynced again. Failed publication residue and prior partial-tail
objects remain retained; unreferenced bytes do not advance a ledger. All files
count toward the 4,096-file / 256-MiB ground archive bound. Missing, changed,
noncanonical, incorrectly scoped, oversized or unsafe files refuse. There is no
pruning or fallback to an inline journal. Use fresh fixture directories and new
signed fixture genesis under the changed implementation, never previous value.

The logical 8-MiB, 256-block / 64-snapshot and permanent ledger index limits
remain unchanged. Long-history execution, compact remote evidence, independently
retained latest roots and the 200,000-block-era acceptance are still required.
The image commands above implement only bounded ledger recovery. This changed
candidate cannot inherit revision-20 cycle/fault results.

Pinned checks also require every authenticated retained incident to appear in the manifest index. An extra unindexed incident refuses before reconciliation; its proof is retained and cannot be hidden by a passing storage head.

The 4130-file / (520 MiB + 32 byte) ceiling counts retained native payload
(manifest, guard, history, incidents and damaged residue). The separate canonical
archive index is bounded at 8 MiB; locks and filesystem directory metadata are
not included in the reported retained-native byte count. This clarification
does not change native limits or the frozen source used by the running campaign.

### Native disk checkpoint prefix sharing (V2 candidate)

Normal creation now uses `RLD-NATIVE-HISTORY-MANIFEST-V2` and
`RLD-NATIVE-HISTORY-OBJECT-V2`. A later checkpoint may store only its new blocks
and certificate/era metadata plus the exact digest and byte length of its
earlier listed predecessor object. Reading reconstructs the complete original
Snapshot and Journal before normal native authentication. Prefixes cannot use
orphans, forward references, another region/currency, mismatched lengths or
heights. Expanded complete snapshot bytes must fit the declared logical
journal budget; hashes never grant value authority. Every old object remains
retained and counts against the unchanged 4096-file/256-MiB history capacity.

Full signed transport snapshots, native 8-MiB/256-block/64-checkpoint bounds,
permanent import records and private archive recovery rules remain unchanged.
This changed implementation requires a new signed no-value fixture genesis;
V1 private stores refuse unchanged. No adopted upgrade or old-value migration.
The disk improvement is not compact remote proof or long-history qualification.

### Native checkpoint-prefix transport candidate

`RLD-REGIONAL-CONTACT-V2` and `RLD-REGIONAL-BFT-NETWORK-V2` carry an evidence
list of exact original certificates/era metadata and new block suffixes. Optional
prefixes name earlier checkpoints and their complete block count in the same
message. Native reconstruction refuses missing/forward/cross-domain/range
references and expanded-byte overflow, then full native replay authenticates
the original Evidence. No cache, digest, receipt or prefix grants value rights.

`bft-network-pack --file LOGICAL-ENVELOPE.json` checks a full typed logical V2
envelope and prints its compact wire form without signing, sync or debit.
`bft-network-check --file WIRE-ENVELOPE.json` expands and verifies the wire form,
returning full native-checked evidence for sync. Ordinary `proof` remains full
Evidence; BFT signed message/proposal/finality bodies remain complete. Rust
submission packing still requires typed verification, and enqueue never debits.

Original physical 3-MiB and native logical 8-MiB/256-block/64-checkpoint limits
remain. V1 payloads refuse without fallback; use fresh signed no-value fixtures
for the changed source and never migrate old/test balances. This phase shares
transport blocks but does not implement compact Merkle/state witnesses, extend
full native history/memory/index capacity or qualify long/independent/physical
operations. Final frozen source/lifecycle checks remain pending.

The next incompatible ground candidate uses `RLD-REGIONAL-STATE-COMMITMENT-V1` for native header/checkpoint state roots. Ordered coin/export/permanent-import indexes commit exact typed keys/records and entry counts, with separate leaf/branch/padding/empty domains and minted/received counters. `state-proof --checkpoint ID --collection coins|exports|imports --key HASH` constructs a bounded historical member/absence witness from the fully replayed certificate. `state-proof-check` also requires those caller-selected arguments and refuses missing native checkpoints, substituted queries, roots, paths, records and malformed adjacent ranges. No proof signs, imports, debits or declares a historical output currently spendable. Current incidents remain separate native checks. Full signed Evidence and full native replay are still mandatory; proof generation rebuilds bounded maps and is not incremental durable indexing or complete compact remote authorization. Fresh signed zero-allocation fixture genesis/currency is required, with no older candidate state/value migration. Current 256-block/64-checkpoint/8-MiB and 4,096-entry limits remain. Final frozen, process and new-cycle/fault qualification is pending.

## Bounded native stream replay groundwork

`RLD-NATIVE-STREAM-REPLAY-V1` is a separate read-only archive verifier. It starts
with the caller-pinned, fully authenticated fresh fixture genesis and executes
every block through the same owner/value kernel as ordinary native chains.
There is no deserializable cursor or cached-ledger starting point. Its rolling
history retains at most 256 height/tip/history commitments, while the complete
coin/export/permanent-import maps retain their existing 4,096-entry bounds.
Exact local certificate observations are bounded by 64 and require full native
snapshot verification plus the exact replayed prefix. A hash does not confer
finality, import, signing or spendability rights. Invalid tails stage all fallible
checks before changing the ledger, history or anchor.

`history-stream-check --bootstrap GENESIS.json --region earth --file PRIVATE.jsonl
--expected-head EXACT_HEAD` checks a separately retained exact replay head.
Records are tagged Evidence, Block or Finalize; evidence replacement carries a
complete bounded proof set and receives full native verification. A private,
singly linked regular file is required; each complete newline-terminated record
is bounded by 8 MiB and the archive by the existing 256 MiB archive ceiling.
The reader allocates at most one bounded record at a time and never writes to
or adopts a node store. RESTORING targets refuse before the command runs.

The profile explicitly requires an initial unanimous PoW region. Local epoch
handoff and BFT replay refuse rather than lowering admission rules. Ordinary
stores, snapshot construction, BFT, wallets, signers and the 256-block/64-snapshot
limits remain unchanged. Incidents/quarantine are NOT reconciled by this
archive format; its CLI reports that fact. Passing replay is not a recovered
live ledger, a fresh finality certificate, independent latest-state protection
or restored signing custody. All-state/head rollback remains unqualified.
The changed native source requires a new signed no-value genesis/currency and
never migrates older candidates or adopted value.

The initial focused sample replays 1,032 real blocks with 1,024 actual-owner
local payments, a delayed return import of net 59, permanent duplicate-import
refusal and exact cold replay while retaining only 256 observations. This is
bounded replay groundwork, not ordinary-node long-history operation: new
long-range checkpoint authority, incremental durable indexes, real issuance-era
recovery beyond 200,000 blocks, independent archives, cryptographic horizons
and physical/independent qualification remain open. Final frozen whole-native,
process, command-line and new-source lifecycle checks are pending.

## Signed bounded checkpoint segments (local candidate)

`RLD-REGIONAL-SEGMENTED-UNANIMOUS-FIXTURE-V1` is a new explicitly signed
Admission profile, retaining four exact ordered unanimous validator approvals.
It cannot reinterpret a legacy or BFT region, change their thresholds, or
perform local epoch handoff. A snapshot's optional `base` must equal its signed
Statement.previous. Each new segment contains at most 256 complete native blocks;
its first parent/height/anchor must extend that exact already fully verified
certificate. The initial segment executes from the signed zero-allocation genesis.
Later state is copied only from the process's private fully native-executed
predecessor under the exact currency/admission trust binding. It is never decoded
from a ledger cache, supplied by a sender, or authorized by a content hash alone.
Every suffix still checks owner consent, maturity, issuance/conservation, export
finality, permanent imports, command/state roots, work and incident authority.

Ordinary Chain template/accept/install now retain only the bounded unfinalized
segment after this profile's certificate installation. Signed blocks and proofs
remain in the durable native journal; clearing a replay window never deletes
native evidence. Legacy and BFT chains keep their original full-prefix/256-block
behavior. BFT prospective messages refuse a segmented base. Signer journals pin
the preceding exact signed terminal and new segment's first parent/height, with
separate caller heads and existing vote/byte limits. Wallet/recipient queries
read historical blocks from the already fully native-replayed local journal;
absolute historical heights never index the shorter active segment. Incident
comparison uses overlapping absolute heights, avoiding a false conflict between
different compatible segments. Neither ancestry headers nor signatures alone
prove a valid ledger; full native execution remains mandatory.

The ordinary Journal still retains its original total event and 8-MiB limits,
evidence still retains at most 64 snapshots, permanent maps at most 4,096
entries, and the archive all retained objects at most 4,096 files / 256 MiB.
This new finality/remote-value representation breaks the compulsory whole-prefix
certificate dependency; it does not solve the whole persistent journal limit,
BFT long history, incremental durable permanent indexes or 200,000-block-era
recovery. Native stream replay V1 remains a separate read-only legacy-profile
verifier and does not adopt this profile. Complete incident-aware storage,
independent latest-state protection, custody, physical routes and independent
operations remain separate requirements.

## Incremental state-root and record-proof computation candidate

The native V1 ordered state commitment and record-proof dialect are unchanged.
One private process-local witness retains exact typed leaves and Merkle levels.
Every invocation audits the supplied complete ledger and compares every current
record. A leaf is reused only for the exact collection/key/value, and a branch
only for the exact collection/depth/ordered child pair. Counters and counts come
from the current audited ledger. Changed maturity, dependencies, ownership,
export fields or import identities rehash their affected paths. No decoded
witness or hash supplies native value state, authorization or freshness.

A missing/evicted witness reconstructs fully; it is never serialized. Accounting
for retained canonical values, fixed entry overhead and hashes stays at most
8 MiB, independent of original ledger/proof bounds. Optional retention exhaustion
clears the witness and reconstructs the exact original commitment/proof, without
pruning or new acceptance. This accounting is not a measured peak-RSS guarantee;
current/native ledgers and transient preparation remain separate allocations.
`Commitment::from_ledger_uncached` supplies an independent full reconstruction.

Ordered insert/delete can shift most tree positions and still requires linear
work; this is not a sparse-tree or durable-index implementation. A 4,096-entry
synthetic single-record update uses one new leaf hash and twelve branch hashes,
versus 4,096 leaves/4,095 branches cold, with exact independent full roots.
That measures hashing work, not issuance, wall-clock speedup or long-history
qualification. All permanent maps, complete proofs, 64 checkpoints, event/archive
and existing transport bounds remain. The changed native implementation requires
new signed zero-allocation fixtures; prior source/private stores never migrate.
Focused six differential/refusal tests pass; final full native/process checks and
fresh source/lifecycle verification are pending for the final candidate source.

## BFT unanimous epoch activation candidate

`contact-fixture bootstrap --bft-epochs` signs the separate
`RLD-REGIONAL-BFT-UNANIMOUS-EPOCH-FIXTURE-V1` admission. Ordinary blocks retain
three distinct prepare and commit votes. Epoch activation requires four old
and four new signatures over the exact closing checkpoint and next validator
set. Old signatures must use `bft-sign` with `EpochFence`, the original BFT
signer directory and separately retained caller head; never use a new legacy
signer with an old key. `sign-handoff` supplies only fresh candidate approvals.
Install the complete certificate through `install-epoch`; this changes
validator authority without allocating or migrating value. Each new BFT signer
starts only at that exact native height/finality/epoch boundary, with a separate
retained caller head. All historically used validator keys refuse reactivation.

An old signer that has already proposed/prepared/committed or timed out beyond
the closing checkpoint cannot fence it. Stop ordinary scheduling before the
ceremony and inspect the retained heads; any released fence permanently stops
that journal even if another approval never arrives. Preserve partial
certificates, caller heads and old journals. Recovery returns only an exact
already signed response. Restarted old signers never resume votes. Partial
activation has no cancellation, unsealing, threshold reduction or timeout refund.
The ceremony and new signer configuration are explicit operations; individual
approval messages are not ordinary consensus-network envelopes.

This is an all-participant activation candidate, not fault-tolerant dynamic
membership or missing-signer liveness. Four replicas on one host/controller,
process interruptions and surviving local heads do not qualify independent
custody, all-state rollback protection, copied-key concurrency, power loss or
physical links. Legacy BFT and segmented profiles refuse activation unchanged.
New source requires fresh signed no-value genesis; old/adopted value never moves.

`tools/regional_bft_epoch_campaign.py --binary /absolute/native --root
/absolute/NEW-private-directory --report /absolute/report.json` exercises a
four-replica native CLI ceremony, actual owner payments before/after activation
and exact old response recovery. Its controller carries consensus messages;
this is separate from an autonomous multiregion or full fault profile.
Current full frozen qualification and publication remain pending.
