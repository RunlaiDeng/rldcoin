# Native loopback wallet server

The candidate's `wallet-app` command runs the application and HTTP server in
Rust, with the existing browser assets embedded and bound into the native source
identity. It preserves the command's wallet, caller-head, owner, miner, key,
backup and port options. The node's separate `--transport-python` option does
not select a wallet interpreter or fallback. Python application and proposal
algorithms remain independent test references.

The server binds literal `127.0.0.1`, including for an automatically selected
port. Its private startup response contains the browser URL with one ephemeral
capability in the fragment. Requests require the exact local Host; API calls
also require the exact Origin and capability, an unexpired one-hour session,
application/json and an absent or permitted same-origin fetch indication.
Capability comparison uses constant-time byte comparison. Duplicate critical
headers, transfer encoding, ambiguous lengths and duplicate JSON fields at any
depth refuse. Only the three embedded assets and `/api` are served. Responses
retain no-store, no-referrer, nosniff and restrictive content security policy.

One request is served per connection. Header bytes are bounded by 8 KiB,
API input by 2 MiB and response by the existing native 8 MiB limit. Socket input
and output each have one three-second total wait deadline. These wait deadlines
do not qualify a bound on complete native replay or local block production.
No ledger, wallet or caller operation lock is held while waiting for browser
input; the separate nonblocking app lock protects the application's lifetime.
Unix private-file ownership, permissions and no-follow handling remain required.

The existing API covers observations, wallet initialization, preparation,
explicit review signing/cancellation, retained response recovery, submission,
group proposal selection/build/review/combination, recipient receipts and
encrypted full-journal backup. Four retained reviews and four combinations each
expire after five minutes without extending a payment's original ledger expiry.
Preparation and cancellation grant no signature or input release. Every value
operation uses ordinary native history, incident, owner, finality and reservation
checks. Received receipts remain independently checked local observations.
Historical transport reports grant neither process-liveness nor value authority.

Signing durably retains the clicked review in the separate native caller store
before releasing a signature, then publishes the new caller head before the
response. Startup reconciles unsigned pending reviews against the unchanged
native head or recovers an exact already-retained native response without a key.
Unknown or changed custody refuses. Caller publication failure closes further
application operations until restart and full native revalidation; no error or
timeout releases reserved inputs.

Encrypted startup unlock requires an echo-free local terminal. No HTTP variant
accepts a passphrase, private key or filesystem path. The server retains an
unlocked passphrase in zeroizing memory, and backups use the configured private
directory and ordinary native complete-journal encryption. A shutdown signal
stops admission, allows an ongoing native operation to finish and releases
application locks; socket waiting never authorizes another operation after stop.

This candidate requires fresh signed no-value genesis and custody directories
after native source changes. Old balances, keys and failed stores never migrate.
Same-host restart and payment checks do not qualify power-loss, copied-key or
all-state rollback protection, independent custody, full fault profiles, long
history, physical links or mainnet acceptance. Node consensus scheduling and
contact transport remain separate migration work.
