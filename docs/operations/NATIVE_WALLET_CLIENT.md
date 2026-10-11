# Native wallet caller custody

The ground wallet UI delegates caller-state loading, publication and keyless
recovery calculation to `wallet-client-open`, `wallet-client-store` and
`wallet-client-reconcile`. Signing remains the ordinary native wallet operation.
These interfaces require explicit `--wallet-dir`, separate `--head-dir` and
`--owner`, with complete native currency/history and wallet-journal replay.
The [native wallet server](NATIVE_WALLET_HTTP.md) owns the lifetime app lock and
browser session. The Python application remains an independent test reference.

Caller state retains `RLD-REGIONAL-WALLET-APP-V1` and the existing exact fields:
`format`, `binding`, `head` and `pending`. The binding contains currency, region,
owner and the absolute wallet path. Sorted ASCII JSON preserves the Python
canonical encoding, including Unicode surrogate pairs in wallet paths. Duplicate,
unknown, noncanonical or mismatched typed fields refuse. Inputs and stored state
retain the 8 MiB bound; a transition input includes both complete prior and
proposed states within that same bound. There is no larger transport or history cap.

The caller directory uses a separate nonblocking `.state.lock`. Private regular
files must belong to the current Unix user with no group/other access. Paths
must be absolute, without symlinks or parent traversal; caller and wallet
directories cannot contain one another. These native custody operations require
Unix no-follow file handling and refuse unsupported platforms. State publication
creates a private unique file, writes and synchronizes it, atomically renames it
and synchronizes its directory. Failed publication residue remains private and
is never promoted as a latest head.

`wallet-client-open` does not invent a missing latest wallet head. An existing
wallet requires its separately supplied exact head when creating caller state.
Retained pending consent is user review data, not authorization: startup must
reconcile it before presenting an active signing session. With no pending review,
the stored head must pass ordinary full native wallet validation.

`wallet-client-store` takes a `--file` containing `previous` and `proposed`.
The complete previous state must equal retained state under the caller lock.
Initial head installation checks exact native custody. Beginning a pending
review checks owner/domain, original caller head and complete review commitment;
the review may have become stale after the click. It grants no signature,
reservation or value authority. Ordinary native signing must still recheck the
complete draft against current inputs, incidents, finality and reservations.
Existing pending consent cannot be replaced by a different review. A changed
head without that pending review and an exact retained native response refuses.

`wallet-client-reconcile` takes the complete expected caller state as `--file`.
It computes a proposed next state without publishing it or reading a key.
An exact retained approval is checked through native journal/history replay and
the original review/caller head. Recovery cannot first-sign and an unhealthy
wallet after publication failure refuses response release until reopened.
An unsigned pending review clears only after the original unchanged native head
is fully verified. An unknown, changed or rolled-back head preserves pending
consent and refuses. The UI then publishes the calculated state through the
separate native store operation before releasing its response.

The Python reference recovery algorithm remains in tests, with exact canonical
state comparison for unsigned and signed response-loss boundaries. Wallet
payments, reservations, encrypted key use, full-journal backups, fresh restores,
stale-head rejection and caller write failures remain separately checked.
No older native binary or Python persistence fallback is used.

This migrates a ground runtime responsibility. It does not qualify common
state/head rollback, copied-key concurrent custody, independent latest-state
protection, power-loss or cross-device recovery. Changed native source requires
fresh signed no-value fixtures; old fixture balances, custody and failed stores
are not migrated. Consensus scheduling and contact transport still have Python
dependencies; removing those dependencies and complete mainnet
acceptance remain separate requirements.
