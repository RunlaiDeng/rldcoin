# Native ordinary BFT tick policy

Ordinary and complete-origin node companions use `bft-tick-observation` to
select their next consensus request. Rust chooses complete finality,
current Prepare/Commit, proposal eligibility, the initial wait, future Prepare
and timeout in the existing priority order. The Python companion dispatches
requests and service callbacks, records phase entry, and retains lifecycle and
communication duties. Joint-epoch and role-slot workflows remain separate.
There is no Python decision fallback for the migrated ordinary path; the
independent former Python policy is used only in tests.

## Exact input and clocks

The command takes the same signer, caller-head, archive, archive-digest, key,
runtime-format and round pins as native phase selection. Its private canonical
JSON file contains `context`, `order`, `stage`, `proposed`, `entered_at`,
`interval`, `timeout`, `stopped`, `initial_wait` and `timeout_refresh`.
`order` must include every retained body exactly once. Unknown or duplicate
fields, wrong types, noncanonical encoding and stale pins refuse. Both input
and output retain the ordinary 8 MiB bound; all archive and wire bounds remain.

Native fully replays current ledger and signer custody, retains original locks
and fences, and authenticates every relevant complete envelope before selection.
The entry uses the host OS monotonic clock: `mach_absolute_time` on macOS and
`CLOCK_MONOTONIC` on other supported Unix hosts. The companion's original
`time.monotonic` phase entry stays in that same local clock domain. Entry,
interval and timeout must be finite, with the existing 0.5–3600 second interval
and 2–3600 second timeout bounds. Repeated evidence observations and callback
returns never replace phase entry. This is local scheduling, not authenticated
time or independent freshness.

## Stages and dispatch

`begin` gives complete certificates priority even after a timeout or when
stopped/keyless. It then selects current Prepare/Commit, an eligible proposal
or initial wait, future Prepare, and finally a due timeout. Timeout age remains
`min(3600, timeout * (round + 1))`; rounds stay below 32. The Origin initial wait
returns the original absolute `entered_at + interval` deadline. A service yield
ends the unit without signing. A successful wait or timeout-refresh callback
requires a new full native observation before another request. Callback-use
flags bound each callback within the existing unit.

`commit` and `committed` retain the phase interface's freshly verified current
Commit and own-committed-value finality rules. Existing profiles still govern
same-unit Commit after a current Prepare; future Prepare ends its original
phase. `after-proposal` is Origin-only and requires an exact typed hint for the
just-retained Propose request. Immediate Prepare requires the actual signer's
proposed round, no own Prepare/Commit, its own authenticated proposal leader,
and the exact complete snapshot and timeout certificate. It runs the original
native transition on a private clone with all durable fences retained.

The observation binds exact request bytes, context, round, caller head,
archive digest and key. Returned plans never sign, persist a signer transition,
install a certificate, debit or establish spendability. Each dispatched native
operation independently validates its current custody and authorization.
`ledger_changed`, `signing_authority` and `independent_freshness_qualified`
remain false. Refusal cannot trigger a weaker policy or delete evidence.

## Qualification boundary

Retained disk and wire encodings are unchanged. Changed native source requires
fresh signed no-value fixtures; compatibility never authorizes old custody or
failed-store migration. Python runtime dependency removal, native lifecycle and
transport, sustained faults, reconfiguration, independent custody, physical
routes and mainnet acceptance remain separate obligations.
