# Native group proposal interface

`wallet-proposal-build` and `wallet-proposal-review` use the ordinary Native
Store and wallet locks, pinned signed currency and complete wallet/history replay.
Both require `--wallet-dir`, the separately retained `--expected-wallet-head`
and a bounded `--file` input. Neither accepts a signing key or creates an approval,
input reservation, block or caller-head transition.

Build input contains exactly `request` and `selection_pin`. A new request contains
the ordinary owner, participants, explicit inputs, outputs, optional remote
payment, fee and `valid_for_blocks` fields. Owner may be omitted: the locked
wallet binding selects the reviewer. The selection pin must equal the complete
current Native wallet observation. `valid_for_blocks` is an integer from 1 to 32;
the build request cannot supply `valid_through`, even as null. Native derives one
checked absolute expiry and verifies all actual input owners, ordering, eligibility,
reservations and exact conservation through the existing wallet preparation kernel.

Build output contains `prepared` and `proposal`. The proposal retains the existing
`RLD-REGIONAL-GROUP-PROPOSAL-V1` format, currency, region, intent ID and complete
request with absolute expiry. Review input is that complete proposal. Later
owners re-review current Native inputs under their own wallet binding; the exact
intent and original absolute expiry must survive. An expired, altered, unbalanced,
wrong-domain or stale proposal refuses. No group change is allocated implicitly.

Each input is at most 2 MiB. Unknown and duplicate typed fields refuse. Existing
Native history, output, owner-count and input-count limits remain unchanged.
The Python wallet UI delegates these operations to Native with no older-binary
fallback. Its Python test reference retains the proposal algorithm independently
and compares complete canonical prepared/proposal output, including review
commitments, across owner and height changes. Signing, combination, submission,
recipient maturity and restart recovery retain their separate native requirements.

This is an incremental runtime migration. Caller persistence and keyless recovery
calculation use the [native caller interface](NATIVE_WALLET_CLIENT.md). The UI
server, consensus scheduling and contact transport still have Python dependencies.
Changed Native source requires fresh signed no-value fixtures; existing fixture
currency, private custody and failed stores are not converted. This interface
does not establish independent custody, full protocol acceptance or mainnet readiness.
