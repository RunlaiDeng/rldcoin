# Regional value composition

The existing regional ledger has no channel/fee-reserve value bucket. The
executable model in `../value_composition_model.py` and the contract in
`../../docs/research/REGIONAL_VALUE_COMPOSITION_CONTRACT_V1.md` are mathematical
inputs for implementation, not authenticated native state or an adopted profile.
Its oracle booleans and search bounds never authorize a block or relax native
limits. Preserve the old single-unit model and frozen fixture evidence.

Adding native channels requires explicit new currency/admission/rule identity;
legacy profiles must refuse the new commands. Bind exact funding, parties,
signed states, challenge deadline, reserved-fee owner, provenance, incidents and
resource/atomicity policy. Keep all actual input-owner approvals and native
finality/era checks. Carry unchanged capacity through fee-reserve allocation;
every resulting capacity, reserve, change, fee and settlement output inherits
the full input provenance union. Put capacity/reserves in state commitments,
full replay and E, never liquid/owner spend budgets. An incident preserves every
liability and forbids its dependent next transition; unrelated proven value
may progress. An absent resolution authority cannot clear quarantine.

The model's exact old-backup counterexample passes graph/accounting checks but
can close before an unseen incident. Native signing/recovery therefore requires
the separately retained current witness/caller head; replay or head creation
from that backup cannot establish freshness. All-state/head rollback and copied
key concurrency remain separate independent gates. Do not count mathematical
composition, scalar conservation or a fresh-directory replay as those passes.

Changed native implementation needs fresh signed no-value fixtures, never old
state/value/custody migration. Check the shared ordinary execution path, typed
BFT submission/reception, wallet review/recovery, incident exposure, capacity
and cold replay before any broader lifecycle qualification. Keep existing
thresholds, history/evidence bounds and stopped failed sources intact.
