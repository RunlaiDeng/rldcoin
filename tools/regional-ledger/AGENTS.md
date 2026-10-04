# Regional value composition

The ordinary regional ledger now has an explicitly admitted channel/fee-reserve
bucket for the new native ground value-channel profiles. The
executable model in `../value_composition_model.py` and the contract in
`../../docs/research/REGIONAL_VALUE_COMPOSITION_CONTRACT_V1.md` are mathematical
inputs for implementation, not authenticated native state or an adopted profile.
Its oracle booleans and search bounds never authorize a block or relax native
limits. Preserve the old single-unit model and frozen fixture evidence.

`src/channels.rs` is a separate typed native signature/value kernel under
authority-signed `RLD-REGIONAL-CHANNEL-KERNEL-V1`. Its standalone API stages
copies of fully native-replayed inputs and checks the
separately retained exact latest head and never signs or persists custody.
Its U/E audit, source declaration, complete state/owner signatures, native
snapshot provenance, one-use reserve and c+1 through c+2016 challenge checks
are component evidence only. Serialized Book/head observations cannot
initialize authority. Same-sequence state conflicts, paid descendants,
mandatory adequately reserved receipt acceptance and wallet signing/custody
remain open. Do not expose this as a live owner signing or restore service.

The separate `RLD-REGIONAL-BFT-VALUE-CHANNELS-FIXTURE-V1` and
`RLD-REGIONAL-SEGMENTED-VALUE-CHANNELS-FIXTURE-V1` admissions sign the exact
`src/channel_profile.md`, kernel and reserve-era issuance identities under a
new admission domain. Legacy admissions refuse value_rules/channel commands.
The ordinary shared execution, complete NativeState state commitment and
genesis/history replay retain E, complete source/party signatures and signed
prior action heads. The latter is a block dependency, never independent latest
freshness for first signing/recovery. New currencies require the exact 10^35
cap and normative origin issuance; old constant-reward fixtures stay scoped.
BFT remains ordered 3-of-4 with fixed membership, segmented unanimous stays
4-of-4. Epoch/stream profiles do not silently adopt channels or lower thresholds.
Existing bounds and every stopped failed fixture remain. Kernel/ordinary
samples do not qualify same-sequence incidents, full paid descendants, invoice
acceptance, owner signing, long BFT history or independent/physical operation.

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
