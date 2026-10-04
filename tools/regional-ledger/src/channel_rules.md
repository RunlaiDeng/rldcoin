# RLD-REGIONAL-CHANNEL-KERNEL-V2

Native signature/value component only. This is not a complete protocol profile,
ordinary node activation, signing custody, incident resolution or value migration.
An independently pinned fixture currency/region and authority-signed exact
component/source declaration are required. Only fresh no-value fixtures qualify
this component; older private source/state/head domains are never converted.

All action signatures bind exact component, currency, region, nonce, absolute
valid-through height, actor and complete action. Funding requires every actual
input owner plus both distinct channel parties in strict key order. Amounts are
positive checked u128 quantities within the adopted cap; inputs equal capacity,
change and named fees. Channel states separately bind currency, region, channel,
sequence and both payouts and require both party signatures in exact order.

A fee reservation requires the actual mature coin owner, who must be a party.
It authorizes one fee no greater than its signed limit for a fully authenticated
higher closing state of this exact channel, paid to the containing block miner.
No arbitrary transfer, other channel or first signing is delegated. Original
capacity is carried unchanged; capacity and reserve inherit all input lineage.
Close uses a separately owned action-bound mature fee coin and retains its
authenticated payout state. Close/challenge fee and change inherit the union
of capacity, reserves and fee input. Challenge requires a strictly higher state
from c+1 through c+2016; it never rebases c or the absolute deadline. Settlement occurs
strictly after c+2016, pays the exact retained split and returns all unused
reserves once. Complete settled records remain and cannot be reopened.

Capacity and reservations are E, never ordinary liquid coins; every transition
preserves minted+received = U+E+historical_outbound in this source component.
Every output/fee/change/return retains complete snapshot dependency union.
Limits remain 16 actual inputs/outputs, 16 reserves per channel and at most
4096 combined channel/reserve records, with the existing complete 8-MiB bound.
Canonical typed unknown fields, malformed/duplicate actors and altered domains
refuse. Quarantined dependencies forbid all new transitions. A separately
retained exact latest component head is required before evaluation; a newly
observed or reconstructed head is not an independent freshness witness.

The standalone kernel verifies existing signatures and stages value in process.
It does not sign, release an owner response or initialize serialized state.
The separate explicit native value-channel profile integrates this kernel into
ordinary blocks, state commitments and complete history replay, requiring an
action-signed prior native head. That deterministic replay dependency is not an
independent freshness witness for signing. Wallet/caller custody, automatic
incident observation, invoice acceptance and independent recovery still require separate
implementation and qualification before live adoption.

Outputs retain the full certified-checkpoint and channel-funding identity union;
their combined bound is 64. Open includes its exact identity. Capacity, reserve,
fee, change, settlement and ordinary Spend/Import outputs carry that union.
A fully authenticated same-sequence channel conflict quarantines all dependent
new transitions without changing retained liabilities. Its self-contained native
funding checkpoint and both party signatures are mandatory; no hash-only proof
or automatic resolution is allowed.
