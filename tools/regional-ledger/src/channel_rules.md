# RLD-REGIONAL-CHANNEL-KERNEL-V5

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

The separate invoice receipt event authenticates both exact channel states and
both parties' signatures over the complete invoice, amount, checkpoint, chosen
reserve, fee budget and previous receipt/state IDs. The challenge rule's floor
remains one runlai; a receiver can pin a larger signed budget. One actual mature
unconsumed reservation must cover that entire budget and its owner delegation.
The 16-reserve limit is a maximum, never a minimum for receipt acceptance.

The separate RLD-NATIVE-CHANNEL-OWNER-V1 purpose binds exact currency, region,
profile, channel and owner. One separately locked private journal per actual
party retains initial and increasing state plus invoice partials before release.
Every historical partial fully authenticates its complete native-replayed
funding/prior state and exact observed checkpoint; subsequent signing binds
the exact highest own signed state and previous receipt with unique invoices.
Only explicit recover-only may fsync/promote an exact already signed one-record
tail under the caller's retained transition head. No key is read in recovery.
Each journal retains at most 128 records / 8 MiB; no records are discarded.
Current native and owner heads must be separately supplied, never adopted from
a backup. Combined partials grant no acceptance, ledger credit or new funds.
Incomplete creation refuses unchanged; no restore, independent freshness,
copied-key concurrency, monitoring/inclusion or physical qualification follows.

V5 ground signing custody requires RLD-NATIVE-CHANNEL-WITNESS-V1. Both parties
sign the optional funding witness key; absent policy is read-only for the owner
service, never a fallback. The witness key differs from parties, authority and
regional validators. Its separate private OS-locked journal fully authenticates
every signed complete owner birth/extension from native genesis-derived funding.
Existing owner inception cannot be replaced by another directory; new signing
requires separately retained current native, owner and witness heads and exact
full owner-journal agreement. Own signature response persists first, then the
complete witness extension signs/persists before any response release. Failure
returns no partial. First witness completion on a previously retained owner
response is explicit and requires the witness key; keyless recovery cannot first
attest. Pending witness promotion is explicit, exact and fully authenticated.
Witness entries remain bounded at 256 and combined bytes at 8 MiB; all owner,
evidence and monetary limits remain. Witness statements grant no ledger, value,
finality or issuance authority. The same-process same-host ground role separation
does not qualify independent service/custody, common/witness rollback, copied
witness keys, independent anti-rollback hardware or adversarial raw-key signing.
