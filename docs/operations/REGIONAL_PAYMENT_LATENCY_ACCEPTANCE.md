# Regional payment latency acceptance

The product target for ordinary transfers inside one settlement region is
recipient-verified finality and spendability at p95 at most three seconds and
p99 at most five seconds under declared normal network and load conditions.
This target applies to an Earth region spanning continents, a Mars region or
a ship region with an explicitly admitted validator profile. It is a pending
acceptance requirement, not a claim that the current candidate meets it.
It implements the measurement obligations of the
[current research release](../WHITEPAPER_RELEASE_2026-10-09.json), Sections 1,
5, 8 and 20. Its historical release snapshot is not a current implementation
qualification or permission to change a signed genesis.

An API acknowledgment means processed or queued. A preconfirmation is an
intermediate observation. Finalized means that the recipient independently
authenticates and installs the exact certified Native result. Spendable means
that its actual output satisfies current ownership, incident, maturity and
local value rules. The latency endpoint requires both finalized and spendable;
the recipient must also demonstrate an actual second ordinary independently
signed payment consuming the output, and independently verify its finality.
A sender's receipt, a transport receipt or a controller's observed height is
insufficient.

For every unique valid signed ordinary submission, start timing at its first
submission before admission, including queue delay and backpressure. Retain
every sample, including follow-up payments, and its processed, preconfirmed, finalized,
spendable and re-spend outcomes. Report p50, p95 and p99 using a declared
percentile method, observation horizon and drain/censoring policy. A p95 claim
requires at least 95 percent of all valid cohort submissions to complete within
three seconds; a p99 claim requires at least 99 percent within five seconds.
Unresolved samples remain in the
population, with explicit lower bounds; they cannot be discarded, restarted or
converted into successes. An observation cut off before the required tail can
be assessed is incomplete. Recovery and retransmission retain the original
submission time and transaction identity. Use a monotonic timebase or bounded
cross-host clock uncertainty with a conservative timing bound; disclose invalid
submissions separately with their validation reasons.

Before a qualification run, pin the offered rate, burst limit, payment size,
validator and recipient resources, retained-history size, complete source and
launched binary, topology, authenticated route and RTT/load measurement method.
An initial benchmark envelope may require measured validator-to-validator RTT
at most 300 milliseconds; it is a declared test condition, not an achieved
measurement or a universal regional bound. Characterize supported load before choosing the
benchmark rate; neither an unspecified load nor a single successful payment
establishes this target. Measure Earth continent pairs in both directions and
report Mars and same-spacecraft actual or labeled simulated conditions
separately. Do not pool slower regions, validator/control counts or load/latency
classes into faster cohorts. Run queue saturation, leader loss, equivocation,
partition, reorder and restart as separately declared fault profiles. A
partition that lacks the admitted quorum must halt finalization.

The regional BFT admission uses n = 3f + 1 validators and at least 2f + 1
distinct approvals, with independently controlled custody. The four-validator
candidate uses three distinct approvals. A ship with too few independently
controlled validators cannot silently claim the same fault tolerance or lower
the admitted threshold. Any other profile requires explicit adoption and its
own assumptions and qualification.

Transfers between settlement regions remain asynchronous. Physical contact,
causal propagation, independently authenticated import and signed maturity
rules determine their completion. Multiple Earth settlement domains have this
cross-region boundary even when users reside on the same planet. The regional
latency target does not change cross-region maturity, issuance, refunds,
quorums, supply or Native safety requirements.

Same-host fixtures can discriminate implementation defects and finite timing
costs. They do not establish independently operated regional performance,
production custody, sustained fault liveness, physical links or adopted-network
qualification. Current normative release receipts and historical failed scopes
remain separately binding.
