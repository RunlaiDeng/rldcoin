# Private owner-state observation V1

`Session::owner_state(expected_head, actor, now)` and the private session command
`{"command":"owner_state","head":"<exact caller head>","actor":"<owner actor>"}`
derive a wallet observation from the existing authenticated owner journal and
the actual selected native ledger. The actor must be registered owner role0 or
role1. Retainer role2 and unknown actors refuse. This read does not change any
genesis, invoice, signature, journal encoding, native rule or control format.

## Authentication and retained evidence

Normal trusted caller-control, exact caller/native file-prefix and native clock
checks precede the observation. The owner journal is opened at its caller-bound
head with complete native birth history, delegation, ordered owner records,
signatures and retained acknowledgments authenticated. A complete retained state
is derived from its verified certificate; sequence0 uses the native funding's
initial allocation and has no complete payment receipt. Journal/file and parent
directory durability checks retain the existing custody requirements. A digest,
an operator balance or peer advertisement cannot initialize the observation.

The response includes `actor_head`, `channel`, `owner`, `funding_miner`,
`delegated_retainer`, `retained_state_sequence`, `complete_receipt_retained`,
`retained_principal`, both `retained_fee_slots`, `remaining_own_fee_slots` and
`next_protocol_fee`. Integer amounts, counters and times are decimal strings.
`retained_miner_fee_entitlement` is the checked sum of each signed slot count
times its native funding rate, across both owners. It is reserved fee evidence,
not an additional balance or an observed mature miner payout.

## Conditional onward state

`native_backing_usable_now` checks the exact funding context in the actual
selected native ledger, its current tip and permitted clock age. Closing,
absent, reorganized or stale backing yields false with its exact
`native_backing_diagnostic`; the retained principal and receipt remain visible.
Integrity or control failures refuse the command rather than returning a
fabricated balance. These local checks do not establish independent freshness
or knowledge of unseen stronger work.

`conditional_onward_state_available` is true only when that backing check
succeeds, this owner has no pending invoice, its own fee-slot count is below the
native signed limit, and its retained principal is positive. Only then does
`conditional_onward_principal` contain that principal. Otherwise it is null,
including fee-slot exhaustion with positive principal. Null does not erase the
retained claim or mean zero funds. There is no implicit slot renewal or fee-free
fallback.

This is a local observation, not a promise that a new payment will complete.
The exact proposed amount, other owner's state and consent, live communication,
retainer availability, backing, monitoring and exit obligations still require
normal review and execution. A subsequent native change invalidates the old
observation. Native withdrawal, fee settlement and reward maturity have separate
conditions and clocks.

## Original pending preparation

`pending_payment` is null or contains the retained `invoice`, `logical_payment`,
`amount`, `fee`, `sequence`, `own_signature_retained`, `original_prepared_at`,
`original_prepared_native_tip` and `original_pending_age_seconds`. The time and
tip come from the first successful durable owner preparation already encoded in
the existing journal. Review, own signing, exact repeated preparation and cold
replay preserve them. A read before that time refuses. The age uses the supplied
observation clock and grants no timeout-based release, refund or new signature.

Preparation time is not the earliest client submission, human-consent time or
an independently trusted clock. G9 measurements must retain the original payer
authorization/submission clock separately, including earlier queueing, retries,
refusals and pending work. This view cannot reset or replace that denominator.

## Authority and required checks

Responses retain `fast_completion_authorized=false` and
`independent_freshness=false`, and set `observation_only=true`,
`owner_spend_authorized=false`, `wallet_key_loaded=false` and
`native_payout_status="NOT_EVALUATED"`. Reads neither load keys nor append caller,
owner or native records; existing exclusive locks and durable-file checks still
apply. There is no public signing or balance endpoint.

`tests/fast_live_payment.rs` exercises actual separately approved owner and
retainer signatures over automatic native/peer carriage, received-value onward
payment, native closure and greater-work removal of the actual funding,
exhausted fee slots, original pending metadata,
key-unavailable cold reads, stale/unknown requests and damaged owner evidence.
Removed backing must also refuse a new proposal; complete retained receipts
remain independently authenticated during full cold session replay without
restoring their losing funding or granting compensation.
`fast_owner.rs`, `fast_session.rs` and `fast_native_view.rs` retain their separate
authorization, full-audit and native integrity obligations. Finite local cases
do not qualify independent custody, consumer approval UX, hostile geography/load,
unilateral or mass exit, daily capacity, or composed G1-G11.
