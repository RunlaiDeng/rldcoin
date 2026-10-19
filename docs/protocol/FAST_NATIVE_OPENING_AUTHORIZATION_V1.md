# Independent joint opening authorization

This private no-value session interface builds and signs existing kind1
RLD-FAST-ESCROW-1 openings. Native bytes, both strict owner signatures, issuance,
work, windows and maturity are unchanged. No monetary adoption or migration follows.

`opening_proposal` takes current head, timestamp and typed terms: nonzero nonce,
two ordered distinct owners, principal amounts, limits, rates, operation fees,
expiry and each owner's1..32 ordered input references. IDs use lowercase hex and
integers canonical decimal strings. The actual native ledger computes change
from input value minus principal, reserved payment fees and opening fee. Shared
strict parsing and full nonmutating execution check both owners, disjoint mature
inputs, exact sums, positive fees/rates, slot/exit budgets, expiry and capacity.
Proposal construction neither signs nor reserves inputs.

Existing unsigned operation U contains kind1, version/suite, chain, nonce, ordered
owners, principal, interleaved limits/rates, fees, change, expiry and input lists.
Maximum U length is2473; complete signed length2601. Proposal ID is SHA256 of
`RLD-FAST-ESCROW-1/OPEN-PROPOSAL` || zero || U. Both signatures retain the existing
OPEN domain over U without its kind byte. A partial is owner_index:u8 plus its
64-byte signature; it cannot pass complete native admission.

`open_prepare` binds selected tip and plan(proposal hex, own index, timestamp).
It reviews both sides, then durably reserves only its own inputs against all
opening/ordinary-transfer/escrow preparations. Review is SHA256 of
`RLD-FAST-ESCROW-1/OPEN-REVIEW` || zero || tip32 || timestamp:u64 || own_index:u8 || U.
Re-review may change the local evaluation time for the same reserved intent.
Changed proposals cannot reuse reserved inputs. Counterparty input verification
grants no reservation or signing authority over that counterparty.

`onchain_sign` requires exact persisted preparation/review/tip, approved=true and
the corresponding owner's O13 encrypted key. It retains only that owner's partial
before release, returned as `opening_partial_hex` without a complete operation.
Secure native password input and separately retained latest caller heads remain
mandatory. Separate owners retain separate caller states and keys.

`open_combine` binds tip, preparation request, own signing request, exact review
and the existing counterparty partial. It requires the real retained own signature,
distinct correct indices, identical U and current native review. It creates no
signature or ledger rights. Immutable caller references/intents retain U and both
complete partials; a short verified reply binds the complete native operation ID.
Reconstruction fully verifies native context and signatures; a digest alone grants
no authority. The4096-byte reply and32-MiB caller limits remain unchanged even for
64 inputs. `submit_authorized` accepts a complete combine, refusing a lone partial.

Cold opening authenticates every review, partial, reference and native context.
Exact predecessor-head/request/digest recovery cannot first-sign, replace state
or release inputs. A retained combine intent can complete from existing signatures
under unchanged selection; stale selection refuses. Completed replies reconstruct
the same bytes. Wrong/missing/duplicate/changed proofs or damaged records refuse.
Pool custody, own-template PoW, complete admission and selected funding origin are
distinct. Peer carriage carries data, never remote approval or signing authority.

This is not qualification of continuous solvent monitoring, autonomous latest-head
custody, independent operations/security, consumer UI, scalable history/archival/
mass exit, physical routes or composed local-latency/daily100M G1-G11. Ordinary
CPU mining and causal stellar payments retain their open participation rules.

## Versioned data carriage

Peer kinds7/8 add RLD-FAST-OPENING-CARRIAGE-1. Both use this big-endian frame:
version:u16=1, suite:u16=1, chain32, U_length:u16, exact U. Kind7 ends there
(403..2511 bytes); kind8 appends one complete65-byte partial (468..2576 bytes).
U length365..2473 and its own version/chain/nonce/owners/terms/input ordering are
strictly checked. Kind8 also authenticates its actual owner signature against U.
Alternative/trailing encodings refuse. Existing packet/TLS/box limits and roles
remain unchanged. Older peers refuse unknown kinds without fallback or migration.

`peer_opening(source_request,destination)` carries a retained successful proposal
or own partial. `peer_open_prepare(packet,request_id,owner,timestamp)` is a separate
explicit local preparation of received kind7; no key or approval is supplied by
the network. `peer_open_combine(packet,request_id,prepare_request,sign_request,review)`
requires kind8's exact U to equal the retained local proposal, then combines under
normal full native and signature checks. Data receipt never advances a caller
head, reserves funds or signs by itself.

## First-use composition

A first-use path must start with independently native-verified ordinary inputs,
not an already-open fast channel or an operator's account credit. If one owner
needs funding, its preceding ordinary transfer requires the actual spending
owner's exact review, explicit approval and retained native signature. Normal
pool custody, own-template proof of work, native execution and peer import must
precede selection of those outputs for the opening. Reward maturity remains
h+100; an aged logical fixture does not demonstrate physical-time mining.

Each opening owner independently reviews and signs its own inputs. Received
proposal/partial packets supply data only. A lone retained partial cannot be
submitted as a complete opening; the exact other owner's signature and normal
native admission remain mandatory. Only the resulting selected native funding
can initialize owner/retainer actors and authorize subsequent fast reviews.

`tests/fast_live_payment.rs` composes ordinary-input funding, carried joint
opening, actual pool-template mining, automatic native import, separately
approved fast payments and key-unavailable complete cold replay. The recipient's
onward amount must require the preceding receipt where that property is claimed.
Original first-use setup and native inclusion clocks stay separate from each
funded fast payment's original submission clock. Setup cannot be relabeled as
seconds-fast service or silently removed from a first-use cohort. Retained miner
fee evidence does not prove settlement or mature payout. Same-host scripted
approvals do not establish consumer UI, independent custody, population latency,
daily capacity, unilateral/mass exit or physical interstellar qualification.
