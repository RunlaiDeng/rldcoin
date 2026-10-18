# Fast miner-fee claims: prospective component V1

This is a verification-only candidate for F04/F06, not an adopted transaction,
funded ledger, complete channel construction or change to Survivor-1. No ordinary
C04 output acquires escrow rights from this document or its component API. Fresh
no-value native funding, owner custody, principal disputes, inclusion capacity,
canonical operations and independent review remain required before activation.

## Why a balance accumulator or reserve alone is insufficient

Consider a channel whose jointly signed initial state has zero accrued fees.
After one real off-chain payment both parties possess a newer positive-fee state.
If the base accepts the old state, the two parties can cooperate to publish it.
An execution with no off-chain payment and one with an omitted payment have the
same funding and close bytes. A base verifier cannot infer the missing event.
A signature or proof over only the submitted history does not prove that no
other jointly signed history exists.

An irrevocable full-budget payment to a miner can give an upper bound on covered
fees, but does not establish the exact aggregate for actual completed payments.
It also charges unused capacity. It is not a substitute for F04's per-payment
entitlement and completeness requirements. This candidate instead gives an
independently retained fee claim its own monotone settlement floor.

## Principal and fee reserves

Prospective funding locks principal P and two payer-specific existing-value
reserves E_A=N_A*f_A and E_B=N_B*f_B, using checked integers. Both N are positive
u64 limits and both f are positive runlai quantities. P+E_A+E_B is at most C=10^35.
Reserves are not ordinary spendable outputs and are not counted again as supply.
An actual funding transition must authenticate every mature input owner, debit
those exact inputs once and bind both distinct channel owners' authorization.

The fee beneficiary is the miner reward key of the exact selected block containing
the prospective funding operation. The funding identity includes that block;
re-inclusion in another block does not reuse old fast claims. A component caller
supplying a key or hash has not proved this native funding relationship.

Both owners sign state sequence q, principal payouts b_A+b_B=P, and cumulative
authorized fee-slot ranges 1..k_A and 1..k_B, where 0<=k_i<=N_i. A payment by i
increments exactly that payer's k by one, moves its positive principal amount to
the other owner, and binds its positive fee f_i and complete old/new state. Its
logical identity is (funding identity, payer index, fee slot). Different invoices
using the same slot conflict; they are not two valid distinct completions.
Native owner custody and the recipient must refuse slot reuse and rollback.

Signing a state explicitly authorizes the complete fee ranges it names, even if
the owners fabricate an unnecessary counter jump. Such a jump cannot reduce a
fee obligation or create supply; it spends only their separately reserved budget.
The ordinary payment protocol must reject jumps rather than count them as real
payments. A signed range is not evidence that its number of payments occurred.

## Independent fee retention is a completion condition

Before reporting a fast payment complete, the recipient needs durable custody of
both complete owner signatures, its full funding/old/new payment evidence and an
authenticated durable-custody acknowledgment from the funding miner's explicitly
authorized fee retainer. That retainer retains the complete highest signed fee
ranges before acknowledgment and monitors the selected chain through close.
It cannot sign for either owner or authorize principal transfers. Its availability
is a declared fast-service condition, never a prerequisite for base validation,
ordinary mining or asynchronous C04 carriage. A missing acknowledgment stays pending.

The retainer must be independent of cooperating channel owners for the claimed
fee-preservation property. A founder service, an unpinned advertised endpoint,
one author's second key or a hash-only acknowledgment does not establish that
assumption. Exact retainer delegation, custody/crash recovery and acknowledgment
bytes are not specified by this component and must precede a full fast profile.

## Fee floor and close

A prospective first close fixes height c and an absolute challenge deadline c+W,
under an explicitly adopted finite W and inclusion/resource assumptions. Later
states do not reset it. Before final settlement, any party or fee retainer may
present a complete authentic jointly signed state as a fee claim. This is not a
principal update: even a lower-sequence claim remains admissible for its fee rights.
For every fully authenticated claim, update independently:

```
m_A = max(m_A, k_A)
m_B = max(m_B, k_B)
F_A = m_A * f_A
F_B = m_B * f_B
```

Initialization and cooperative/forced close must incorporate their complete state
as a claim too. Principal sequence selection, a lower counter on a newer state,
or signatures by both owners cannot decrease either floor. Claim verification
checks the same exact funding, parties, principal capacity, canonical bytes,
counter limits and both strict signatures. Hashes and opaque operator counts do
not authorize a range. Duplicate claims are idempotent and never paid separately.

Once the fixed dispute window is safely closed, a native settlement consumes the
exact escrow once, pays F_A+F_B to the pinned funding miner and returns E_i-F_i
only to that reserve's original owner. The principal engine separately enforces
the selected valid payout state. All fallible checks precede mutation; amounts
conserve P+E_A+E_B. Payout at height h is a miner reward eligible only at h+100.
The normal containing-block operation fee is separately owner authorized; it
does not replace the accrued fast-payment fees. No second settlement or recreated
escrow is allowed. Reorganization reconstructs locks, floors, refunds and rewards
from the newly selected complete native history, not from cached claim state.

For one funding/payer, every conforming payment has one unique slot <=m_i after
all timely retained claims. Thus no two such payments share one charged slot;
every authorized slot in 1..m_i is funded by E_i and its amount is exactly f_i.
The exact range aggregate is m_i*f_i. A signed counter without the actual payment
evidence/retention condition cannot certify the real-payment count for G10.

This is conditional on the retainer or an honest owner presenting its highest
claim before the fixed deadline. If every holder withholds it, loses it, is
censored or cannot communicate during that window, a lower floor may settle.
No purely local signature check can detect that missing history. Such a path
does not meet the advertised completion/safety cohort. Unbounded disconnection
and one-way stellar routes cannot silently use this fast dispute mechanism.

## Canonical verification component

The following is an unadopted state-certificate codec, not a new network packet.
Integers are unsigned big-endian; no optional/trailing bytes are accepted.
The caller supplies a separately authenticated prospective funding view containing
chain, funding identity, ordered owner keys, miner key, P and both (N,f) pairs.
The component only validates their shape/arithmetic; it cannot authenticate the
funding view as native monetary state.

```
version:u16 = 1
suite:u16 = 1
chain:bytes[32]
funding:bytes[32]
sequence:u64
balance_A:u128
balance_B:u128
slots_A:u64
slots_B:u64
signature_A:bytes[64]
signature_B:bytes[64]
```

The unsigned portion is124 bytes; the full certificate is252 bytes. A228-byte
contract context is `version:u16=1 || suite:u16=1 || chain:bytes[32] ||
funding:bytes[32] || owner_A:bytes[32] || owner_B:bytes[32] || miner:bytes[32] ||
P:u128 || N_A:u64 || f_A:u128 || N_B:u64 || f_B:u128`. Its commitment is
SHA256 of `ASCII("RLD-FAST-FEE-CLAIM-1/CONTEXT") || 0x00 || context`.
Each owner signs `ASCII("RLD-FAST-FEE-CLAIM-1/STATE") || 0x00 ||
context_commitment:bytes[32] || unsigned`. Each signature
uses the baseline strict Ed25519 point/canonical verification rules, in the
funding view's exact owner order. Equal/reversed/unbound parties, wrong chain or
funding, unknown version/suite, malformed size, nonconserving principal, invalid
signatures and overbound ranges refuse before changing a component floor.

The process-local verification component accepts no serialized ledger, issues no
coins, advances no native head and performs no payout, signing, network custody
or elapsed-time claim. Its mathematical floor is not an escrow or a current
funding/freshness proof. Native funding/close/claim/reorg integration must use a
new explicitly versioned no-value profile; this codec alone cannot activate it.

## Remaining construction and capacity obligations

Fix canonical funding, complete payment/invoice, retainer delegation/acknowledgment,
first close, principal challenge, fee claim and settlement operations; implement
their composition, owner reservations, cold replay and actual h+100 payouts.
Native funding authenticity and every base/fast double-spend boundary remain open.
Specify abandoned counterparties, retainer outages/key loss, conflicting states,
data availability, durable anti-rollback custody and deep selected-history loss.

At most two maximal fee-range certificates per channel may summarize numerical
floors, but this does not remove full owner/payment custody or principal dispute
evidence. Every admitted worst-case claim, close and refund needs base capacity
before its fixed deadline. Derive the admitted channel count and exit window from
actual canonical bytes, operation/signature limits and declared work/inclusion
assumptions; if they do not fit, the advertised scale fails. A constant-size fee
certificate does not prove safe mass exit or daily throughput.

G9-G11, F-T01-F-T08 and all G1-G8 obligations remain open. Full public vectors,
independent proof/implementation review, actual ordinary-node execution and a
continuous composed daily campaign are required. This component selects a
candidate mechanism for further falsification, not a performance/release result.
