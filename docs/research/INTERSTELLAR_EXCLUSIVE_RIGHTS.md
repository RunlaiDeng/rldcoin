# Interstellar exclusive rights: candidate and security boundary

This is a research design contract, not a replacement whitepaper, executable
consensus profile, adopted network or completion certificate. Survivor-1 and its
published receipts retain their existing meaning. The companion
[isolated Rust model](../../tools/interstellar-rights-model/README.md) exposes
both conditional constructions and counterexamples. No novelty priority is claimed.

## Required behavior and distinct authorities

The desired system combines ordinary permissionless mining, local payment progress
during long interstellar disconnection, preservation of completed payments after
reconnection, one conserved currency and the existing exact issuance schedule.
These are separate obligations. Starting proof-of-work computation needs no
permission; final allocation of a reward must additionally exclude a conflicting
allocation of the same issuance right. A valid owner signature authorizes an
intent; final payment acceptance must additionally exclude a conflicting use of
the same input. Neither role is conferred by a relay identity or geographic name.

One global total transaction order need not be imposed on unrelated inputs.
Asset-transfer research separates owner-controlled causal histories from general
consensus [1]. Its Byzantine message-passing construction still relies on secure
broadcast. Sui Lutris combines object-specific certificates with consensus for
shared operations and maintenance, and explicitly assumes a bound on Byzantine
validators and communication conditions [2]. These results do not establish
unconditional isolated single-device finality.

## Conditional composition

Assign each exact input/version one authenticated spending domain. A domain is
an authority binding, not a planet label or an endpoint learned from advertising.
Within a domain, unrelated inputs can advance independently. Each completed
transition consumes its predecessors once, preserves owner authorization and
amounts, and produces complete, independently verifiable evidence. An honest
recipient's subsequent payment must carry or resolve every required dependency.

A cross-domain handoff permanently consumes the old spend right and binds one
destination domain, owner, amount, currency and exact predecessor. The destination
validates the complete authority history before creating the new spend right;
it retains permanent duplicate-import protection. Received bytes, an intermediate
custody acknowledgment, a local timeout or an unavailable destination never
authorize a second credit or a source refund. Missing evidence waits. Valid
receipt loss can leave a transfer pending indefinitely.

Reconnection composes causally closed, compatible certified histories. It does not
replace them with a global work winner. This preserves prior completed payments
only while their authorization, conflict-exclusion and cryptographic assumptions
hold. Contradictory authority certificates expose a broken assumption; freezing
the affected inputs is incident containment, not proof that earlier recipients
have suffered no loss. Automatic confiscation, compensation issuance or history
rewriting cannot silently restore the original finality claim.

The basic conservation argument is conditional: an active input is either
replaced by equal authorized outputs or consumed into one pending handoff. A
unique valid import replaces that pending obligation with equal destination
outputs. These classes are mutually exclusive. This induction requires a real
non-equivocation mechanism for every predecessor; it cannot assume the very
single-use property it is meant to establish.

## Duplicate issuance is another single-use problem

The unchanged schedule uses cap `C = 10^35` runlai and `L = 200000`. For reserve
`R`, an era spends budget `B = R` if `R < 2`, otherwise `floor(R/2)`. Slot `k`
issues `floor(B/L) + 1` for `k < B mod L`, and `floor(B/L)` otherwise. Initial
issuance and initial allocation remain zero. Every globally identified slot may
create its scheduled amount once; local domain IDs cannot multiply the schedule.

Two disconnected regions both treating their first block as global slot 1 can
each claim the first reward. Prefixing each claim with a region ID merely makes
different claim identifiers; it does not make both rewards authorized by the
single-slot recurrence. Giving both claims the same global ID makes the conflict
detectable after communication, but does not choose an irreversible owner while
both recipients are disconnected.

Trusted, disjoint issuance-slot assignments can prevent overlap between honest
domains. Escrow-style allocation is an established way to preserve a numeric
bound during disconnected operation [3]. But it introduces two obligations:

1. A publicly verifiable process must allocate and transfer exclusive future
   issuance rights without duplicating the reserve or inventing additional
   issuance. Assigning rights is not issuing coins at genesis, but it is a real
   privilege that needs explicit allocation and Sybil-resistance rules.
2. The domain assigned a slot must not certify two different owners for it.
   Copying its software authority recreates the same conflict inside the domain.

A newly arriving isolated miner without an applicable assignment can perform
hashing, but cannot immediately claim an irreversible subsidy under this
construction. Thus exclusive slots alone do not satisfy a requirement that every
new disconnected miner independently finalize rewards. A fair, permissionless
assignment mechanism, safe succession and exact mapping from the original
height-based schedule to multi-domain events remain unspecified.

## Copied-software counterexample

Consider the following assumptions together:

1. Keys, counters, journals and every local authority/freshness record are ordinary
   copyable software state. No external non-forking witness or qualified secure
   hardware is available during the payment.
2. Two honest recipients have no communication with each other or a shared
   conflict-exclusion service during acceptance.
3. Each recipient must be able to finish a payment from an otherwise eligible
   isolated sender without waiting for any absent party.
4. The sender may be malicious, and two conflicting payments of the same input
   must never both become irrevocably accepted.

Clone a fully eligible sender immediately before an unspent input is consumed.
In one isolated execution it pays Alice; in another it pays Bob. A malicious
sender can run both copies. Each honest recipient has the same local view it
would have in the corresponding eligible isolated execution. If both executions
must finish, both recipients accept conflicting successors. A later selection,
punishment or loss disclosure cannot make both earlier payments irrevocable and
conserved. This argument is about the stated copyable-state model; it is not a
claim about hypothetical non-copyable physical money.

The real-signature witness signs different recipient intents using the same key,
input/version, sequence and prior head. Each signature verifies strictly, and a
signature over one intent fails for the other. No cryptography was broken. Both
intents can also carry genuine proof of work. Work is a costly computation, not
proof that its producer did not compute another conflicting result.

Hash chains, locally monotonic counters and zero-knowledge proofs of a locally
valid transition still allow two copies to prove two valid transitions from the
same old state. A unique computational result for a fixed input does not prevent
running computations for two different recipient intents. A deterministic
eventual tie rule chooses a loser, requiring conditional acceptance until that
choice can be justified. Double-spend detection or penalties after reconnection
are distinct from prevention before acceptance.

## Mechanisms that can discharge the assumption

An intersecting quorum can provide conflict exclusion while enough authenticated
honest signers preserve their locks. For four fixed identities and at most one
Byzantine identity, two three-vote sets intersect in at least two identities,
including an honest one. That honest identity must refuse conflicting decisions.
The roster, epoch, object/version and exact intent must be authenticated. Dynamic
membership must preserve this property across handoff. Silence does not justify
reducing a threshold or replacing the old authority; the old group might merely
be partitioned. A lone voter cannot create the required certificate.

Alternatively, qualified non-exportable keys and non-rollbackable hardware state
can narrow the copied-software model for explicitly supported devices and finite
horizons. Such a construction must specify attestation trust, hardware failures,
stateful transfer, interrupted writes, device replacement, lost devices and key
renewal. Software emulation is not evidence of non-copyability. Offline payment
research using secure elements makes these hardware assumptions explicit [4].
There is no qualified Rldcoin hardware construction in this candidate, and it
cannot be silently required of arbitrary ordinary computers.

Waiting for communication preserves an honest recipient's ability to reject
conflicts but weakens isolated completion. Keeping acceptance provisional preserves
local activity but weakens finality. Insurance introduces credit and capital
assumptions; it neither prevents duplicate issuance nor proves that every payee
can be compensated without changing the monetary rules.

## Admission and verification obligations

Before this architecture can replace the paper, an exact executable contract must
specify the conflict-exclusion mechanism, open participation and Sybil resistance,
issuance-right allocation, domain/epoch succession, split/combined amounts, fees,
complete evidence, durable replay protection and failure policy. The copied-state
assumption must be discharged explicitly, rather than hidden inside a trusted
single-writer or uniqueness oracle.

Finite state exploration of a single existing input under an ideal certifier only
checks the handoff composition under that assumption. It does not implement the
certifier, establish an unbounded proof, qualify native code or demonstrate a
physical route. Independent validation, security/custody review, full history,
cryptographic renewal and authenticated adoption remain distinct obligations.
No model or document creates a monetary network or migrates test balances.

## References

[1] Guerraoui et al. The Consensus Number of a Cryptocurrency, 2019.
https://arxiv.org/html/1906.05574v1

[2] Blackshear et al. Sui Lutris: A Blockchain Combining Broadcast and Consensus.
https://arxiv.org/html/2310.18042v5

[3] Balegas et al. Extending Eventually Consistent Cloud Databases for Enforcing
Numeric Invariants, 2015. https://arxiv.org/abs/1503.09052

[4] Federal Reserve. A Robust Risk Framework for Offline Payments.
https://www.federalreserve.gov/econres/feds/a-robust-risk-framework-for-offline-payments.htm
