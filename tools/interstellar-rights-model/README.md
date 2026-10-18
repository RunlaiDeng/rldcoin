# Exclusive-rights research model

This isolated Rust executable explores an **unadopted** payment/issuance design.
It does not modify Survivor-1, open any node or wallet store, create a network,
qualify an implementation or establish an operational interstellar route.
All signing material is a deliberately public **NO-VALUE** constant defined in
the source. It must never protect assets.

```sh
cargo test --offline --locked --manifest-path tools/interstellar-rights-model/Cargo.toml
cargo run --offline --locked --manifest-path tools/interstellar-rights-model/Cargo.toml
```

The executable writes observations as JSON on standard output. Exit zero means
that the declared research checks completed, including expected counterexamples;
it does **not** mean that the requested unconditional protocol has been solved.
An invariant error, missing coverage, search-bound exhaustion or unexpected
signature result exits nonzero. Store run reports outside the public source tree.

## Included constructions

- A finite handoff state machine with three domains, two owners, one pre-existing
  indivisible unit, at most two handoffs and three local transfers. It explores
  all reachable distinct states under those action bounds, including delayed and
  reordered receipt returns. Any finite undelivered-message prefix can remain
  pending. Duplicate self-loops do not create additional states.
- Source consumption, complete symbolic certificate ancestry, destination-bound
  import, permanent duplicate protection and an actual modeled onward payment.
  The model observes global conservation but authorizes local transitions from
  their local input state. A destination receives a complete certificate bundle,
  not permission to inspect the source's current balance or spent set.
- A separate three-slot issuance model with trusted exclusive domain assignments
  and local issued-slot records. Initial issued supply is zero. The unchanged
  reserve/era recurrence determines amounts; assignment of future rights is an
  explicit input assumption, not a solved permissionless allocation protocol.
- Real Ed25519 verification of two conflicting successors signed by copied
  software authority, using the same input, counter and prior head. Both messages
  also admit independently computed double-SHA256 research work at a declared
  leading-zero-byte target. These are not native transaction or block encodings.
- A finite fixed-roster quorum calculation, plus an intentionally unsafe
  timeout-refund trace that duplicates existing value after receipt loss.

## Critical abstraction boundary

The handoff model assumes an authenticated, persistent, non-equivocating certifier
for each input. Exact membership in the retained certificate set is the model's
ideal authentication primitive. It is not native signature verification. Its
acknowledgment transition similarly abstracts an authentic destination receipt.
These assumptions are deliberately removed in the separate copied-key witness.

A local database set, ideal single-writer object, one-shot issuance-slot bit or
unique identifier does not implement that abstraction under arbitrary copying,
rollback, Byzantine signing or local membership replacement. The fixed-roster
quorum calculation assumes at most one faulty identity among four and persistent
locks for every honest identity; a lone survivor cannot supply three votes.

The single-unit model does not cover split/combined amounts, multiple concurrent
assets, dynamic membership, real crash persistence, cryptographic aging, native
implementation behavior or physical links. No timing, throughput or liveness
qualification follows from enumeration. Mining participation is distinct from a
finalized reward, and both are distinct from final payment acceptance.

The [research boundary](../../docs/research/INTERSTELLAR_EXCLUSIVE_RIGHTS.md)
explains the assumptions, counterexamples and remaining protocol obligations.
