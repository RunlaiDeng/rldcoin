# Rldcoin survivor-first protocol specification

Status: **complete candidate contract, not an adopted network or qualified implementation**.
Profile identifier: `RLD-SURVIVOR-1`. Consensus version: `1`. Cryptographic suite: `1`.

This specification selects one baseline, rather than leaving consensus choices to
implementers. Its authority is limited to the new, rollback-permitted design.
Previously released papers, signed networks, experiments and qualification results
retain their original meaning. Publication does not upgrade any of them.

The requirements are: a capable surviving full node can produce blocks and execute
authorized transfers without another participant; disconnected peers can do the
same; interstellar contacts carry payments and validation history asynchronously;
reconnection can reverse payments, rewards and their descendants. There is one
currency and one locally selected history, not independently additive regional money.

“Any node” means any correctly operating full validating node with the pinned
genesis, the necessary authentic history, usable storage, a progressing clock and
mining computation. Spending also requires an authorized owner's signature. A
relay, an empty installation, a lost ledger or a device without power cannot satisfy
these prerequisites. Mining is probabilistic. No finite completion deadline, eternal
hardware lifetime, superluminal delivery or irreversible distant settlement is promised.

## Normative documents

1. [Consensus and binary formats](CONSENSUS.md): identity, encodings, mining,
   difficulty recovery, issuance, transfers, execution and branch selection.
2. [Node, wallet and delayed transport](OPERATIONS.md): durable transitions,
   recovery, reorganization, resource behavior, contacts and payment status.
3. [Conformance and obligation mapping](CONFORMANCE.md): reproducible public
   vectors, adversarial scenarios, old obligation disposition and release gates.
4. [Public vectors](vectors.json): machine-readable, deliberately no-value inputs
   and expected outputs. The [Rust vector tool](../../../tools/survivor-spec-vectors/README.md)
   checks the published bytes; it is not a production node.

[SPECIFICATION.json](SPECIFICATION.json) binds the exact normative documents and
vector file with SHA-256. This is a candidate revision commitment, not a signed
monetary adoption. The vector tool checks these commitments as well as vector values.

The prose defines the protocol. Vectors illustrate it and must agree; a disagreement
blocks release and requires an explicit specification correction, never an implicit
implementation preference. MUST, MUST NOT, SHOULD and MAY express requirements,
recommendations and allowed alternatives respectively. All integers and algorithms
are defined below; there are no runtime-selected consensus thresholds.

## Scope of completeness

The baseline fully defines accepted bytes, validity, selection, accounting, externally
visible state and required recovery behavior. Storage engines, user interface layout,
physical radios and performance optimizations may differ if those behaviors match.
It deliberately defines unknown versions, unsupported cryptography and missing
evidence as refusal or waiting, rather than pretending to specify future discoveries.

Specification completeness is distinct from implemented conformance, an independent
security argument, operational scalability, cryptographic lifetime qualification and
physical-route qualification. In particular, the emergency difficulty rule is a new
security tradeoff, not Bitcoin's established mainnet rule. Its attack resistance must
be measured before monetary adoption. Acceptance of rollback does not authorize
invalid signatures, supply inflation or concealment of unresolved operations.

Whitepaper integration must describe this exact contract and its limitations before
implementation is represented as its realization. Mainnet additionally requires the
separate adoption gates in CONFORMANCE.md and a new authenticated zero-allocation
genesis. This document creates no mainnet, coin balance or migration entitlement.
