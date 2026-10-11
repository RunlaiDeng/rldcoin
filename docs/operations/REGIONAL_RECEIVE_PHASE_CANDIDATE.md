# Origin receive and phase observation candidate

This is an unadopted ground performance candidate. The companion's
`regional_bft_receive_phase.CANDIDATE_ENABLED` is false. An explicitly selected,
bounded local controller may exercise it; ordinary runtime configuration does
not enable it. It does not qualify payment finality, maturity, custody, history,
physical routes or an adopted network.

## Native operation

`bft-origin-network-receive-phase` requires the explicit signed Origin network
profile, a canonical ordered batch, the independently retained native storage
head, the original signer directory, its separately retained exact caller head
and the configured signer identity. Its response domain is
`RLD-BFT-ORIGIN-RECEIVE-PHASE-V1`.

The operation retains the original complete receive ordering and authentication:
bounded admission, authentic conflict retention, complete envelope verification
and native dependency/certificate synchronization. It then fully replays the
original signer journal once against that current native Store. The Store lock
remains held across both operations; the actual signer lock remains held through
response serialization. It never signs, initializes a journal from a decoded
status, grants independent freshness or substitutes for later signing checks.

The original four-envelope unit, 8 MiB input/output, 3 MiB individual network
payload and logical history/evidence limits remain unchanged. Every complete
envelope is authenticated, including a later envelope whose body is already
retained. An authentic conflict remains quarantined even if a later envelope is
invalid. A forged signature cannot create an incident or credit value.

## Refusal and recovery

Receiving a complete certified prefix can commit before signer inspection or
complete response serialization refuses. This preserves the original separate
receive-then-observe semantics. A signer lock, stale caller head, interrupted
output or complete-output capacity refusal releases no success response and
does not undo an already authenticated prefix. Preserve the complete received
input and separately retained caller state. There is no fallback or replacement
signing request after the mutating operation begins. Cold recovery performs
ordinary full native verification; an incomplete response is not an acknowledgment.

## Companion consumption

The companion captures an immutable bounded observation only after every
complete received envelope has been durably retained. It consumes that
observation once, within the same finite Service unit and exact caller/native
domain. Changed caller state, pending requests, unreleased responses, a new
unit, configured signer directory or identity, region, failures and restart discard it. Known companion native mutations
invalidate it. A concurrent Native change still refuses the independently
pinned later signature; the observation cannot authorize the stale request.
Keyless drain and unsupported profiles retain their original observation paths.

Scheduling telemetry grants no signing or value rights. A subsequent signature
still requires independently durable pending-before-sign, the original fresh
pinned Native open, full caller/journal/value validation and durable native
response/head publication before carriage release. The native journal remains
the signature linearization point. Neither the receive cutoff, legal Timeout
eligibility, quorum nor signed genesis parameters change. Input arriving after
the cutoff remains eligible for a later complete receive unit.

Every changed Native implementation requires a fresh signed no-value fixture
genesis/currency. Old stores, old failed scopes and old qualifications cannot
be migrated or inherited. Same-host process interruption does not establish
power-loss, cross-device or independent custody qualification.
