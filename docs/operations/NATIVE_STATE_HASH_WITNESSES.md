# Bounded worker-local state hashing witnesses

The Native V1 ordered Merkle commitment remains unchanged. Every invocation
audits the complete supplied ledger and compares every exact current typed
coin, export and permanent import record before reusing a leaf. Branch reuse
requires both exact children and the original collection/level domain. Counters
and channel commitment derive from the current audited input each time.

At most two process-only thread slots retain these optional hashing witnesses.
All slots share the original 8-MiB retention budget; another large witness evicts
older slots rather than multiplying that limit. Least-recent slot eviction,
thread exit, a cache miss or poisoning removes only hashing acceleration. Full
uncached reconstruction yields the same root and proof dialect. Failed audits
preserve an existing slot; no partial replacement root is published.

These witnesses have no serialization interface and retain no signing, trust,
ledger-adoption or latest-state authority. Computing a root does not validate a
serialized ledger, authenticate a certificate or authorize a payment. Actual
Native owner/value execution, complete incoming proof authentication, cold
replay, independent current heads and incident checks remain mandatory.

The coin/proof/archive limits and all consensus, maturity, signature and storage
rules remain unchanged. The retention accounting is the existing typed-record
and tree budget, not a bound on total process resident memory or allocation peaks.
Native history, independent custody and physical-route qualification remain
separate acceptance obligations.
