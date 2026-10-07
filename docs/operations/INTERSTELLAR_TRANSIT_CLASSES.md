# Bounded recent and historical transit scheduling candidate

Private scheduler `RLD-CONTACT-TRANSIT-SCHEDULER-V4` labels at most 32 actual
newly retained unreceipted packet IDs as recent. Enqueue and authenticated receive
publish those labels with the complete packet state. Repeated packets, shorter
authenticated paths and retained archives never become recent again. Label
eviction removes no evidence; stale syntactic labels intersect only actual active
packets and grant no custody or ledger rights.

Each pinned neighbor retains independent nullable last-prepared recent and
historical packet IDs. Each class skips received, unroutable and verified-hop
suppressed rows before allocating its slot. Both classes rotate by sorted successor and interleave
within the original four outgoing slots. Eligible nonempty classes normally
receive two slots each; route, suppression and byte eligibility still apply.
A single-packet wire budget alternates the leading class using a bounded
per-peer preparation counter. An empty preparation advances one examined start
and the leading class. These are preparation steps, never delivery observations.
The original aggregate packet cursor records the last actual prepared packet for
diagnostics. All cursor publication precedes socket or spool I/O; failed sends
retain complete signed bytes and revisit them through rotation.

Receipts and normal completion archives remove only corresponding recent labels.
Unreceipted transits remain active. Original 256-message/64-MiB active admission,
four transits, sixteen receipts, archive 4,096 files/256 MiB, wire Mesh V3/TCP V4,
exact challenges, TLS pins, complete transit/envelope authentication and Native
owner/value/finality/caller-head rules remain unchanged. No peer priority,
unchecked header cache, proof pruning, Native rule change or timeout increase is
introduced. V3 and older private identities/stores refuse unchanged; use fresh
fixture directories and pins. Failed L and earlier payment custody stays stopped.

Tests cover a 96-packet mixed pool across cold reopen, continual authenticated
local additions with historical progress, one-packet and zero-packet budgets,
per-peer isolation, publication failures, duplicate/malformed receive, bounded
metadata, old-format refusal, absent labels, and actual three-carrier pinned-TLS
worker delivery with both classes and retained destination receipts. Synthetic
transport authentication is separate from Native inclusion and spendability.
Fresh frozen ordinary payments, full cold verification and subsequent fault
qualification remain required; local checks alone cannot qualify them.
