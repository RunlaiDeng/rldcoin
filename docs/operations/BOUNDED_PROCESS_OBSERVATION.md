# Bounded process observations

`tools/bounded_process_observation.py` observes the caller's existing command
and progress budget without a shell or an external timing wrapper. The caller
must retain its source, actual binary, fixture and command bindings and original
acceptance checks. The observer does not select tests, change compiler profiles,
extend budgets, initialize Native state or establish qualification.

Output is retained in a new private log; existing logs refuse before launch.
Direct child wait status remains separate from timeout and live-descendant
residue. An expired budget remains expired even if termination produces a zero
exit. Cleanup signals only the newly created owned process group; successful
cleanup cannot turn timeout or descendant residue into a passing observation.
Observations also distinguish whether that group is actually empty.

Resource observations use the operating system's direct child wait result:
user/system CPU, peak resident bytes, major faults, swaps and involuntary context
switches. These describe the child and its reaped descendants, not historical
host pressure or individual internal phases. Unreaped descendants are not added
to those resource fields. POSIX direct resource waiting is required; unsupported
platforms refuse rather than supply fabricated zero costs.

Raw output, command bindings, resource receipts and per-run outcomes stay local.
An observed exit or metric supplies no custody, ledger, signing, freshness,
independent-review, physical-route or complete-protocol authority. Only the
original scope's necessary checks can establish its corresponding result.
