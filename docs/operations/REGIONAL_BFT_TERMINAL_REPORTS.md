# Ground campaign terminal reports

Three-region and joint-cycle controllers share the same owned-process cleanup
as the role-payment controller. Keep an owned child until its wait is terminal;
a failed wait leaves the exact handle registered. Try all other owned children
and close all logs even if one child fails. Forced/nonzero shutdown remains an
unclean outcome after a later empty cleanup.

Write the terminal report after cleanup. Retain the original stage or fixture
initialization error separately from a cleanup failure. `completed` requires an
actual successful run and verified clean shutdown; unknown ownership cannot
produce success. An existing terminal report refuses before fixture creation.
Reports record the exact caller and shared terminal-helper source commitments.
No cleanup action recovers Native responses, changes caller heads, releases
wallet reservations or grants ledger/transport/finality rights.

Checks include actual subprocesses at both CLI entrypoints, one exit 7 with two
live peers, stage plus cleanup errors, caught earlier cleanup failure, complete
clean shutdown, failed-wait tuple ownership, constructor refusal and existing
report preservation. The exact frozen prior controller demonstrates premature
ownership loss after a wait error and a success report written before an unclean
shutdown. These are controller checks, separate from ordinary Native payments,
full cold validation, fault liveness and independent custody qualification.

Current role-payment runs use their frozen source unchanged. This supplemental
repair enters a future separately frozen three-region controller only; it never
retroactively changes an old run or its report.

Fresh three-region setup separately retains each carrier's public identity,
network and exact mesh configuration commitment before any ordinary process
starts. The terminal report binds that anchor file's original digest. Cold
verification first requires completed, failure-free, stopped and clean terminal
observations, then checks the exact setup anchor inventory and opens only
MeshInspection. It never derives an anchor from the inspected private identity,
constructs a normal Node, signs or repairs transport state. All full Native,
owner/receipt, caller-head, retained-envelope and transport archive checks remain.
Old reports without these anchors refuse; they are preserved without conversion.
