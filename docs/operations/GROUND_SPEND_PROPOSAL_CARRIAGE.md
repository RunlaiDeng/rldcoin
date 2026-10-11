# Native-retained Spend proposal carriage

The current Origin companion may include an already fully Native-authenticated
Spend proposal in its existing ordered carriage hint. Its separate extra filter
reconstructs the exact Native typed field order, checks the complete parent and
child command commitments, every supplied owner-intent signature, leader
signature, current parent/epoch/round and any complete timeout certificate.
Spend and Import commands retain their original bounds. Unknown commands and
incompatible profiles fall back to ordinary carriage; the default empty/Import
filter remains unchanged unless this Origin option is explicitly enabled.

This filter does not determine actual input owners, conservation, maturity,
quarantine, freshness, signing rights or ledger inclusion. Complete Native replay
and authorization remain mandatory before retaining the envelope, on cold startup
and at the destination. A changed envelope still needs its own full Native check.
The hint retains exact complete frame identities and original bytes. It uses the
existing ordered spare places, first offers, recent/history streams, fairness
rotation and wire/state/worker limits. It starts no worker or extra contact and
grants no receipt or custody. Missing or evicted hints keep ordinary carriage.

Signature models with empty evidence grant no Native authority. This interface
does not qualify payment percentiles, sustained faults, independent custody,
physical routes, cryptographic adoption or an existing network upgrade.
