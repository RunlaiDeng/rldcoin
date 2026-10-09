# Bounded frame hashing during outgoing preparation

`interstellar_mesh.Node.prepare_exchange` may share SHA-256 arithmetic within
one synchronous preparation operation. It still prepares the complete exchange
and durably publishes its outgoing rotation before opening a network connection. Selection,
carriage limits, custody acknowledgment and native ledger authorization remain
governed by their existing checks.

The witness matches the complete canonical bytes preceding a frame and the exact
immutable frame string. It retains an unfinished SHA-256 state for that prefix;
every invocation canonically encodes the current surrounding fields and hashes
the current suffix. A frame identifier, supplied digest or previously validated
ledger cannot initialize this witness. The resulting digest and length must equal
hashing the complete canonical object, including changed signatures, nonces,
destinations and hops.

Only bounded strings containing ASCII bytes that require no JSON escaping use
this path. Other shapes, encodings and capacity refusals use the original complete
computation. Signature, routing, admission, archive, contact and native evidence
validation continue independently. Digest agreement grants no authentication,
custody, signer, finality or value authority.

One nonblocking process-local owner retains at most 8 MiB of conservatively
accounted input/hash storage, at most 512 frame entries and 512 prefix entries,
and at most 8192 preceding canonical bytes per retained prefix. Contending threads
compute complete commitments without waiting or creating another witness. Nested
synchronous preparation shares the same budget. Return or failure discards every
retained frame and hash state and releases the owner; nothing is serialized.

For repeated exact frame/prefix inputs, hashing the large frame can be shared
while each current suffix is still processed. Distinct frames, canonical metadata
work, cold authentication, durable writes and full native replay retain their
costs. This arithmetic optimization does not establish regional payment latency,
ordinary scheduling liveness, complete fault-profile success, long-history
qualification, independent custody or physical routes.
