# Native BFT command selection

Ordinary Runtime candidate construction delegates ordered command trials to
`bft-candidate-select`. Python transports bounded batches and maps the returned
indices; it has no command-validity or trial fallback algorithm. The original
Python selection algorithm remains in a test-only reference module.
Retained submissions and pending imports keep their original order. A joint
profile's explicitly selected plan keeps its original first position. Highest
prepared values still require the exact retained proposal and normal Native
timeout/lock checks; this interface does not replace that path.

Each input contains exactly `context`, `selected`, `seen` and `commands`.
The complete typed context must equal the current independently replayed Native
Store under its operating-system lock. An input carries at most sixteen new
commands and four already-selected commands, within the existing 8 MiB byte
bound. Duplicate and unknown JSON fields refuse. Selected commands must be
distinct, occur in the ordered distinct seen-ID set, and fully execute again
under this invocation's current trust, history, finality, owner and safety state.
Neither seen IDs nor caller-carried selected commands initialize a ledger or
grant authorization.

Rust processes each new distinct command in order through the ordinary
`Store::bft_candidate` execution path, retaining a maximum of four user commands.
Automatic channel challenges retain their existing shared slot and priority
rules. Invalid trials do not delete, rewrite or cancel submissions. Duplicate
IDs schedule nothing; they cannot authorize value. A failed initial Store lock
or changed context returns no partial selection. The retained prefix is checked
again before returning selection metadata. No block, caller head, owner or
validator signature is published by selection.

The bounded response identifies the exact raw request, complete context,
ordered seen set and each attempted command's index, canonical ID and choice.
The Python adapter verifies every binding, field, order, index, count and flag
before mapping commands. There is no older-binary or Python trial fallback.
The seen set exists only during this construction operation, never on disk.
Large queues rotate through bounded requests without raising transport, history
or Runtime retention limits. An input that cannot fit refuses while preserving
all queued submissions.

Final construction uses `bft-candidate --context FILE` with the complete original
context and selected commands. This independently opens/replays Native again
and refuses any intervening context change before constructing a complete
ordinary candidate snapshot. Existing explicit CLI calls may omit the context
option; ordinary Runtime construction supplies it. Every later proposal,
prepare/commit, certificate and installation retains its separate original
Native checks. Selection receipts are neither signatures nor finality.

Diagnostic candidate markers observe completed Native trials when their batch
response returns. They do not claim individual trial start times or replace
any submission's original payment clock. No local scheduling improvement proves
the regional payment latency distribution, ordinary network fault liveness,
independent custody or complete whitepaper acceptance.

Changed Native source requires a fresh signed no-value genesis and private
fixture/custody directories. Existing failed scopes, balances, keys and custody
are not reused or converted. Full consensus scheduling and contact transport
retain Python responsibilities pending further migration; mainnet adoption,
physical routes and long-history qualification remain separate requirements.
