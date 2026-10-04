# Exact installed historical epoch observation candidate

`bft-installed-epochs` is a separate bounded Native observation after the ordinary
locked store open has fully replayed pinned genesis, blocks, finality, incidents
and local epoch events. It walks complete ordered local `Event::Epoch` selections,
returns their exact original retained proofs, verifies the predecessor order and
requires the last selected epoch to equal the fully replayed current chain epoch.
Known verified remote evidence and unselected retained proofs are excluded. The
original 16-epoch and 8-MiB Native bounds remain; an unhealthy publication or
authenticated local-region quarantine refuses. The query changes no journal,
caller head, signer lock or custody. It is not independent latest-state protection.

The companion first authenticates every complete incoming envelope and synchronizes
new certified dependencies. Only then may it compare complete canonical incoming
proof bytes with this fresh Native observation. Exact already installed historical
proofs need no redundant pack/activation operation. A different valid proof variant
still takes Native activation; invalid later envelopes refuse before comparison,
deduplication, signing or head changes. No Python witness or hash initializes a
ledger, selects an epoch or substitutes for signature or owner/value execution.
Original body/envelope bytes, local flags, all evidence and all bounds stay retained.

A previous stopped ordinary cycle recorded 59–144 explicit activation calls in its
last processes, taking 29.2–82.45 seconds per process. Those stage observations are
not a unique failure cause or an isolated benchmark. This candidate needs its own
Native/process regressions and fresh ordinary three-era payments/cold verification.
Its changed Native implementation requires fresh signed no-value genesis/currency;
no retained failed balances, private stores or custody migrate. Full fault,
independent custody/freshness, long-history and physical qualifications remain open.
