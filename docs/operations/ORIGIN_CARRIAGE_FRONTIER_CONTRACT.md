# Origin carriage scheduling positions

The Origin companion keeps separate process-local positions for current-parent
and historical carriage. A growing list of complete retained Timeout envelopes
can insert before a positional index and repeatedly skip a waiting Prepare.
Seeking after the last emitted immutable message/peer pair preserves progress
across those insertions and deletion of a previously emitted pair.

The ordinary unit still enqueues at most four pairs. When both classes have at
least two pending pairs, it normally selects two from each; a short class donates spare
slots. During the one callback after a fresh local Native Propose has completely
returned and been retained, an unambiguous exact current Proposal may instead
reach all of its at most three configured recipients in that same four-item
unit. Three Proposal copies leave one historical place. One or two recipients
retain up to two historical places; spare places use the ordinary selection.
The hint binds the just-released round, own leader key and configured recipient
set, under the complete Native-observed parent context and authenticated retention.
Missing copies, ambiguous candidates, unsupported recipient counts and absent or
changed context retain the ordinary selection. The hint is cleared on callback
return or failure and is never serialized. Later broadcasts, retries and cold
restarts use the ordinary reservation; no additional enqueue unit is created.
Every exceptional unit with pending history retains at least one historical
place and advances its existing frontier. Existing same-peer Proposal and Prepare dependency selection still
applies. The first selection uses the existing durable cursor. Each successful
selection remembers the final emitted key in each class, ordered by body ID,
configured peer ID and complete envelope ID. An empty class retains its prior
position. These scheduling positions do not establish bounded liveness under
unbounded arrivals or an unavailable quorum.

Only an Origin runtime with fully Native-authenticated retention and an exact
Native-observed parent context may use the positions. Their domain binds the
runtime format, trust binding, Native authority/currency/ledger, region, local
node, configured transport and validators, parent context and capacity limits.
Round changes under the identical parent keep the positions. Parent, trust or
contact changes reset them. The combined domain and positions are bounded by
8,192 bytes; exceeding that bound uses the existing scheduling path.

Positions are cleared before fallible Mesh opening, enqueue, close and companion
publication. They become reusable only after those operations succeed. Restart,
missing Native observation, unverified retention, other profiles and capacity
fallback retain the original path. The positions are never serialized and never
initialize a ledger, signing state, caller head, custody or value authorization.

Complete envelope authentication, incident handling, durable receipt custody and
Native consensus checks remain required. This mechanism changes no network
payload, admission, quorum, maturity, round timeout or per-unit capacity. It
does not qualify whole payment progress, sustained fault liveness, independent
custody, an adopted network or physical routes.
