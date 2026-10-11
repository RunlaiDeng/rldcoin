# Native ground listener and connection tasks

The ordinary pinned-TLS path in `interstellar_tcp.Server` uses
`RLD-NATIVE-CONTACT-LIFECYCLE-V1`. Rust owns the IPv4 listener, original two-entry
kernel backlog, accept loop, connection threads, session interruption and joins.
No Python listener socket or connection thread is created on this default path.
The node and native library must have matching source implementation identities.
Build them together with `cargo build --bins --lib` in the regional-ledger crate.

## Startup and callback custody

`ListenerPrepare` binds an independently configured literal IPv4 endpoint and
returns a process-local handle before creating a callback thread. The separate
`rld_contact_listener_start` C entry starts that known handle with one trusted,
thread-safe C callback. Its function pointer is a typed local ABI argument;
JSON and remote requests never supply executable addresses. At most 64 listeners
may be retained. Prepared listeners can be closed without ever starting a task.

The callback remains executable until native close has joined the listener and
all connection tasks. Start-response loss can still close the known handle.
Malformed or lost close observations retain the callback and service owner;
they cannot establish a successful join. Exact retry against the same native
provider can release them only after a proven joined-close response. Callback
exceptions fail the listener and never unwind across the C boundary. A callback
thread cannot close and join its own listener.

Service startup records its transport owner before starting it. An unproven
transport shutdown retains the service's descriptor and runtime owner. A proven
join with a callback error still drains the remaining local input thread before
reporting failure and releasing custody. These process observations are not an
independent latest-state anchor, recover-only authorization or power-loss proof.

## Shared admission and original clocks

The native loop keeps at most two live connection tasks. It also observes queued
and active deferred inputs, and performs final admission through the original
Python guard. Both paths share the original two receiving slots. A completed
connection may hand its slot to one already authenticated deferred input; no
extra application queue, worker, receipt or value authority is created.

Occupied slots wait only within the original 0.2-second local handoff window,
outside mesh locks. Further connections are refused without custody assertions.
Completed native threads are joined before their handles are reused as capacity;
the join inventory stays bounded by two. Native listener descriptors are marked
close-on-exec and retain the existing reuse-address and literal-endpoint policy.

Each accepted connection receives one native monotonic three-second deadline.
The callback and TLS/frame operations preserve it without rebasing. Private
certificate policy, complete challenge/reply authentication, canonical frame
bounds, durable carriage before connect and actual custody before acknowledgment
remain mandatory. Shutdown stops new admission, interrupts retained sessions
without taking their I/O mutex, and joins every callback/task before success.

## Remaining migration and qualification

Python still executes the existing authenticated mesh/custody callback, deferred
input consumer, outgoing scheduling, service orchestration and remaining wallet
flows. Explicit ground insecure mode retains its separate Python listener path;
it is never a fallback from native TLS failure. Native listener completion grants
no ledger acceptance, signing, finality, maturity, spendability or refunds.

Immutable archive publication, mutable state/index file publication and retained-file synchronization use the
[native storage interface](NATIVE_CONTACT_STORAGE.md). Complete mesh and ledger
authentication and signed-index selection remain separate caller obligations.
The [native shared-frame state codec](NATIVE_CONTACT_STATE_CODEC.md) owns bounded
packing and complete-record reconstruction; its output still requires that
authentication.

This interface does not qualify independent operations/custody, hardware or power
interruption, long history, full BFT fault profiles, PQ cryptography, physical
routes or mainnet. Changed native source requires fresh signed no-value fixtures;
old ledgers, balances, custody and stopped failed stores are never migrated or
reopened for replacement qualification.
