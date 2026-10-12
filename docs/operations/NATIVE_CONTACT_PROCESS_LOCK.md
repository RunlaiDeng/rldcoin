# Native process lock ownership

Mesh instance, regional startup and service ownership use the matching sibling
library's `RLD-NATIVE-CONTACT-PROCESS-LOCK-V1`. The explicit independent Python
flock/directory oracle is `interstellar_process_lock_reference.py`; native refusal
never selects it as a fallback.

## Directory and fixed roles

Native directory traversal requires an absolute path, checks every existing
ancestor without following symlinks, opens retained directory descriptors and
creates missing directories with mode `0700`. Existing permissions are not changed.
The ordinary `safe_dir` interface retains its previous ancestor-symlink refusal.

The only lock roles are `Mesh` (`.lock`), `Startup` (`.startup.lock`) and `Service`
(`.regional-contact-service.lock`). Opens require no-follow regular files and
create missing lock files with mode `0600`. Locks retain the original exclusive
OS semantics: Mesh and Startup may block, while Service is nonblocking. No
new lock deadline or timeout grants ownership, custody or value.

## Handles and failure boundaries

The typed `rld_contact_process_lock` ABI accepts canonical controls up to 8,192
bytes. At most 256 process-local pending/held handles are admitted. A caller
preselects a fresh opaque token, permitting cleanup after a lost acquisition
result. Handles contain no executable address and are not accepted from peers.
Controls/results bind the current native implementation, token, exact path and
role; the bridge retains the acquiring library for later release.

Reserve the token before opening/waiting, then release the global table mutex
before OS flock. A waiting reservation cannot report owned or released. Failed
acquisition removes only that exact pending reservation. A duplicate token
refusal never closes the existing owner. No directory or lock file is removed.

Release verifies the original process/path/role and closes the actual owned
descriptor. Successful repeated release is idempotent, including a lost success
response. An uncertain descriptor-close failure retains an unhealthy record and
refuses success; it never blindly retries a potentially reused descriptor number.
SDK tokens are fresh for each acquisition and are never deliberately reused.
Forked/copying process state is not an independently qualified lock or custody
transfer; lock descriptors are close-on-exec.

## Lifecycle and authority

Constructor rollback closes only its acquired lock. Service close preserves
the original outgoing/incoming/runtime/publisher order. Unknown native task join
keeps the service owner and callbacks retained; a local close request alone is
not proof of shutdown. Process termination releases OS ownership while keeping
the lock file and all state/evidence intact.

Responses carry `ledger_authority: false` and `custody_acknowledgment: false`.
Local exclusion never authenticates native history, establishes freshness,
releases signer/owner locks, authorizes signing, or acknowledges evidence custody.
Caller heads, full native replay, admitted validator rules and value checks remain
separate and mandatory.

Python still performs mesh/service scheduling and remaining wallet/runtime flows.
Finite same-host process tests do not qualify power-loss, independent or cross-device
custody, full fault/load, long history, cryptographic adoption, physical routes or
mainnet. Changed native source requires fresh signed no-value fixtures; old failed
stores, candidate balances and private custody are never migrated for qualification.
