# Owner-authorized eventual mainnet deployment

The owner instructed on 20 October 2026: finish implementation, then launch the
mainnet on `galaxy@35.200.194.179`. This is conditional launch authorization; it
supersedes the prior blanket no-mainnet instruction after functional completion.
It does not make incomplete code complete or permit old balances/keys to migrate.

## Verified target

Read-only SSH with strict existing host-key verification succeeded on 20 October.
The host runs Ubuntu on x86_64 with 2 virtual CPUs, approximately 3.8 GiB RAM,
no swap and approximately 13 GiB free on its 19 GiB root filesystem. The live
`bbb-backend.service`, `bbbfi-pool-analytics.service` and Nginx must remain intact.
The BBBFi backend uses loopback 4021; Nginx uses 80/443. There were no existing
`/opt/rldcoin`, `/var/lib/rldcoin` or `/etc/rldcoin` deployments in this inspection.
These observations are point-in-time facts, not reserved resources or proof of
future capacity. No server files, service state or network rules were changed.

## Prepared layout

- Versioned Linux executables: `/opt/rldcoin/releases/<reviewed-source-id>/`.
  An atomic `current` symlink selects the installed build. A macOS executable is
  not a Linux release artifact. Verify exact executable hashes and compiled guest
  image IDs before installing any monetary state.
- Public descriptor, independently approved peer pins and TLS config:
  `/etc/rldcoin/`. Use the separate native TLS listener on port 18443; the existing
  BBBFi Nginx configuration and listeners stay unchanged.
- Private state and encrypted vaults: `/var/lib/rldcoin/`, owned by a dedicated
  unprivileged `rldcoin` service account. The latest-head directory is outside
  the node store. This path separation is not independent rollback protection.
- `deploy/systemd/rldcoin.service` is a prepared unit, not an installed/running
  service. It uses a systemd encrypted credential passed through native stdin,
  process isolation and a resource budget intended to limit impact on BBBFi.
  That budget is not a demonstrated capacity envelope for Rldcoin.
- `deploy/config/node.json` is a syntax-valid template. Empty neighbors create no
  remote route. Its local prover is disabled; a complete authenticated proof-worker
  arrangement is still required. No host is silently trusted through discovery.

A production credential must be created through echo-free local/native input and
an encrypted systemd credential; never put vault passwords in argv, environment,
unit text, Git, deployment logs or HTTP. Do not copy another project's keys or
credentials. TLS keys and fresh monetary keys have different purposes.

## Launch sequence after completion

1. Resolve the functional and operational completion boundaries recorded in
   `docs/IMPLEMENTATION.md`. Preserve real failed evidence and compile/runtime
   distinctions. The owner has not authorized replacing those requirements with
   a cosmetic readiness flag or an unmeasured claim.
2. Select and publish the intended monetary authority/validator structure. One
   machine is one failure/custody domain. Four processes on this server are not
   four independent operators. The supported f=0 single-validator profile has no
   Byzantine redundancy; do not claim otherwise.
3. Obtain a reviewed Linux build, its dependency locks, real guest image IDs and
   exact file hashes. Determine feasible full public-inventory and monetary-proof
   generation resources; the target machine has not been qualified for that work.
4. Create a separate authentic monetary currency descriptor, fresh identity and
   position/controller keys and a zero-issued, zero-allocation genesis. Perform
   actual inventory admission proof and exact descriptor approvals. No test
   currency, old fixture state, previous balance or old key migrates.
5. Install only the versioned RLD release and its isolated configuration/state.
   Configure IP/hostname-valid pinned TLS, independently approved neighbors and
   the explicitly scoped new listener/firewall route. No existing service is
   stopped, replaced or given RLD secrets.
6. Initialize from the approved genesis, then start the monetary service. Verify
   actual reported currency, genesis, binary/profile, issuance counters, service
   health and subsequent certified inclusion. Service startup or transport custody
   is not proof of settlement, revenue, daily throughput or interstellar delivery.
7. Publish the actual public descriptor and usable ordinary-user connection/mining
   instructions after the network exists. Monitor resource admission and funded
   retention; stop unsafe signing on conflicting certificates or unreconciled heads.

## Current disposition

Implementation is not complete, so monetary keys/genesis and mainnet launch have
not been performed. The server address is an accepted deployment destination,
not evidence that a monetary network is running. No additional launch permission
is required within the user's existing conditional authorization; the missing
condition is completion, not approval.
