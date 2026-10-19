# Explicit trusted caller control and block-only ingress

This fresh NO_VALUE_ONLY local application profile makes unattended native
ingress recoverable while preserving exact owner authorization. The operator
explicitly supplies a private trusted caller-head file. Its integrity and latest
state are local trust assumptions, never independent freshness, exclusive key
custody or all-state rollback protection. Native monetary/work/issuance, owner
signatures, disputes and reward maturity are unchanged. This is not adoption,
continuous fee service, physical-route or composed G1-G11 qualification.

## Storage and execution

The caller journal uses RLDFSES1 with local version2 and suite1. Its229-byte
header appends a fresh nonzero random32-byte instance after the existing creation
clock; record framing is unchanged. This distinguishes independent caller roots
even with the same genesis, native initial head and exact creation clock. The
instance grants no signing or monetary authority. Legacy version1 create/open/recover cannot open it; controlled
interfaces refuse version1. Use fresh roots and head files, without conversion,
fallback, migration, truncation or removal of failed residue. Native and actor
journals keep their separate existing formats and full authentication obligations.

The trusted file is big-endian RLDFCALL8, version:u16=1, suite:u16=1,
caller_header_hash32, previous_snapshot_hash32, committed_caller_head32,
pending_length:u32, exact_canonical_pending_intent, snapshot_hash32. Snapshot hash
uses SHA256(RLD-FAST-SESSION-1/CONTROL followed by NUL and all preceding bytes).
The caller header hash binds the complete229-byte version2 header, genesis,
chain, original native head, creation clock and independent instance. Neither checksum grants value.

Pending bytes use exactly the existing typed canonical Intent JSON: id, action,
at. They retain one nonzero request ID, complete key-free Action and original
observation time, never a password, raw key or decoded ledger. Maximum pending
length is1048507 bytes, within the unchanged caller record bound. Maximum snapshot
size is1048651 bytes. At most one same-bounded path.next publication candidate
exists. The separate private path.lock holds the exact caller header hash under
an exclusive stable-inode lease; warm operations recheck its bytes and identity.
Caller/actor32-MiB,65536-request,16-actor and all native limits remain unchanged.

Before any caller intent or child mutation, publish the complete pending request
while retaining the prior committed caller head. Each publication exclusively
creates path.next, synchronizes file and parent, checks its exact predecessor,
renames over the head file and synchronizes the parent again. After ordinary
Session execution has retained/audited its child effect and complete reply,
publish the completed caller head with no pending request before response release.
A failure suspends new execution until explicit reconciliation. Read observations
and current in-memory heads cannot supply a replacement latest-state witness.

## Recovery

Normal startup requires a completed trusted snapshot with no candidate residue,
an exact caller head/header match and complete native/caller/actor replay. Recovery
may finish only the exact retained pending intent, not first-execute it. Canonical
caller inspection selects a path but grants no authority. Full ordinary session
audits must precede completion or control publication.

If the caller is still exactly at the trusted prior head, fully audit unchanged
native/actor state and clear only the unused control preparation. If exactly that
request was retained, require its complete canonical bytes, prior head, ID, digest
and original time, then use ordinary keyless recovery. An already retained child
effect is verified; absence is resolved without first preparing, signing, accepting
a block or releasing a reservation. A commit candidate requires a complete audited
reply at its exact nominated head; it cannot justify completing a pending caller.
An unpublished prepare candidate requires the unchanged prior caller state.
Unknown advances, changed requests, damaged tails, mismatched bindings/candidates
or future clocks refuse without repair. No wallet key/password or socket is needed.

Interfaces are create-control ROOT GENESIS PIN TRUSTED_HEAD_FILE,
serve-control ROOT GENESIS PIN TRUSTED_HEAD_FILE, and
recover-control ROOT GENESIS PIN TRUSTED_HEAD_FILE. Manual requests still supply
their exact current session head and persisted review/approval references. A
background native change can invalidate a review; never rebase its approval.

## Explicit block-only background operation

serve-control may select --peer-root PEER_ROOT --peer-head-file PEER_HEAD_FILE
and separately enable --auto-import-blocks. Automatic mode requires both explicit
trusted-file controls. It processes at most one retained received kind1 packet
per loop, rotating among the bounded retained IDs. Complete peer authentication,
admission and durable data custody precede use of its bytes.

Before retaining a caller request, nonmutating native prevalidation checks the
actual prefix/current head, exact duplicate bytes, complete parent history, work,
signatures, ownership/value execution, eligibility and existing resource bounds.
Ordinary native acceptance independently repeats those checks. Known exact blocks
need no new caller request. Missing parents, invalid blocks, clocks and exhausted
capacity retain data and report a diagnostic; no receipt becomes ledger authority.
Later rounds can reconsider original bytes after dependencies or clocks change.

The local request ID is the session AUTO-BLOCK domain hash over exact chain32,
native block ID32 and prior caller head32. It selects one key-free Native action
against the current selected tip. Full execution is required regardless of that
hash. Recovery never first-executes it; a later ordinary round may submit a new
request if the block remains absent. Original peer queue times are retained.

Other packet kinds cannot register actors, prepare or sign payments, grant user
approval, submit a fee claim or choose a trusted caller head. No mining service,
fee-solvent challenge monitor, automatic forwarding, discovery or multihop route
is implied. Operator diagnostics and counters are not payment completion evidence.
Independent latest-state/key protection, power-loss/cross-device custody,
resource/history/archive/mass exit and actual composed latency/daily100M remain
separate requirements. Frozen paper/PDF, supply and all acceptance gates remain.
