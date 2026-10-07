# Bounded public-key material retention

The regional ground candidate may retain up to 64 exact canonical Ed25519
public keys and their parsed verification material in one shared process cache.
Only the unchanged Core canonical encoding, curve point, weak-key and prime-order
subgroup checks may initialize an entry. Cache lookup compares the entire
canonical lowercase public key. Uppercase or otherwise altered encodings cannot
reuse a validated entry. Native key-material admission and message verification
share these entries. Each material miss invokes the original Core validator;
a hit returns the same fixed-suite material predicate result. Currency identity,
implementation, rules, validator membership, role, epoch and purpose are still
checked independently at every original authorization boundary.

Every received or retained message independently runs the same strict Ed25519
signature verification over its complete signing bytes. Signature bytes, message
success, admission membership, role, epoch, proof, ledger, caller head and signer
lock are never cached here. Fully executed Native genesis/history, complete
retained signer records, original request semantics, quorum signatures and
current incident/safety guards remain mandatory. A public material entry cannot
authorize an identity in a new trust set or epoch.

The cache has one shared 64-entry ceiling across workers. Least recently used
material is evicted before admitting another entry. No mutex is held during
curve checks or signature verification. A miss, eviction, restart or poisoned
mutex falls back to the full original Core material checks. Invalid keys never
enter retention; a valid key may be retained independently of whether a
particular message has a valid signature. That entry grants no message authority.
No cache is serialized or restored from disk, and no transport or evidence
capacity is changed. The entry ceiling bounds retained key material, not total
process memory or transient verifier allocations.

The source unit cases compare exact results with the original Core verifier
for warm valid messages, changed messages, wrong signatures, malformed signatures,
noncanonical, small-order and mixed-order keys, eviction and poisoned retention.
Key-material predicate cases also compare exact success and error results with
the original Core validator after warm signature verification, eviction and
poisoning. A changed message still requires its own strict verification. Test signing
seeds are public no-value verification vectors. The ordinary signed Native
fixture observes material reuse while still counting actual strict verification
attempts, then independently replays Native and complete signer/wallet journals
from genesis under separately retained heads. Its clocks measure original
append, publication and old-record boundaries only in test builds; timings and
witness counts never enter signed inputs, journals or consensus decisions.

This is public-key parsing acceleration for the existing ground suite. It does
not adopt a new cryptographic suite, qualify independent custody or freshness,
prove complete fault liveness, or authorize mainnet, money or physical routes.
