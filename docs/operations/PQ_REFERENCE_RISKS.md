# Hybrid reference admission risks

The reference tools are verification-only candidates outside adopted monetary
profiles. Independent security review and authenticated P1–P8 adoption remain
required; another implementation under the same author is not independent custody
or a complete independently audited protocol implementation.

## Weak Ed25519 public-key admission

The earlier reference delegated key admission to OpenSSL. An identity Ed25519
public key and identity-R/zero-S forgery could pass alongside a valid ML-DSA87
half over the same message. The Core admission checks reject this key. A valid PQ
half must not hide the loss of the classical authorization half.

The reference now explicitly decodes canonical compressed points and rejects
identity, small-order and mixed-order public keys using the prime-subgroup
condition. Signature R must be canonical, nonidentity and prime-order; its scalar
must be below the group order. These checks precede OpenSSL verification, and
both actual signature halves remain mandatory. Regression sources cover the
forgery, malformed points/signatures, finite policy scope and original dual paths.

Public-point arithmetic follows
[RFC8032 sections5.1.3/6](https://www.rfc-editor.org/rfc/rfc8032.html). It handles
public data only and does not replace signature verification or provide a
production cryptographic qualification. Adopted Core/Native keys, rules, balances
and locks are not changed by this reference repair.

Full malicious-key/proof corpora, independent security review, side-channel and
entropy qualification, complete protocol interoperability, delayed revocation,
finite journey horizons and monetary adoption remain open. Internal reproducer
outputs and historical failures are retained locally.
