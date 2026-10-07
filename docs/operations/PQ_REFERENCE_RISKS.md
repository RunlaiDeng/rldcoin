# Hybrid reference admission risks

The reference tools are verification-only candidates outside adopted monetary
profiles. A passing finite scope never replaces independent review or P1–P8.

## PQ-REF-01: weak Ed25519 public-key admission

**Confirmed and locally repaired; broader review remains open.** Under source
published at a95447d7c, the actual OpenSSL reference accepted an identity Ed25519
public key and identity-R/zero-S forgery alongside an unchanged valid ML-DSA87
half over the same public manifest. Actual Core1835d169 refused it. No private
key or signing was needed. V38 is FAIL, retained with source and public inputs;
V37 remains only its limited original23-case observation, not safe admission.

The fix explicitly decodes canonical compressed public points, rejects identity,
small-order and mixed-order points by the prime-subgroup condition, and requires
canonical nonidentity prime-order signature R and scalar below the group order
before calling OpenSSL. Public-point arithmetic follows
[RFC8032 sections5.1.3/6](https://www.rfc-editor.org/rfc/rfc8032.html); it neither
handles secrets nor replaces signature verification. Both actual signature halves
remain mandatory. No adopted Core/Native rules, keys, balances or locks changed.

V39 passed three public-point regressions, the related23 manifest cases, six
additional forgery/encoding guards and an existing genuine PAYMENT dual signature
in1.784655 seconds, original60 cumulative2.245997 including V38. Original evidence,
backend/source/controller bindings and all failures stay local. Full malicious
key/proof corpora, independent security review, side-channel qualification,
complete protocol interoperability and monetary adoption remain open.
