# Earth transition authorization

This optional operator-local authorization binds one exact fresh Earth genesis preview, rule hash and implementation source. It is not a substitute for the four-signature Earth value adoption or source finality.

`TransitionAuthorizationStatement` is canonical compact JSON in its declared field order. Its format is `RLD-EARTH-SUCCESSOR-TRANSITION-AUTHORIZATION`; the signing preimage is that ASCII domain, a zero byte, and the canonical statement JSON. The statement includes the SHA-256 of this file, the exact preview ID, the empty genesis anchor, rule hash and source commitment. The signer supplies an Ed25519 signature; each node must separately pin that public key and the statement ID. Unknown or changed fields, noncanonical JSON, a changed genesis, stale preview, wrong rule or source hash, and invalid signatures fail closed.

The official direct Earth activation additionally requires the signed genesis PoW adoption, the four-signature value adoption, the empty height-zero anchor and explicit operator acceptance of their exact IDs. This optional authorization does not add a predecessor balance or make any historical candidate chain current.
