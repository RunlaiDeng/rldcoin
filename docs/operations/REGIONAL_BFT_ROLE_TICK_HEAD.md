# Fresh voter-head check within the ordinary tick

Verification-only ground candidate; transport receipts do not grant ledger or signer authority.

The new ordinary scheduling candidate defers the first of those two voter
observations only in `Runtime._tick`'s private role-loop entry. Role advance still
reads actual native membership, resolves pending responses, flushes retained
responses and validates any new voter creation. A false role result immediately
returns to Runtime's existing fresh native context and signer/head check, before
consensus signing or timeout. A pending handoff performs the native voter check
before any further fence/readiness operation. Standalone role tick and advance
retain their immediate native voter checks.
