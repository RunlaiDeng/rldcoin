# No-value BFT capacity fixtures

These fixture sources use public test seed keys and a fresh signed zero-allocation
profile. Generated stores, keys and caller heads stay private. Existing fixture
roots refuse; failed signed state is never a template for another execution.

`src/window.rs` exercises checkpoint retention and full-store refusal.
`src/custody.rs` exercises complete Agent journals and separately retained caller
heads. `src/cost.rs` separates measured operation classes without granting ledger
or signer authority. Run with two positional arguments: a fresh private root and
the separately reviewed exact Native implementation identity. Mismatched identity
refuses before fixture creation.

Use an explicit process-group wall-clock budget including compilation. Keep
original certificates, limits and failure residue; never launch unbounded or
raise capacity to complete a scope. These fixtures cannot qualify independent
freshness, power loss, sustained load or an ordinary-node campaign.
