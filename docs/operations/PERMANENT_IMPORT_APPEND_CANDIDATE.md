# Permanent import commitment and append candidates

These verification-only interfaces commit permanent import identifiers within a
currency and destination scope. They do not authorize an export, credit value,
consume a nonce, install a ledger root or replace Native replay. The caller must
authenticate its current root, policy, epoch and next nonce separately; arriving
signatures and retained proofs cannot supply freshness.

The scope is `currency_root[32] || destination_root[32]`. Identifiers are 32 bytes.
The bounded compressed radix commitment uses SHA-512, canonical increasing branch
positions and committed subtree counts. Proofs have at most 256 branch frames and
32,768 bytes. The candidate refuses duplicates and an append beyond 200,001 keys.
These bounds do not raise any Native ledger, archive or transport limit.

`crates/rld-core/src/permanent_import_candidate.rs` verifies complete canonical
membership/absence proofs and derives a one-key append root. Its Python counterpart
is `tools/permanent_import_index_candidate.py`. Shared public vectors are in
`vectors/permanent-import-index-candidate-v1/`.

The dedicated `PERMANENT_IMPORT_APPEND` authorization binds the following bytes,
in order, under SHA-512:

```
RLD-PERMANENT-IMPORT-APPEND-CANDIDATE-V1\0
scope[64] || previous_root[64] || query[32] || new_root[64]
|| previous_count[u32 BE] || new_count[u32 BE] || SHA512(complete_proof)[64]
```

Both actual Ed25519 and ML-DSA-87 signatures over the same candidate intent are
required. Payment, finality and archive-manifest purposes cannot substitute for
this purpose. The existing finite policy horizon, caller trust and nonce checks
apply. An old absence proof under a newly authenticated current root refuses.

The standalone Core file reader takes five independently selected inputs:

```
rld-hybrid-import-append-core-candidate POLICY CURRENT_ROOT QUERY PROOF ENVELOPE
```

Root and query files contain exact raw 64- and 32-byte values. Input files must be
bounded, owned private regular files; symlinks refuse. The separate Python/OpenSSL
reader is `tools/pq_permanent_import_reference_candidate.py`; its `--help` lists
those inputs and the required independently selected backend hash, fresh private
scratch path and finite verification budget. It reconstructs the commitment and
verifies both signatures without calling Core. Exit codes are 0 for a verified
candidate, 1 for refusal and 2 for unavailable input/backend.

The public fixture generator creates fresh RAM-only no-value keys and stores only
public policy and signature bytes. It cannot sign an adopted currency or recover
old custody. Neither independent implementation is an independent operator or
external security review. Root installation, permanent deduplication during value
import, rollback protection, archival funding, full long-history recovery and
profile adoption remain separate requirements.
