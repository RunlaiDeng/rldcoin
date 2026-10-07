# Bounded OpenSSL candidates

`transport.c` is a same-host mutual TLS 1.3 candidate. It requires exact peer
certificate pins, explicit provider/group/suite and complete bounded payloads.
Transport receipts prove bytes, never monetary acceptance or physical routes.

`mlkem768_kat.c`, `mlkem768_encap_kat.c` and `mlkem768_keygen_kat.c` compare known
NIST ML-KEM-768 test material; no private keys or generated seeds belong in Git.
OpenSSL 3.6.3 was the measured provider. Build each with its exact source digest,
using the corresponding source macro (inspect the `#ifndef` declaration):

```sh
# Set OPENSSL_PREFIX to the explicitly selected OpenSSL installation.
# Example for mlkem768_kat.c; do not use the TLS transport as a KAT entry.
source=tools/fixtures/pq-tls-candidate/mlkem768_kat.c
source_sha=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$source")
cc -std=c11 -O1 -Wall -Wextra -Werror -pedantic \
  -I"$OPENSSL_PREFIX/include" -L"$OPENSSL_PREFIX/lib" \
  -DRLD_MLKEM_CANDIDATE_SOURCE=\""$source_sha"\" \
  "$source" -lcrypto -o /tmp/rld-mlkem768-kat
```

Supply owned mode0600 regular inputs. Decap arguments are `dk2400 c1088 expected_k32`;
encap `ek1184 m32 expected_c1088 expected_k32` or `check ek1184`;
keygen `d32 z32 expected_ek1184 expected_dk2400` or `check dk2400`.
Exit0 means matched known bytes/check accepted, exit1 refusal/mismatch,
exit2 unavailable input or API. Implicit rejection can correctly match expected
bytes; successful decapsulation is not ciphertext/peer authentication.

The [minimal fixed-corpus driver](../../pq_mlkem_known_answer.py) runs one
named case with separately selected binary SHA-256 values, two different engines,
a mismatch negative and an absolute120-second deadline. It does not download,
install, sign, open sockets, inspect real custody or repeat entire fault scopes.
Its output is local and preserves failure bytes. Test entropy is publicly known
and MUST NOT be used for production key generation. Standard subset PASS is not
complete FIPS203/204, FIPS140/CAVP, constant-time, production RNG or adoption.

## Explicit durable archive-spool receipt

The TLS candidate adds a distinct archive-spool receipt marker. Client adds
`archive-spool` after its public input path. Server adds absolute Python executable,
absolute spool script path, existing owned spool directory and independently
retained128hex manifest SHA512 after the fresh raw destination path. Compile
`RLD_TLS_CANDIDATE_SOURCE` with exact C source SHA256 and
`RLD_SPOOL_SCRIPT_SHA256` with exact `tools/pq_public_archive_spool_candidate.py`
SHA256. An omitted/mismatched script pin refuses this mode.

After complete raw-file and directory fsync, one owned child executes that exact
script, accepting/fsyncing the packet under its manifest/capacity/OS-lock rules.
Only successful child termination inside the original3-second deadline releases
`RLD-PQ-PUBLIC-ARCHIVE-SPOOL-RECEIPT-V1`. Failure retains raw bytes/staging and
releases no archive receipt. Ordinary transport receipt remains distinct.
Neither receipt proves inner signature validity, ledger acceptance or spendability.
The measured193-packet64-entry same-host scope and two real refusal paths passed;
this is not independent custody, physical delays, cross-host/power-loss qualification
or a full requalification of all historical TLS observations on the changed source.
