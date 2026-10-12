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
source_sha=$(shasum -a 256 "$source" | cut -d' ' -f1)
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

Run each fixed public case directly against independently pinned binaries.
Retain original negative and unavailable results locally. Public test entropy
must never be used for production keys. A subset comparison does not qualify
complete FIPS203/204, FIPS140/CAVP, constant time, production RNG or adoption.

## Explicit durable archive-spool receipt

The TLS candidate adds a distinct archive-spool receipt marker. Client adds
`archive-spool` after its public input path. Server adds absolute Rust `rld-maintenance` executable,
existing owned spool directory and independently
retained128hex manifest SHA512 after the fresh raw destination path. Compile
`RLD_TLS_CANDIDATE_SOURCE` with exact C source SHA256 and
`RLD_SPOOL_EXECUTABLE_SHA256` with the separately retained executable
SHA256. An omitted/mismatched executable pin refuses this mode.

After complete raw-file and directory fsync, one owned child executes that exact
executable with `pq-spool --root ROOT --expected-root SHA512 accept PACKET`,
accepting/fsyncing the packet under its manifest/capacity/OS-lock rules.
Only successful child termination inside the original3-second deadline releases
`RLD-PQ-PUBLIC-ARCHIVE-SPOOL-RECEIPT-V1`. Failure retains raw bytes/staging and
releases no archive receipt. Ordinary transport receipt remains distinct.
Neither receipt proves inner signature validity, ledger acceptance or spendability.
Independent custody, physical delay, cross-host and power-loss qualification remain separate requirements.
