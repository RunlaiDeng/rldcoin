"""Independent Python/OpenSSL permanent-ID append verification candidate.

Separate caller-authenticated root, scope, nonce and finite policy are mandatory.
No Core call, signing, root installation, nonce consumption or ledger import.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import permanent_import_index_candidate as index
import pq_authorization_candidate as auth
from pq_archive_manifest_reference_candidate import (
    decode_json, owned_file, POLICY_FIELDS, WIRE_FIELDS,
)

DOMAIN = b'RLD-PERMANENT-IMPORT-APPEND-CANDIDATE-V1\0'
PURPOSE = 'PERMANENT_IMPORT_APPEND'


def prepare_append(scope, current_root, query, complete_proof):
    """Independent canonical append digest; not a trusted state transition."""
    proof = index.decode_proof(complete_proof)
    root, count, present = index.proof_root(scope, query, proof)
    index.require(root == current_root and not present, 'root mismatch or duplicate import ID')
    new_root = index.derive_insert_root(scope, current_root, query, proof)
    proof_digest = hashlib.sha512(complete_proof).digest()
    payload = hashlib.sha512(DOMAIN + scope + current_root + query + new_root
                             + count.to_bytes(4, 'big') + (count + 1).to_bytes(4, 'big')
                             + proof_digest).hexdigest()
    return {'previous_root': current_root.hex(), 'new_root': new_root.hex(),
            'previous_key_count': count, 'new_key_count': count + 1,
            'payload_root': payload}


def verify_append(trusted_raw, current_root, query, complete_proof, envelope,
                  scratch, openssl, deadline):
    try:
        trusted = decode_json(trusted_raw, 8192)
        wire = decode_json(envelope, 12288)
        auth.require(set(trusted) == POLICY_FIELDS and set(wire) == WIRE_FIELDS,
                     'exact separate policy/wire fields required')
        auth.require(wire['profile'] == trusted['profile'] == auth.PROFILE,
                     'candidate profile differs')
        auth.require(trusted['policy_trust'] == 'CURRENT_AND_TRUSTED', 'caller trust unavailable')
        auth.require(trusted['purpose'] == PURPOSE, 'dedicated append purpose required')
        auth.uint(trusted['current_epoch'])
        auth.uint(trusted['next_nonce'])
        auth.digest(trusted['currency_root'], 64)
        auth.digest(trusted['region_root'], 64)
        scope = bytes.fromhex(trusted['currency_root'] + trusted['region_root'])
        append = prepare_append(scope, index.fixed(current_root, 64),
                                index.fixed(query, 32), complete_proof)
        intent = wire['intent']
        auth.signing_bytes(intent)
        auth.require(intent['nonce'] == trusted['next_nonce']
                     and intent['payload_root'] == append['payload_root'],
                     'independent nonce or complete append root differs')
        auth.require(json.dumps(wire, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=True).encode('ascii') == envelope,
                     'noncanonical public envelope')
        for value, width in ((trusted['ed_public_key'], 64), (trusted['pq_public_key'], 5184),
                             (wire['ed_signature'], 128), (wire['pq_signature'], 9254)):
            auth.digest(value, width)
        policy = auth.Policy(trusted['profile'], trusted['currency_root'], trusted['region_root'],
                             trusted['purpose'], trusted['valid_from_epoch'], trusted['valid_until_epoch'],
                             auth.ED_SPKI + bytes.fromhex(trusted['ed_public_key']),
                             auth.PQ_SPKI + bytes.fromhex(trusted['pq_public_key']))
        proof = auth.Proof(bytes.fromhex(wire['ed_signature']), bytes.fromhex(wire['pq_signature']))
        result = auth.verify_candidate(policy, intent, proof, trusted['current_epoch'],
                                       scratch, openssl, deadline)
        return result, append if result == auth.Result.VERIFIED else None
    except (ValueError, TypeError, KeyError, OverflowError):
        return auth.Result.REJECTED, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('policy', 'current-root', 'query', 'proof', 'envelope', 'scratch', 'openssl', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--budget-seconds', type=int, default=60)
    args = parser.parse_args()
    append = None
    try:
        auth.require(1 <= args.budget_seconds <= 60, 'finite budget1–60 required')
        backend = Path(args.openssl)
        auth.require(backend.is_absolute() and backend.is_file(), 'selected absolute backend required')
        auth.digest(args.openssl_sha256, 64)
        auth.require(hashlib.sha256(backend.read_bytes()).hexdigest() == args.openssl_sha256,
                     'independent backend hash differs')
        scratch = Path(args.scratch)
        parent = scratch.parent.lstat()
        auth.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                     and parent.st_mode & 0o077 == 0 and not scratch.exists(),
                     'fresh scratch under owned private parent required')
        result, append = verify_append(owned_file(args.policy, 8192), owned_file(args.current_root, 64),
                                       owned_file(args.query, 32), owned_file(args.proof, index.MAX_PROOF_BYTES),
                                       owned_file(args.envelope, 12288), scratch, backend,
                                       time.monotonic() + args.budget_seconds)
    except (OSError, ValueError):
        result = auth.Result.UNAVAILABLE
    print(json.dumps({'candidate_only': True, 'installed': False, 'nonce_consumed': False,
                      'result': result.value, 'append': append}))
    return {auth.Result.VERIFIED: 0, auth.Result.REJECTED: 1, auth.Result.UNAVAILABLE: 2}[result]


if __name__ == '__main__':
    raise SystemExit(main())
