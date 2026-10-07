"""Independent Python/OpenSSL manifest candidate; no Core, signing or adoption.

Caller-authenticated policy and freshness are separate files. A valid result
verifies only the finite manifest authority; entry signatures remain separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import pq_authorization_candidate as auth
import pq_public_archive_candidate as archive

POLICY_FIELDS = frozenset({
    'profile', 'currency_root', 'region_root', 'purpose', 'valid_from_epoch',
    'valid_until_epoch', 'ed_public_key', 'pq_public_key', 'current_epoch',
    'next_nonce', 'policy_trust',
})
WIRE_FIELDS = frozenset({'ed_signature', 'pq_signature', 'profile', 'intent'})
MAX_MANIFEST_BYTES = len(archive.DOMAIN) + 2 + 64 * 68


def decode_json(raw, maximum):
    auth.require(type(raw) is bytes and len(raw) <= maximum, 'public JSON exceeds bound')

    def pairs(items):
        result = {}
        for key, value in items:
            auth.require(key not in result, 'duplicate public field')
            result[key] = value
        return result

    def noninteger(_):
        raise auth.Rejected('noninteger public encoding')

    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_float=noninteger, parse_constant=noninteger)
    except (ValueError, RecursionError) as error:
        raise auth.Rejected('public JSON malformed') from error
    auth.require(type(value) is dict, 'public object required')
    return value


def verify_manifest(trusted_raw, manifest, envelope, scratch, openssl, deadline):
    """AND verification under independently retained scope/nonce/horizon only."""
    try:
        trusted = decode_json(trusted_raw, 8192)
        wire = decode_json(envelope, 12288)
        auth.require(set(trusted) == POLICY_FIELDS and set(wire) == WIRE_FIELDS,
                     'exact separate policy/wire fields required')
        auth.require(wire['profile'] == trusted['profile'] == auth.PROFILE,
                     'candidate profile differs')
        auth.require(trusted['policy_trust'] == 'CURRENT_AND_TRUSTED',
                     'caller authority unavailable/revoked/broken')
        auth.require(trusted['purpose'] == 'ARCHIVE_MANIFEST', 'manifest purpose required')
        auth.uint(trusted['current_epoch'])
        auth.uint(trusted['next_nonce'])
        auth.require(type(manifest) is bytes and len(manifest) <= MAX_MANIFEST_BYTES,
                     'manifest exceeds fixed bound')
        archive.decode_manifest(manifest)
        intent = wire['intent']
        auth.signing_bytes(intent)
        auth.require(intent['nonce'] == trusted['next_nonce']
                     and intent['payload_root'] == hashlib.sha512(manifest).hexdigest(),
                     'independent nonce or manifest root differs')
        auth.require(json.dumps(wire, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=True).encode('ascii') == envelope,
                     'noncanonical public envelope')
        auth.digest(trusted['ed_public_key'], 64)
        auth.digest(trusted['pq_public_key'], 5184)
        auth.digest(wire['ed_signature'], 128)
        auth.digest(wire['pq_signature'], 9254)
        policy = auth.Policy(trusted['profile'], trusted['currency_root'],
                             trusted['region_root'], trusted['purpose'],
                             trusted['valid_from_epoch'], trusted['valid_until_epoch'],
                             auth.ED_SPKI + bytes.fromhex(trusted['ed_public_key']),
                             auth.PQ_SPKI + bytes.fromhex(trusted['pq_public_key']))
        proof = auth.Proof(bytes.fromhex(wire['ed_signature']),
                           bytes.fromhex(wire['pq_signature']))
        return auth.verify_candidate(policy, intent, proof, trusted['current_epoch'],
                                     scratch, openssl, deadline)
    except (ValueError, TypeError, KeyError, OverflowError):
        return auth.Result.REJECTED


def owned_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        auth.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and info.st_mode & 0o077 == 0 and info.st_size <= maximum,
                     'bounded owned private regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        auth.require(len(raw) <= maximum, 'public input grew beyond bound')
        return raw
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('policy', 'manifest', 'envelope', 'scratch', 'openssl', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--budget-seconds', type=int, default=60)
    args = parser.parse_args()
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
                     'fresh verification scratch under owned private parent required')
        result = verify_manifest(owned_file(args.policy, 8192),
                                 owned_file(args.manifest, MAX_MANIFEST_BYTES),
                                 owned_file(args.envelope, 12288), scratch, backend,
                                 time.monotonic() + args.budget_seconds)
    except (OSError, ValueError):
        result = auth.Result.UNAVAILABLE
    print(json.dumps({'candidate_only': True, 'installed': False,
                      'nonce_consumed': False, 'result': result.value}))
    return {auth.Result.VERIFIED: 0, auth.Result.REJECTED: 1,
            auth.Result.UNAVAILABLE: 2}[result]


if __name__ == '__main__':
    raise SystemExit(main())
