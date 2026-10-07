"""Separate Python/OpenSSL four-signature renewal archive reference candidate.

No Core imports, signing, ledger installation or head discovery. Caller supplies
an independently trusted initial anchor, per-entry observations and latest head.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import pq_authorization_candidate as auth
from pq_archive_manifest_reference_candidate import decode_json, owned_file

POLICY_FIELDS = frozenset({'profile', 'currency_root', 'region_root', 'purpose',
                          'valid_from_epoch', 'valid_until_epoch',
                          'ed_public_key', 'pq_public_key'})
ANCHOR_FIELDS = POLICY_FIELDS | frozenset({'crypto_era', 'key_epoch', 'next_nonce',
                                         'last_transition', 'caller_locks_root',
                                         'consumed_exports_root', 'current_epoch',
                                         'policy_trust'})
RENEWAL_FIELDS = frozenset({'activation_epoch', 'new_crypto_era', 'new_key_epoch',
                            'next_policy', 'previous_transition', 'profile', 'proof'})
OBSERVATION_FIELDS = frozenset({'current_epoch', 'next_nonce', 'policy_trust'})
WIRE_PROFILE = 'RLDCOIN-HYBRID-JOINT-RENEWAL-WIRE-CANDIDATE-V1'
CALLER_PROFILE = 'RLDCOIN-HYBRID-RENEWAL-ARCHIVE-CALLER-CANDIDATE-V1'
MAX_ENTRY_BYTES = 32768
MAX_ENTRIES = 64
MAX_TOTAL_BYTES = 2097152


class Unavailable(RuntimeError):
    pass


def exact(value, fields):
    auth.require(type(value) is dict and set(value) == fields, 'exact public fields required')


def policy(value):
    exact(value, POLICY_FIELDS)
    auth.require(value['profile'] == auth.PROFILE and value['purpose'] == 'RENEWAL',
                 'renewal policy profile/purpose differs')
    for field, width in (('currency_root', 64), ('region_root', 64),
                         ('ed_public_key', 64), ('pq_public_key', 5184)):
        auth.digest(value[field], width)
    result = auth.Policy(value['profile'], value['currency_root'], value['region_root'],
                         value['purpose'], value['valid_from_epoch'], value['valid_until_epoch'],
                         auth.ED_SPKI + bytes.fromhex(value['ed_public_key']),
                         auth.PQ_SPKI + bytes.fromhex(value['pq_public_key']))
    result.validate()
    return result


def policy_bytes(value):
    policy(value)
    profile = value['profile'].encode('ascii')
    return (b'RLD-PQ-RENEWAL-POLICY-CANDIDATE-V1\0'
            + len(profile).to_bytes(8, 'big') + profile
            + bytes.fromhex(value['currency_root']) + bytes.fromhex(value['region_root'])
            + b'\x05' + value['valid_from_epoch'].to_bytes(8, 'big')
            + value['valid_until_epoch'].to_bytes(8, 'big')
            + bytes.fromhex(value['ed_public_key']) + bytes.fromhex(value['pq_public_key']))


def proof(value):
    exact(value, frozenset({'ed_signature', 'pq_signature'}))
    auth.digest(value['ed_signature'], 128)
    auth.digest(value['pq_signature'], 9254)
    return auth.Proof(bytes.fromhex(value['ed_signature']), bytes.fromhex(value['pq_signature']))


def decode_renewal(raw):
    value = decode_json(raw, MAX_ENTRY_BYTES)
    exact(value, RENEWAL_FIELDS)
    auth.require(value['profile'] == WIRE_PROFILE, 'renewal wire profile differs')
    for field in ('activation_epoch', 'new_crypto_era', 'new_key_epoch'):
        auth.uint(value[field])
    auth.digest(value['previous_transition'], 128)
    policy(value['next_policy'])
    exact(value['proof'], frozenset({'old', 'new'}))
    proof(value['proof']['old'])
    proof(value['proof']['new'])
    auth.require(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') == raw,
                 'noncanonical complete renewal')
    return value


def verify_step(anchor, renewal, observation, scratch, openssl, deadline):
    exact(anchor, ANCHOR_FIELDS)
    exact(observation, OBSERVATION_FIELDS)
    old = {key: anchor[key] for key in POLICY_FIELDS}
    new = renewal['next_policy']
    old_policy, new_policy = policy(old), policy(new)
    for field in ('crypto_era', 'key_epoch', 'next_nonce'):
        auth.uint(anchor[field])
        auth.require(anchor[field] < auth.U64_MAX, 'renewal successor integer overflow')
    auth.uint(observation['current_epoch'])
    auth.uint(observation['next_nonce'])
    for field in ('last_transition', 'caller_locks_root', 'consumed_exports_root'):
        auth.digest(anchor[field], 128)
    auth.require(observation['policy_trust'] == 'CURRENT_AND_TRUSTED',
                 'old authority unavailable/revoked/broken')
    auth.require(renewal['previous_transition'] == anchor['last_transition']
                 and renewal['new_crypto_era'] == anchor['crypto_era'] + 1
                 and renewal['new_key_epoch'] == anchor['key_epoch'] + 1
                 and observation['next_nonce'] == anchor['next_nonce']
                 and renewal['activation_epoch'] <= observation['current_epoch']
                 and new['ed_public_key'] != old['ed_public_key']
                 and new['pq_public_key'] != old['pq_public_key'],
                 'renewal predecessor/era/nonce/rotation differs')
    encoded = (b'RLD-PQ-JOINT-RENEWAL-CANDIDATE-V1\0'
               + policy_bytes(old) + policy_bytes(new))
    for number in (anchor['crypto_era'], anchor['key_epoch'], anchor['next_nonce'],
                   renewal['new_crypto_era'], renewal['new_key_epoch'], renewal['activation_epoch']):
        encoded += number.to_bytes(8, 'big')
    encoded += b''.join(bytes.fromhex(value) for value in (
        anchor['last_transition'], renewal['previous_transition'],
        anchor['caller_locks_root'], anchor['consumed_exports_root']))
    intent = {'candidate_only': True, 'currency_root': old['currency_root'],
              'region_root': old['region_root'], 'purpose': 'RENEWAL',
              'epoch': renewal['activation_epoch'], 'nonce': anchor['next_nonce'],
              'payload_root': hashlib.sha512(encoded).hexdigest()}
    old_proof, new_proof = proof(renewal['proof']['old']), proof(renewal['proof']['new'])
    for role, selected_policy, selected_proof in (
            ('old', old_policy, old_proof), ('new', new_policy, new_proof)):
        result = auth.verify_candidate(selected_policy, intent, selected_proof,
                                       observation['current_epoch'], scratch / role,
                                       openssl, deadline)
        if result == auth.Result.UNAVAILABLE:
            raise Unavailable('actual signature backend unavailable')
        auth.require(result == auth.Result.VERIFIED, 'actual ' + role + ' dual signatures refused')
    head = hashlib.sha512(b'RLD-PQ-JOINT-RENEWAL-HEAD-CANDIDATE-V1\0'
                          + auth.signing_bytes(intent) + old_proof.ed_signature
                          + old_proof.pq_signature + new_proof.ed_signature
                          + new_proof.pq_signature).hexdigest()
    return dict(anchor, **new, crypto_era=renewal['new_crypto_era'],
                key_epoch=renewal['new_key_epoch'], next_nonce=anchor['next_nonce'] + 1,
                last_transition=head)


def verify_archive(initial, entries, observations, expected_latest, scratch, openssl, deadline):
    """Immutable verification result; all bounds checked before any signature."""
    exact(initial, ANCHOR_FIELDS)
    auth.digest(expected_latest, 128)
    auth.require(type(entries) in (tuple, list) and type(observations) in (tuple, list)
                 and 1 <= len(entries) <= MAX_ENTRIES and len(entries) == len(observations),
                 'complete ordered archive count differs')
    auth.require(all(type(raw) is bytes and 1 <= len(raw) <= MAX_ENTRY_BYTES for raw in entries)
                 and sum(map(len, entries)) <= MAX_TOTAL_BYTES, 'archive byte bounds exceeded')
    current = dict(initial)
    for index, (raw, observation) in enumerate(zip(entries, observations)):
        auth.require(time.monotonic() < deadline, 'original finite verification deadline exhausted')
        step = scratch / ('entry-' + str(index))
        step.mkdir(mode=0o700)
        current = verify_step(current, decode_renewal(raw), observation, step, openssl, deadline)
    auth.require(current['last_transition'] == expected_latest,
                 'valid prefix differs from independently retained latest head')
    return current


def entry_file(directory_fd, name):
    auth.require(type(name) is str and 1 <= len(name) <= 96
                 and name not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9_.-]+', name),
                 'bounded ASCII leaf required')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        auth.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and info.st_mode & 0o077 == 0 and info.st_size <= MAX_ENTRY_BYTES,
                     'bounded owned private archive entry required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_ENTRY_BYTES + 1)
        auth.require(len(raw) <= MAX_ENTRY_BYTES, 'entry grew beyond original bound')
        return raw
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('anchor', 'caller', 'directory', 'scratch', 'openssl', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--budget-seconds', type=int, default=60)
    args = parser.parse_args()
    try:
        auth.require(1 <= args.budget_seconds <= 120, 'finite budget1–120 required')
        deadline = time.monotonic() + args.budget_seconds
        backend = Path(args.openssl)
        auth.require(backend.is_absolute() and backend.is_file(), 'selected absolute backend required')
        auth.digest(args.openssl_sha256, 64)
        auth.require(hashlib.sha256(backend.read_bytes()).hexdigest() == args.openssl_sha256,
                     'independent actual backend hash differs')
        initial = decode_json(owned_file(args.anchor, 8192), 8192)
        caller = decode_json(owned_file(args.caller, 32768), 32768)
        exact(initial, ANCHOR_FIELDS)
        exact(caller, frozenset({'profile', 'entries', 'expected_latest_transition'}))
        auth.require(caller['profile'] == CALLER_PROFILE and type(caller['entries']) is list
                     and 1 <= len(caller['entries']) <= MAX_ENTRIES, 'caller profile/count differs')
        observations = []
        for item in caller['entries']:
            exact(item, OBSERVATION_FIELDS | frozenset({'file'}))
            observations.append({key: item[key] for key in OBSERVATION_FIELDS})
        auth.require(observations[0] == {key: initial[key] for key in OBSERVATION_FIELDS},
                     'initial independent observation differs')
        directory_fd = os.open(args.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory_fd)
            auth.require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                         'owned private archive directory required')
            entries = [entry_file(directory_fd, item['file']) for item in caller['entries']]
        finally:
            os.close(directory_fd)
        scratch = Path(args.scratch)
        parent = scratch.parent.lstat()
        auth.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                     and parent.st_mode & 0o077 == 0, 'owned private scratch parent required')
        scratch.mkdir(mode=0o700)
        result = verify_archive(initial, entries, observations,
                                caller['expected_latest_transition'], scratch, backend, deadline)
        output = {key: result[key] for key in (
            'crypto_era', 'key_epoch', 'next_nonce', 'last_transition',
            'caller_locks_root', 'consumed_exports_root')}
        output.update(candidate_only=True, installed=False, nonce_consumed=False)
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, Unavailable) as error:
        print(json.dumps({'candidate_only': True, 'installed': False, 'unavailable': str(error)}))
        return 2
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        print(json.dumps({'candidate_only': True, 'installed': False, 'refused': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
