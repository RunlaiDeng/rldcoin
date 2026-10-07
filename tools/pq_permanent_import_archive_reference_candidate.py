"""Independent complete permanent-ID append archive verification candidate.

Caller-authenticated initial/latest anchors and observations stay separate from
incoming bytes. No Core, signing, installed roots, nonce consumption or value.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import pq_authorization_candidate as auth
import pq_permanent_import_reference_candidate as append
from pq_archive_manifest_reference_candidate import decode_json, owned_file, POLICY_FIELDS

DOMAIN = b'RLD-PERMANENT-IMPORT-APPEND-ARCHIVE-CANDIDATE-V1\0'
HEAD_DOMAIN = b'RLD-PERMANENT-IMPORT-APPEND-ARCHIVE-HEAD-CANDIDATE-V1\0'
MAX_ENTRIES = 64
MAX_LOGICAL_BYTES = 2097152
MAX_WIRE = MAX_LOGICAL_BYTES + len(DOMAIN) + 2 + MAX_ENTRIES * 8
ANCHOR_FIELDS = frozenset({'current_root', 'key_count', 'next_nonce', 'archive_head', 'caller_locks_root'})
OBSERVATION_FIELDS = frozenset({'current_epoch', 'next_nonce', 'policy_trust'})


def anchor(value):
    auth.require(type(value) is dict and set(value) == ANCHOR_FIELDS, 'exact separate anchor required')
    for key in ('current_root', 'archive_head', 'caller_locks_root'):
        auth.digest(value[key], 128)
    auth.uint(value['next_nonce'])
    auth.require(type(value['key_count']) is int and 0 <= value['key_count'] <= 200001,
                 'anchor count outside bound')
    return dict(value)


def decode_archive(raw):
    auth.require(type(raw) is bytes and len(raw) <= MAX_WIRE and raw.startswith(DOMAIN),
                 'archive domain/wire bound differs')
    offset = len(DOMAIN)

    def take(n):
        nonlocal offset
        auth.require(n >= 0 and offset + n <= len(raw), 'archive truncated')
        value = raw[offset:offset + n]
        offset += n
        return value

    count = int.from_bytes(take(2), 'big')
    auth.require(1 <= count <= MAX_ENTRIES, 'archive count outside bound')
    entries, total = [], 0
    for _ in range(count):
        query = take(32)
        pn = int.from_bytes(take(4), 'big')
        auth.require(pn <= 32768, 'complete proof exceeds bound')
        proof = take(pn)
        en = int.from_bytes(take(4), 'big')
        auth.require(en <= 12288, 'complete envelope exceeds bound')
        envelope = take(en)
        total += 32 + pn + en
        auth.require(total <= MAX_LOGICAL_BYTES, 'logical aggregate exceeds bound')
        entries.append((query, proof, envelope))
    auth.require(offset == len(raw), 'archive trailing bytes')
    return entries


def verify_archive(policy_raw, caller_raw, archive_raw, scratch, backend, deadline):
    try:
        policy = decode_json(policy_raw, 8192)
        auth.require(set(policy) == POLICY_FIELDS and policy['purpose'] == append.PURPOSE,
                     'dedicated trusted append policy required')
        auth.uint(policy['current_epoch'])
        auth.uint(policy['valid_from_epoch'])
        auth.uint(policy['valid_until_epoch'])
        auth.require(policy['policy_trust'] == 'CURRENT_AND_TRUSTED'
                     and policy['valid_from_epoch'] <= policy['current_epoch'] <= policy['valid_until_epoch'],
                     'current caller policy unavailable or expired')
        caller = decode_json(caller_raw, 16384)
        auth.require(set(caller) == {'initial', 'latest', 'observations'}, 'exact separate caller fields required')
        cursor, latest = anchor(caller['initial']), anchor(caller['latest'])
        observations = caller['observations']
        entries = decode_archive(archive_raw)
        auth.require(type(observations) is list and len(observations) == len(entries), 'observation count differs')
        auth.require(policy['next_nonce'] == cursor['next_nonce']
                     and cursor['next_nonce'] + len(entries) <= auth.U64_MAX
                     and cursor['caller_locks_root'] == latest['caller_locks_root'],
                     'initial nonce, counter overflow or independent locks differ')
        previous_epoch = 0
        for observation in observations:
            auth.require(type(observation) is dict and set(observation) == OBSERVATION_FIELDS,
                         'exact independent observation required')
            auth.uint(observation['current_epoch'])
            auth.uint(observation['next_nonce'])
            auth.require(previous_epoch <= observation['current_epoch'] <= policy['current_epoch'],
                         'independent observation outside current chronology')
            previous_epoch = observation['current_epoch']
        scratch = Path(scratch)
        scratch.mkdir(mode=0o700)
        for i, ((query, proof, envelope), observation) in enumerate(zip(entries, observations)):
            auth.require(observation['next_nonce'] == cursor['next_nonce'], 'noncontiguous independent nonce')
            selected = dict(policy)
            selected.update(observation)
            result, transition = append.verify_append(
                json.dumps(selected, sort_keys=True, separators=(',', ':')).encode(),
                bytes.fromhex(cursor['current_root']), query, proof, envelope,
                scratch / f'entry-{i:03}', backend, deadline)
            if result != auth.Result.VERIFIED:
                return result, None
            auth.require(transition['previous_key_count'] == cursor['key_count'], 'independent initial count differs')
            signed = decode_json(envelope, 12288)['intent']
            head = hashlib.sha512(HEAD_DOMAIN + bytes.fromhex(policy['currency_root'] + policy['region_root'])
                                  + bytes.fromhex(cursor['archive_head'] + cursor['caller_locks_root'])
                                  + cursor['next_nonce'].to_bytes(8, 'big') + signed['epoch'].to_bytes(8, 'big')
                                  + bytes.fromhex(transition['payload_root']) + hashlib.sha512(envelope).digest()).hexdigest()
            cursor.update(current_root=transition['new_root'], key_count=transition['new_key_count'],
                          next_nonce=cursor['next_nonce'] + 1, archive_head=head)
        auth.require(cursor == latest, 'complete cursor differs from independently retained latest')
        return auth.Result.VERIFIED, cursor
    except (ValueError, KeyError, TypeError, OverflowError):
        return auth.Result.REJECTED, None
    except OSError:
        return auth.Result.UNAVAILABLE, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('policy', 'caller', 'archive', 'scratch', 'openssl', 'openssl-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--budget-seconds', type=int, default=60)
    args = parser.parse_args()
    latest = None
    try:
        auth.require(1 <= args.budget_seconds <= 60, 'finite budget1–60 required')
        backend = Path(args.openssl)
        auth.require(backend.is_absolute() and backend.is_file(), 'selected absolute backend required')
        auth.digest(args.openssl_sha256, 64)
        auth.require(hashlib.sha256(backend.read_bytes()).hexdigest() == args.openssl_sha256,
                     'independently selected backend hash differs')
        scratch = Path(args.scratch)
        parent = scratch.parent.lstat()
        auth.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                     and parent.st_mode & 0o077 == 0 and not scratch.exists(),
                     'fresh owned private scratch required')
        result, latest = verify_archive(owned_file(args.policy, 8192), owned_file(args.caller, 16384),
                                        owned_file(args.archive, MAX_WIRE), scratch, backend,
                                        time.monotonic() + args.budget_seconds)
    except (OSError, ValueError):
        result = auth.Result.UNAVAILABLE
    print(json.dumps({'candidate_only': True, 'installed': False, 'nonce_consumed': False,
                      'result': result.value, 'latest': latest}))
    return {auth.Result.VERIFIED: 0, auth.Result.REJECTED: 1, auth.Result.UNAVAILABLE: 2}[result]


if __name__ == '__main__':
    raise SystemExit(main())
