"""Explicit stopped-only pinned authentication; never adopt a Native head."""
import hashlib
import os
from pathlib import Path
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT = 'RLD-BFT-COLD-NETWORK-PLAN-V1'
OBSERVED_FORMAT = 'RLD-BFT-COLD-NETWORK-OBSERVED-PLAN-V1'
MAX_BATCH = 4
MAX_INPUT = 8 * 1024 * 1024
MAX_MESSAGES = 512
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def checked_history(native, expected_head):
    mesh.hex32(expected_head)
    mesh.require(expected_head != '0' * 64, 'explicit nonzero latest history head required')
    current = native.call('history-check', '--expected-head', expected_head)
    return check_history_response(native,current,expected_head)


def check_history_response(native,current,expected_head):
    mesh.require(type(current) is dict and current.get('history_head') == expected_head
                 and current.get('currency') == native.currency
                 and current.get('logical_native_replay_complete') is True
                 and current.get('fixture_only') is True and current.get('live_rld') is False
                 and current.get('independent_latest_state_anchor_qualified') is False,
                 'pinned Native history response differs')
    mesh.hex32(current.get('region'))
    mesh.hex32(current.get('tip'))
    mesh.integer(current.get('height'), 0, 2**63 - 1)
    return current


def check_retained_pinned(runtime, expected_head, *, observed=False):
    """Keep only ordered IDs/values; Native authenticates every complete wire.

    Native message IDs identify expanded typed envelopes, not Python body IDs.
    Exact ordered batch digests bind the returned rows to their complete inputs.
    No Runtime construction, head adoption, cache authority or partial success.
    """
    mesh.hex32(expected_head)
    mesh.require(type(observed) is bool,'pinned cold observation mode differs')
    mesh.require(expected_head != '0' * 64, 'explicit nonzero latest history head required')
    messages = runtime.state['messages']
    mesh.require(len(messages) <= MAX_MESSAGES, 'pinned cold retained count exceeds bound')
    if not messages:
        current = checked_history(runtime.native, expected_head)
        mesh.require(current['region'] == runtime.region, 'pinned cold empty region differs')
        return {'messages_authenticated': 0, 'batches': 0, 'history_head': expected_head,
                **({'current':current} if observed else {})}

    with tempfile.TemporaryDirectory(dir=runtime.root, prefix='.native-pinned-cold-') as scratch:
        root = Path(scratch).resolve()
        manifests, expected_batches = [], []
        processed = 0
        with tempfile.NamedTemporaryFile(dir=root, prefix='frame-', suffix='.json') as handle:
            handle.write(b'[')
            expected, size = [], 2

            def finish():
                nonlocal processed, size, expected
                handle.write(b']'); handle.flush(); os.fsync(handle.fileno())
                handle.seek(0)
                digest = hashlib.sha256()
                while chunk := handle.read(65536):
                    digest.update(chunk)
                ident = digest.hexdigest()
                target = root / (ident + '.json')
                handle.seek(0)
                if target.exists():
                    # An exact repeated input still remains a repeated plan row.
                    with target.open('rb') as retained:
                        while chunk := handle.read(65536):
                            mesh.require(retained.read(len(chunk)) == chunk, 'cold batch byte collision')
                        mesh.require(not retained.read(1), 'cold batch length collision')
                else:
                    with target.open('xb') as retained:
                        os.chmod(target, 0o600)
                        while chunk := handle.read(65536):
                            retained.write(chunk)
                        retained.flush(); os.fsync(retained.fileno())
                processed += size
                mesh.require(processed <= MAX_ARCHIVE_BYTES, 'pinned cold processed archive capacity')
                manifests.append({'sha256': ident, 'bytes': size, 'envelopes': len(expected)})
                expected_batches.append(tuple(expected))
                handle.seek(0); handle.truncate(); handle.write(b'[')
                expected, size = [], 2

            for ident in messages:
                record = messages.record(ident)
                mesh.require(type(record['local']) is bool and ident == mesh.digest(record['body']),
                             'pinned cold body/local binding differs')
                value = record['value']
                if value is not None:
                    mesh.hex32(value)
                raw = messages.payload(ident)
                mesh.require(0 < len(raw) <= wire.MAX_PAYLOAD, 'pinned cold envelope capacity')
                if expected and (len(expected) == MAX_BATCH or size + 1 + len(raw) > MAX_INPUT):
                    finish()
                mesh.require(size + bool(expected) + len(raw) <= MAX_INPUT, 'pinned cold batch capacity')
                if expected:
                    handle.write(b','); size += 1
                handle.write(raw); size += len(raw); expected.append((ident, value))
                del raw, record
            if expected:
                finish()
        plan = root / 'plan.json'
        mesh.atomic(plan, {'format': FORMAT, 'currency': runtime.native.currency,
                          'region': runtime.region, 'batches': manifests})
        # Includes plan bytes and all unique complete batch objects.
        mesh.require(sum(p.stat().st_size for p in root.iterdir()) <= MAX_ARCHIVE_BYTES,
                     'pinned cold retained input archive capacity')
        descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        started, succeeded = time.monotonic(), False
        try:
            result = runtime.native.call('bft-network-check-plan-observed' if observed else
                                         'bft-network-check-plan', '--file', plan,
                                         '--expected-head', expected_head)
            current=None
            if observed:
                mesh.require(type(result) is dict and set(result)=={
                    'format','checked','current','ledger_changed','signing_authority'}
                    and result['format']==OBSERVED_FORMAT and result['ledger_changed'] is False
                    and result['signing_authority'] is False,'observed cold plan response differs')
                current=check_history_response(runtime.native,result['current'],expected_head)
                mesh.require(current['region']==runtime.region,'observed cold plan region differs')
                result=result['checked']
            mesh.require(type(result) is dict and set(result) == {
                'format', 'currency', 'region', 'history_head', 'request_sha256', 'batches',
                'verified', 'ledger_changed', 'signing_authority'}
                and result['format'] == FORMAT and result['currency'] == runtime.native.currency
                and result['region'] == runtime.region and result['history_head'] == expected_head
                and result['request_sha256'] == hashlib.sha256(plan.read_bytes()).hexdigest()
                and result['verified'] is True and result['ledger_changed'] is False
                and result['signing_authority'] is False and type(result['batches']) is list
                and len(result['batches']) == len(manifests), 'pinned cold Native plan response differs')
            for actual, manifest, expected in zip(result['batches'], manifests, expected_batches):
                mesh.require(type(actual) is dict and set(actual) == {'request_sha256', 'results'}
                             and actual['request_sha256'] == manifest['sha256']
                             and type(actual['results']) is list and len(actual['results']) == len(expected),
                             'pinned cold Native batch response differs')
                for row, (_, value) in zip(actual['results'], expected):
                    mesh.require(type(row) is dict and set(row) == {'message_id', 'value'}
                                 and row['value'] == value, 'pinned cold Native retained value differs')
                    mesh.hex32(row['message_id'])
            succeeded = True
        finally:
            observation = getattr(runtime, 'observation', None)
            if observation is not None:
                observation.operation('bft-network-check-plan', started, succeeded)
        return {'messages_authenticated': len(messages), 'batches': len(manifests),
                'history_head': expected_head, 'processed_envelope_batch_bytes': processed,
                **({'current':current} if observed else {})}
