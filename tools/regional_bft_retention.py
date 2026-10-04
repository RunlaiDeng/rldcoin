"""Exact bounded BFT envelope storage, without consensus or value authority.

Shared snapshots are addressed by their complete canonical bytes, not by a
statement identity. Every consumer gets a fresh envelope. Rust still verifies
each incoming envelope and every envelope reconstructed on cold startup.
"""
from collections.abc import Mapping
import hashlib
from pathlib import Path
import tempfile
from types import MappingProxyType

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT = 'RLD-REGIONAL-BFT-RETENTION-V2'
MAX_MESSAGES = 512
MAX_REFS = 64


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Messages(Mapping):
    """Immutable canonical byte records; no mutable cached proof or ledger."""
    def __init__(self, records=None, snapshots=None):
        self._records = MappingProxyType(dict(records or {}))
        self._snapshots = MappingProxyType(dict(snapshots or {}))

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def __contains__(self, ident):
        return ident in self._records

    def __getitem__(self, ident):
        record = self.record(ident)
        return {'envelope': self.envelope(ident), 'value': record['value'], 'local': record['local']}

    def record(self, ident):
        return wire.decode_json(self._records[ident])

    def bodies(self):
        for ident in self:
            record = self.record(ident)
            yield ident, record['body'], record['value'], record['local']

    def envelope(self, ident):
        record = self.record(ident)
        base = dict(record['header'], body=record['body'], evidence={'snapshots': []})
        size = len(wire.canonical(base)) + sum(len(self._snapshots[ref]) for ref in record['refs'])
        size += max(0, len(record['refs']) - 1)
        mesh.require(size == record['size_bytes'] <= wire.MAX_PAYLOAD,
                     'BFT retained expansion capacity/size differs')
        return dict(record['header'], body=record['body'],
                    evidence={'snapshots': [wire.decode_json(self._snapshots[ref]) for ref in record['refs']]})

    def payload(self, ident):
        record = self.record(ident)
        raw = wire.canonical(self.envelope(ident))
        mesh.require(len(raw) == record['size_bytes'] <= wire.MAX_PAYLOAD
                     and digest(raw) == record['sha256'], 'BFT retained envelope bytes differ')
        return raw

    def content(self, ident):
        return self.record(ident)['sha256']

    def with_local(self, ident):
        record = self.record(ident)
        record['local'] = True
        records = dict(self._records)
        records[ident] = wire.canonical(record)
        return Messages(records, self._snapshots)

    def append(self, ident, envelope, value, local):
        mesh.require(ident not in self and len(self) < MAX_MESSAGES and type(local) is bool,
                     'BFT retained message duplicate/capacity')
        mesh.require(set(envelope) == {'format', 'currency', 'region', 'evidence', 'body'}
                     and set(envelope['evidence']) == {'snapshots'}
                     and isinstance(envelope['evidence']['snapshots'], list)
                     and len(envelope['evidence']['snapshots']) <= MAX_REFS
                     and ident == mesh.digest(envelope['body']), 'BFT retained envelope fields/identity differ')
        raw = wire.canonical(envelope)
        mesh.require(0 < len(raw) <= wire.MAX_PAYLOAD, 'BFT retained envelope capacity')
        pool, refs = dict(self._snapshots), []
        for snapshot in envelope['evidence']['snapshots']:
            retained = wire.canonical(snapshot)
            ref = digest(retained)
            mesh.require(ref not in pool or pool[ref] == retained, 'BFT snapshot digest collision')
            pool[ref] = retained
            refs.append(ref)
        header = {k: envelope[k] for k in ('format', 'currency', 'region')}
        record = {'header': header, 'body': envelope['body'], 'refs': refs,
                  'sha256': digest(raw), 'size_bytes': len(raw), 'value': value, 'local': local}
        records = dict(self._records)
        records[ident] = wire.canonical(record)
        return Messages(records, pool)

    def packed(self):
        return ({ident: wire.decode_json(raw) for ident, raw in self._records.items()},
                {ident: wire.decode_json(raw) for ident, raw in self._snapshots.items()})

    @classmethod
    def unpack(cls, records, snapshots):
        mesh.require(isinstance(records, dict) and len(records) <= MAX_MESSAGES
                     and isinstance(snapshots, dict) and len(snapshots) <= MAX_MESSAGES * MAX_REFS,
                     'BFT retained index capacity/type')
        pool = {}
        for ref, snapshot in snapshots.items():
            mesh.hex32(ref)
            raw = wire.canonical(snapshot)
            mesh.require(0 < len(raw) <= wire.MAX_PAYLOAD and digest(raw) == ref,
                         'BFT retained snapshot bytes differ')
            pool[ref] = raw
        packed, referenced = {}, set()
        for ident, record in records.items():
            mesh.hex32(ident)
            mesh.require(isinstance(record, dict)
                         and set(record) == {'header', 'body', 'refs', 'sha256', 'size_bytes', 'value', 'local'}
                         and isinstance(record['header'], dict)
                         and set(record['header']) == {'format', 'currency', 'region'}
                         and type(record['local']) is bool and type(record['size_bytes']) is int
                         and 0 < record['size_bytes'] <= wire.MAX_PAYLOAD
                         and isinstance(record['refs'], list) and len(record['refs']) <= MAX_REFS
                         and ident == mesh.digest(record['body']), 'BFT retained message record differs')
            mesh.hex32(record['sha256'])
            if record['value'] is not None:
                mesh.hex32(record['value'])
            for ref in record['refs']:
                mesh.hex32(ref)
                mesh.require(ref in pool, 'BFT retained snapshot missing')
                referenced.add(ref)
            packed[ident] = wire.canonical(record)
        mesh.require(referenced == set(pool), 'BFT retained orphan snapshot refused; preserve state')
        result = cls(packed, pool)
        for ident in result:
            result.payload(ident)
        return result


def pack_state(state):
    mesh.require(isinstance(state['messages'], Messages), 'BFT exact message store required')
    records, snapshots = state['messages'].packed()
    return {'format': FORMAT, 'runtime': dict(state, messages=records), 'snapshots': snapshots}


def unpack_state(value):
    mesh.require(isinstance(value, dict) and set(value) == {'format', 'runtime', 'snapshots'}
                 and value['format'] == FORMAT and isinstance(value['runtime'], dict),
                 'BFT retention version differs; preserve old fixture and use fresh state')
    state = dict(value['runtime'])
    state['messages'] = Messages.unpack(state['messages'], value['snapshots'])
    return state


def retained_body_present(path, expected):
    """Bounded read-only observation; never proof carriage or ledger inclusion."""
    state = unpack_state(mesh.load(Path(path), 32 * 1024 * 1024))
    return any(body == expected for _, body, _, _ in state['messages'].bodies())


def verify_stopped_state(native, config, current, root):
    """Read-only full native authentication, without Runtime startup/recovery."""
    from regional_bft_node import private, MAX_STATE
    directory = Path(config['state'])
    mesh.require(directory.resolve().is_relative_to(root.resolve()), 'BFT retention path escapes fixture')
    path = private(directory / 'state.json')
    state = unpack_state(mesh.load(path, MAX_STATE))
    mesh.require(set(state) == {'format', 'binding', 'messages', 'height', 'tip', 'snapshot_cache', 'cursor'}
                 and state['format'] == config['format']
                 and (config['format'] == 'RLD-REGIONAL-BFT-NODE-V1'
                      or (config['format'] == 'RLD-REGIONAL-BFT-NODE-JOINT-V1'
                          and native.call('bft-context')['rules'] == 'RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1'))
                 and state['binding'] == {'currency': native.currency, 'region': current['region'], 'key': config['key']},
                 'BFT retained runtime domain differs')
    mesh.integer(state['height'], 0, 64)
    mesh.integer(state['cursor'], 0, 2**63-1)
    mesh.hex32(state['tip'])
    mesh.require(current['height'] >= state['height']
                 and (current['height'] != state['height'] or current['tip'] == state['tip'])
                 and isinstance(state['snapshot_cache'], list) and len(state['snapshot_cache']) <= 64,
                 'BFT retained observation exceeds native state')
    for ident in state['snapshot_cache']:
        mesh.hex32(ident)
    total = 0
    with tempfile.TemporaryDirectory(prefix='rld-bft-cold-input-') as scratch:
        input_path = Path(scratch) / 'envelope.json'
        for ident in state['messages']:
            raw = state['messages'].payload(ident)
            total += len(raw)
            input_path.write_bytes(raw)
            checked = native.call('bft-network-check', '--file', input_path)
            mesh.require(checked['value'] == state['messages'].record(ident)['value'],
                         'BFT retained native value differs')
    return {'retention_format': FORMAT, 'messages_authenticated': len(state['messages']),
            'distinct_complete_snapshots': len(state['messages']._snapshots),
            'retained_state_bytes': path.stat().st_size, 'state_limit_bytes': MAX_STATE,
            'expanded_envelope_bytes_authenticated': total, 'full_native_authentication': True}
