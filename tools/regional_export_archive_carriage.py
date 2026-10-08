"""Opaque public certificate archive carriage; Native inspection remains mandatory.

This codec binds bytes only. It never imports money, initializes a Store, copies
signing custody or establishes latest state. Receiver trust/query pins are external.
"""
import base64
import hashlib
import os
from pathlib import Path

import interstellar_transfer as wire

FORMAT = 'RLD-SOURCE-ARCHIVE-CARRIAGE-CANDIDATE-V1'
ARCHIVE = 'RLD-NATIVE-IMMUTABLE-PACKED-ARCHIVE-CANDIDATE-V1'
LOSSLESS_ARCHIVE = 'RLD-NATIVE-IMMUTABLE-LOSSLESS-PACKED-ARCHIVE-CANDIDATE-V1'
MAX_DECODED_OBJECT = 8 * 1024 * 1024  # Existing Native object bound, never inflated here.


def require(value, reason):
    if not value:
        raise ValueError(reason)


def blob(encoded):
    require(type(encoded) is str and len(encoded) <= 4 * wire.MAX_PAYLOAD // 3 + 4,
            'candidate archive encoding bound')
    raw = base64.b64decode(encoded, validate=True)
    require(base64.b64encode(raw).decode('ascii') == encoded,
            'candidate archive noncanonical encoding')
    return raw


def checked(payload):
    require(type(payload) is bytes and 0 < len(payload) <= wire.MAX_PAYLOAD,
            'candidate archive original payload bound')
    value = wire.decode_json(payload)
    require(type(value) is dict and set(value) == {'format', 'manifest_b64', 'objects'}
            and value['format'] == FORMAT and wire.canonical(value) == payload,
            'candidate archive shape/canonical format')
    manifest = blob(value['manifest_b64'])
    data = wire.decode_json(manifest)
    require(type(data) is dict, 'candidate manifest object')
    lossless = data.get('format') == LOSSLESS_ARCHIVE
    fields = {'format', 'scope', 'packs', 'count', 'head'}
    if lossless:
        fields.add('original_packs')
    require(set(data) == fields
            and data['format'] in (ARCHIVE, LOSSLESS_ARCHIVE) and type(data['packs']) is list
            and 0 < len(data['packs']) <= wire.MAX_QUEUE_FILES
            and type(data['count']) is int and 0 < data['count'] < 2**63,
            'candidate complete archive manifest')
    if lossless:
        require(type(data['original_packs']) is list
                and len(data['original_packs']) == len(data['packs']),
                'candidate lossless complete original reference inventory')
        for ref in data['original_packs']:
            require(type(ref) is dict and set(ref) == {'hash', 'bytes'}
                    and type(ref['bytes']) is int and 0 < ref['bytes'] <= MAX_DECODED_OBJECT,
                    'candidate lossless original object bound')
            wire.hex32(ref['hash'], 'candidate original object hash')
    wire.hex32(data['head'], 'candidate byte head')
    expected = {}
    for ref in data['packs']:
        require(type(ref) is dict and set(ref) == {'hash', 'bytes'}, 'candidate pack reference')
        wire.hex32(ref['hash'], 'candidate pack hash')
        require(ref['hash'] not in expected and type(ref['bytes']) is int
                and 0 < ref['bytes'] <= wire.MAX_PAYLOAD, 'candidate pack duplicate/byte bound')
        expected[ref['hash'] + '.pack'] = ref['bytes']
    require(type(value['objects']) is dict and set(value['objects']) == set(expected),
            'candidate packs missing or extra; no paths or custody allowed')
    objects = {}
    for name, size in expected.items():
        raw = blob(value['objects'][name])
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() + '.pack' == name,
                'candidate pack bytes differ')
        objects[name] = raw
    require(sum(map(len, objects.values())) + len(manifest) <= wire.MAX_QUEUE_BYTES,
            'candidate retained archive byte capacity')
    return manifest, objects, data['head']


def pack_candidate(directory):
    """Read exact public manifest/referenced packs only; never scan private storage."""
    directory = Path(directory)
    manifest = wire.read_file(directory / 'packed.json', wire.MAX_PAYLOAD)
    data = wire.decode_json(manifest)
    require(type(data) is dict and type(data.get('packs')) is list
            and 0 < len(data['packs']) <= wire.MAX_QUEUE_FILES, 'candidate pack inventory')
    objects = {}
    for ref in data['packs']:
        require(type(ref) is dict and type(ref.get('hash')) is str, 'candidate pack reference')
        wire.hex32(ref['hash'], 'candidate pack hash')
        name = ref['hash'] + '.pack'
        require(name not in objects, 'candidate duplicate pack')
        raw = wire.read_file(directory / 'packs' / name, wire.MAX_PAYLOAD)
        objects[name] = base64.b64encode(raw).decode('ascii')
    payload = wire.canonical(dict(format=FORMAT,
        manifest_b64=base64.b64encode(manifest).decode('ascii'), objects=objects))
    checked(payload)
    return payload


def retain_candidate(payload, target):
    """Fresh byte-only target; failed writes retain residue and cannot be resumed.

    Successful return is NOT Native acceptance. The receiver must then use the
    complete Native archive inspector with its independently supplied trust/query.
    """
    manifest, objects, head = checked(payload)  # all byte checks before any writes
    target = Path(target)
    require(not os.path.lexists(target), 'candidate target must be absent; no overwrite/resume')
    target.mkdir(mode=0o700)
    marker = target / 'CANDIDATE_RETAINING'
    wire.write_new(marker, b'BYTE_RETENTION_ONLY_NO_NATIVE_AUTHORITY\n')
    (target / 'packs').mkdir(mode=0o700)
    wire.write_new(target / 'LOCK', b'')
    for name, raw in objects.items():
        wire.write_new(target / 'packs' / name, raw)
    wire.write_new(target / 'packed.json', manifest)
    # Every original byte is already durable. The candidate Native open refuses
    # this sentinel until complete publication; interruption keeps all residue.
    marker.unlink()
    for path in (target, target.parent):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return head
