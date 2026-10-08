"""Bounded complete-object byte carriage; full Native replay grants semantics.

Whole manifest/object hashes bind bytes only, never latest state or ledger trust.
Incomplete/mixed inputs cannot create a receiver archive. No custody is scanned.
"""
import base64
import hashlib

import interstellar_transfer as wire
import regional_export_archive_carriage as archive

FORMAT = 'RLD-NATIVE-PUBLIC-OBJECT-PART-CANDIDATE-V1'
DATA_BYTES = 1024 * 1024
MAX_PARTS = archive.MAX_DECODED_OBJECT // DATA_BYTES


def split_object(raw, part_count=None):
    archive.require(type(raw) is bytes and 0 < len(raw) <= archive.MAX_DECODED_OBJECT,
                    'candidate original Native object bound')
    digest = hashlib.sha256(raw).hexdigest()
    count = (len(raw) + DATA_BYTES - 1) // DATA_BYTES if part_count is None else part_count
    archive.require(type(count) is int and 1 <= count <= MAX_PARTS,
                    'candidate bounded explicit segmentation')
    chunk = (len(raw) + count - 1) // count
    archive.require(chunk <= DATA_BYTES and (count-1)*chunk < len(raw),
                    'candidate nonempty bounded segmentation')
    parts = tuple(wire.canonical(dict(format=FORMAT, object_hash=digest,
        object_bytes=len(raw), part=index, parts=count,
        data_b64=base64.b64encode(raw[index*chunk:(index+1)*chunk]).decode('ascii')))
        for index in range(count))
    archive.require(all(len(part) <= wire.MAX_PAYLOAD for part in parts),
                    'candidate original per-payload capacity')
    return parts


def assemble_object(parts, expected_hash, expected_bytes):
    wire.hex32(expected_hash, 'candidate whole byte object hash')
    archive.require(type(expected_bytes) is int and 0 < expected_bytes <= archive.MAX_DECODED_OBJECT
                    and type(parts) in (tuple, list) and 0 < len(parts) <= MAX_PARTS,
                    'candidate complete object/part inventory bound')
    count = None
    chunk = None
    decoded = {}
    for raw in parts:
        archive.require(type(raw) is bytes and 0 < len(raw) <= wire.MAX_PAYLOAD,
                        'candidate original per-payload capacity')
        value = wire.decode_json(raw)
        archive.require(type(value) is dict and set(value) == {
            'format', 'object_hash', 'object_bytes', 'part', 'parts', 'data_b64'}
            and wire.canonical(value) == raw and value['format'] == FORMAT,
            'candidate canonical object part')
        archive.require(type(value['parts']) is int and 1 <= value['parts'] <= MAX_PARTS,
                        'candidate bounded segmentation count')
        if count is None:
            count = value['parts']
            chunk = (expected_bytes + count - 1) // count
            archive.require(chunk <= DATA_BYTES and (count-1)*chunk < expected_bytes,
                            'candidate nonempty bounded segmentation')
        archive.require(value['object_hash'] == expected_hash
                        and type(value['object_bytes']) is int and value['object_bytes'] == expected_bytes
                        and type(value['parts']) is int and value['parts'] == count
                        and type(value['part']) is int and 0 <= value['part'] < count,
                        'candidate part differs from whole object binding')
        index = value['part']
        archive.require(index not in decoded, 'candidate duplicate part')
        data = archive.blob(value['data_b64'])
        archive.require(len(data) == min(chunk, expected_bytes-index*chunk),
                        'candidate exact part data length')
        decoded[index] = data
    archive.require(set(decoded) == set(range(count)), 'candidate incomplete object parts')
    result = b''.join(decoded[index] for index in range(count))
    archive.require(len(result) == expected_bytes and hashlib.sha256(result).hexdigest() == expected_hash,
                    'candidate complete object bytes differ')
    return result


def manifest_inventory(manifest, expected_byte_manifest):
    wire.hex32(expected_byte_manifest, 'candidate whole byte manifest hash')
    archive.require(type(manifest) is bytes and 0 < len(manifest) <= wire.MAX_PAYLOAD
                    and hashlib.sha256(manifest).hexdigest() == expected_byte_manifest,
                    'candidate complete byte manifest differs')
    value = wire.decode_json(manifest)
    archive.require(type(value) is dict, 'candidate manifest object')
    lossless = value.get('format') == archive.LOSSLESS_ARCHIVE
    fields = {'format', 'scope', 'packs', 'count', 'head'}
    if lossless:
        fields.add('original_packs')
    archive.require(set(value) == fields and value['format'] in (archive.ARCHIVE, archive.LOSSLESS_ARCHIVE)
                    and type(value['count']) is int and 0 < value['count'] < 2**63
                    and type(value['packs']) is list and 0 < len(value['packs'])
                    and len(value['packs']) + 3 <= wire.MAX_QUEUE_FILES,
                    'candidate complete manifest format/peak file capacity')
    wire.hex32(value['head'], 'candidate supplied byte head')
    if lossless:
        archive.require(type(value['original_packs']) is list
                        and len(value['original_packs']) == len(value['packs']),
                        'candidate complete original reference inventory')
        for ref in value['original_packs']:
            reference(ref)
    references = {}
    total = len(manifest) + len(archive.RETENTION_MARKER_BYTES)
    for ref in value['packs']:
        reference(ref)
        leaf = ref['hash'] + '.pack'
        archive.require(leaf not in references, 'candidate duplicate object reference')
        references[leaf] = ref['bytes']
        total += ref['bytes']
        archive.require(total <= wire.MAX_QUEUE_BYTES, 'candidate complete retention peak byte capacity')
    return references, value['head']


def reference(ref):
    archive.require(type(ref) is dict and set(ref) == {'hash', 'bytes'}
                    and type(ref['bytes']) is int and 0 < ref['bytes'] <= archive.MAX_DECODED_OBJECT,
                    'candidate original Native object reference bound')
    wire.hex32(ref['hash'], 'candidate object reference hash')


def retain_archive(manifest, part_inventory, expected_byte_manifest, target):
    """All complete byte objects before a fresh target; still no Native authority."""
    references, head = manifest_inventory(manifest, expected_byte_manifest)
    archive.require(type(part_inventory) is dict and set(part_inventory) == set(references),
                    'candidate missing/extra/path-bearing object inventory')
    objects = {name: assemble_object(part_inventory[name], name[:-5], size)
               for name, size in references.items()}
    return archive._retain_complete_bytes(manifest, objects, head, target)
