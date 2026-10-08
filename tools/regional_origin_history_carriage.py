"""Opaque bounded origin-proof carriage; the fixed-head Native entry authenticates.

Caller-pinned route/currency and whole-byte identity are structural checks only.
No Python signature check, ledger initializer, import, freshness or custody right.
"""
from pathlib import Path

import interstellar_transfer as wire
import regional_archive_parts_candidate as parts
import regional_export_archive_carriage as archive

MAX_SOURCE_CHECKPOINTS = 4096


def _shape(raw, *, source, destination, export, currency):
    archive.require(type(raw) is bytes and 0 < len(raw) <= archive.MAX_DECODED_OBJECT,
                    'original complete Native object bound')
    for value in (source, destination, export, currency):
        wire.hex32(value, 'independently pinned Native scope')
    proof = wire.decode_json(raw)
    archive.require(type(proof) is dict and set(proof) == {
        'source', 'destination', 'export', 'snapshots'}
        and proof['source'] == source and proof['destination'] == destination
        and proof['export'] == export and source != destination,
        'complete origin byte proof differs from caller scope')
    snapshots = proof['snapshots']
    archive.require(type(snapshots) is list and 0 < len(snapshots) <= MAX_SOURCE_CHECKPOINTS,
                    'complete origin source count bound')
    for index, snapshot in enumerate(snapshots):
        archive.require(type(snapshot) is dict and type(snapshot.get('statement')) is dict,
                        'complete origin statement absent')
        statement = snapshot['statement']
        archive.require(type(statement.get('height')) is int
                        and statement['height'] == index + 1
                        and statement.get('region') == source
                        and statement.get('currency') == currency,
                        'complete origin declared order/currency/source differs')
    # These declarations cannot establish authenticated source finality.


def make_frames(raw, *, source, destination, export, currency):
    _shape(raw, source=source, destination=destination, export=export, currency=currency)
    return tuple(wire.make_frame('source-finality', source, destination, export, piece)
                 for piece in parts.split_object(raw))


def retain_proof(pieces, expected_hash, expected_bytes, target, *, source,
                 destination, export, currency):
    raw = parts.assemble_object(pieces, expected_hash, expected_bytes)
    _shape(raw, source=source, destination=destination, export=export, currency=currency)
    target = Path(target)
    archive.require(not target.exists() and not target.is_symlink(),
                    'complete origin proof target must be absent; no resume or overwrite')
    # A write interruption retains residue. Only Native complete parsing and
    # execution can admit the resulting file; byte retention makes no assertion.
    wire.write_new(target, raw)
    return expected_hash
