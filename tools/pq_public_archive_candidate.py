"""Bounded multi-object public carriage; byte completeness only, never authority.

The caller retains the manifest SHA512 independently. Core still verifies every
complete ordered entry using its separately trusted anchor, observations and head.
"""
import hashlib
import hmac
import struct

import pq_public_carriage_candidate as carriage

DOMAIN = b'RLD-PQ-PUBLIC-ARCHIVE-CANDIDATE-V1\0'
COUNT = struct.Struct('>H')
ENTRY = struct.Struct('>I64s')
MAX_ENTRIES = 64
MAX_TOTAL_BYTES = 2097152
MAX_ENTRY_PACKETS = MAX_ENTRIES * carriage.MAX_PARTS


def encode_manifest(entries: tuple[bytes, ...] | list[bytes]) -> bytes:
    if not isinstance(entries, (tuple, list)) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError('archive entry count outside candidate bound')
    records = []
    roots = set()
    total = 0
    for raw in entries:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= carriage.MAX_WHOLE_BYTES:
            raise ValueError('archive entry outside original whole bound')
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('archive aggregate exceeds fixed bound')
        digest = hashlib.sha512(raw).digest()
        if digest in roots:
            raise ValueError('duplicate complete archive entry')
        roots.add(digest)
        records.append(ENTRY.pack(len(raw), digest))
    return DOMAIN + COUNT.pack(len(records)) + b''.join(records)


def decode_manifest(raw: bytes) -> tuple[tuple[int, bytes], ...]:
    if (not isinstance(raw, bytes) or not raw.startswith(DOMAIN)
            or len(raw) < len(DOMAIN) + COUNT.size):
        raise ValueError('archive manifest format refused')
    count, = COUNT.unpack_from(raw, len(DOMAIN))
    if not 1 <= count <= MAX_ENTRIES or len(raw) != len(DOMAIN) + COUNT.size + count * ENTRY.size:
        raise ValueError('archive manifest count/canonical size refused')
    records = tuple(ENTRY.iter_unpack(raw[len(DOMAIN) + COUNT.size:]))
    total = 0
    roots = set()
    for size, digest in records:
        if not 1 <= size <= carriage.MAX_WHOLE_BYTES or digest in roots:
            raise ValueError('archive entry size/root refused')
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError('archive aggregate exceeds fixed bound')
        roots.add(digest)
    return records


def split_archive(entries: tuple[bytes, ...] | list[bytes]) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    manifest = encode_manifest(entries)
    manifest_parts = carriage.split_public_bytes(manifest)
    entry_parts = tuple(part for raw in entries for part in carriage.split_public_bytes(raw))
    return manifest_parts, entry_parts


def reassemble_archive(manifest_parts: tuple[bytes, ...] | list[bytes],
                       entry_parts: tuple[bytes, ...] | list[bytes],
                       expected_manifest_digest: bytes) -> tuple[bytes, ...]:
    manifest = carriage.reassemble_public_bytes(manifest_parts, expected_manifest_digest)
    records = decode_manifest(manifest)
    if not isinstance(entry_parts, (tuple, list)) or len(entry_parts) > MAX_ENTRY_PACKETS:
        raise ValueError('archive fragment inventory exceeds fixed bound')
    pending = {digest: [] for _, digest in records}
    sizes = {digest: size for size, digest in records}
    for packet in entry_parts:
        size, _, _, digest, _ = carriage.parse_public_fragment(packet)
        if digest not in pending or size != sizes[digest]:
            raise ValueError('foreign entry or changed manifest size')
        if len(pending[digest]) >= carriage.MAX_PARTS:
            raise ValueError('entry fragment inventory exceeds original bound')
        pending[digest].append(packet)
    complete = []
    for size, digest in records:
        raw = carriage.reassemble_public_bytes(pending[digest], digest)
        if len(raw) != size or not hmac.compare_digest(hashlib.sha512(raw).digest(), digest):
            raise ValueError('entry differs from ordered manifest')
        complete.append(raw)
    return tuple(complete)
