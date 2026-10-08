"""Operation-local exact canonical transit hashing; no authority or cache.

A Base64 frame needs no JSON escaping. Serialize the bounded surrounding
metadata normally and feed the exact frame bytes into the same SHA-256 stream.
Any unsupported shape/encoding takes the original complete canonical path.
"""
import hashlib

import interstellar_transfer as wire

SAFE_ASCII = bytes(c for c in range(32, 127) if c not in (34, 92))
PATH = ('packet', 'body', 'frame')


def packet_body_bytes(body):
    """Exact signature bytes, with no retained object or authentication shortcut.

    Only an escape-free bounded ASCII frame bypasses JSON's large-string
    encoder. Metadata uses the ordinary canonical encoder. Unsupported values
    take that original complete path, including its original errors.
    """
    if (not isinstance(body, dict) or 'frame' not in body
            or any(type(k) is not str for k in body)):
        return wire.canonical(body)
    value = body['frame']
    if type(value) is not str or not value.isascii() or len(value) > wire.MAX_FRAME * 2:
        return wire.canonical(body)
    frame = value.encode('ascii')
    if frame.translate(None, SAFE_ASCII):
        return wire.canonical(body)
    left, right = _split(body, ('frame',))
    return left + frame + right


def _split(value, path):
    if not path:
        return b'"', b'"'
    key = path[0]
    keys = sorted(value)
    before = [wire.canonical(k) + b':' + wire.canonical(value[k]) for k in keys if k < key]
    after = [wire.canonical(k) + b':' + wire.canonical(value[k]) for k in keys if k > key]
    left, right = _split(value[key], path[1:])
    return (b'{' + b','.join(before) + (b',' if before else b'') + wire.canonical(key) + b':' + left,
            right + (b',' if after else b'') + b','.join(after) + b'}')


def commitment(transit):
    """Return exact (canonical SHA-256, size); never validate a signature."""
    return _commitment(transit, PATH)


def packet_commitment(packet):
    """Exact signed packet ID and size; signatures remain independently checked."""
    return _commitment(packet, ('body', 'frame'))


def archive_commitment(blob):
    """Exact complete archive bytes, with no retained witness or authority.

    Receipt-only or unsupported shapes retain the ordinary canonical path.
    Archive read still authenticates actual files, full transit and receipt.
    """
    return _commitment(blob, ('transit',) + PATH)


def _commitment(transit, path):
    value = transit
    for key in path:
        if not isinstance(value, dict) or key not in value or any(type(k) is not str for k in value):
            raw = wire.canonical(transit)
            return hashlib.sha256(raw).hexdigest(), len(raw)
        value = value[key]
    if type(value) is not str or not value.isascii() or len(value) > wire.MAX_FRAME * 2:
        raw = wire.canonical(transit)
        return hashlib.sha256(raw).hexdigest(), len(raw)
    frame = value.encode('ascii')
    # JSON escaping, not Base64 validity, is this helper's only concern. The
    # ordinary codec/packet validator still enforces canonical Base64. Check
    # control/DEL/quote/backslash bytes without another large regex traversal.
    if frame.translate(None, SAFE_ASCII):
        raw = wire.canonical(transit)
        return hashlib.sha256(raw).hexdigest(), len(raw)
    left, right = _split(transit, path)
    digest = hashlib.sha256()
    digest.update(left)
    digest.update(frame)
    digest.update(right)
    return digest.hexdigest(), len(left) + len(frame) + len(right)
