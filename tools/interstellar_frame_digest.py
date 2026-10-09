"""Exact canonical transit hashing; no authentication or ledger authority.

A Base64 frame needs no JSON escaping. Serialize the bounded surrounding
metadata normally and feed the exact frame bytes into the same SHA-256 stream.
Any unsupported shape/encoding takes the original complete canonical path.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import sys
import threading

import interstellar_transfer as wire

SAFE_ASCII = bytes(c for c in range(32, 127) if c not in (34, 92))
PATH = ('packet', 'body', 'frame')
MAX_PREFIX_WITNESS_BYTES = 8 * 1024 * 1024
MAX_PREFIX_WITNESS_ENTRIES = 512
MAX_PREFIX_LEFT_BYTES = 8192
_operation = ContextVar('rld_frame_hash_operation', default=None)
_operation_lock = threading.Lock()


class _PrefixHashes:
    """One operation's exact immutable input and SHA256 arithmetic only."""
    def __init__(self):
        # Conservative overhead allowances include dictionary/hasher storage.
        self.retained_bytes = 4096
        self.frames = {}
        self.prefixes = {}

    def commitment(self, transit, path):
        if (self.retained_bytes > MAX_PREFIX_WITNESS_BYTES
                or len(self.frames) > MAX_PREFIX_WITNESS_ENTRIES
                or len(self.prefixes) > MAX_PREFIX_WITNESS_ENTRIES):
            self.frames.clear()
            self.prefixes.clear()
            self.retained_bytes = 4096
            return _complete_commitment(transit, path)
        value = transit
        for key in path:
            if (not isinstance(value, dict) or key not in value
                    or any(type(k) is not str for k in value)):
                return _complete_commitment(transit, path)
            value = value[key]
        if (type(value) is not str or not value.isascii()
                or len(value) > wire.MAX_FRAME * 2):
            return _complete_commitment(transit, path)
        if value not in self.frames:
            frame = value.encode('ascii')
            if frame.translate(None, SAFE_ASCII):
                return _complete_commitment(transit, path)
            charge = sys.getsizeof(value) + 256
            if (len(self.frames) >= MAX_PREFIX_WITNESS_ENTRIES
                    or self.retained_bytes + charge > MAX_PREFIX_WITNESS_BYTES):
                return _complete_commitment(transit, path)
            self.frames[value] = True
            self.retained_bytes += charge
        # Every surrounding typed field uses the original canonical encoder.
        # Complete prefix bytes and the exact immutable string are compared;
        # neither a frame ID nor an unchecked digest supplies a cached result.
        left, right = _split(transit, path)
        key = (left, value)
        prefix = self.prefixes.get(key)
        if prefix is None:
            prefix = hashlib.sha256(left)
            prefix.update(value.encode('ascii'))
            charge = sys.getsizeof(left) + sys.getsizeof(key) + 512
            if (len(left) <= MAX_PREFIX_LEFT_BYTES
                    and len(self.prefixes) < MAX_PREFIX_WITNESS_ENTRIES
                    and self.retained_bytes + charge <= MAX_PREFIX_WITNESS_BYTES):
                self.prefixes[key] = prefix
                self.retained_bytes += charge
        digest = prefix.copy()
        digest.update(right)
        return digest.hexdigest(), len(left) + len(value) + len(right)


@contextmanager
def hashing_operation():
    """At most one bounded process-local witness; contention falls back.

    No waiting, persistence or authentication. Failure and return discard the
    witness. Nested synchronous hashing shares the enclosing operation budget.
    """
    if _operation.get() is not None:
        yield
        return
    if MAX_PREFIX_WITNESS_BYTES < 4096 or MAX_PREFIX_WITNESS_ENTRIES <= 0:
        yield
        return
    if not _operation_lock.acquire(blocking=False):
        yield
        return
    witness = token = None
    try:
        witness = _PrefixHashes()
        token = _operation.set(witness)
        yield
    finally:
        if witness is not None:
            witness.frames.clear()
            witness.prefixes.clear()
        if token is not None:
            _operation.reset(token)
        _operation_lock.release()


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
    """Exact complete archive bytes, with no authentication shortcut.

    Receipt-only or unsupported shapes retain the ordinary canonical path.
    Archive read still authenticates actual files, full transit and receipt.
    """
    return _commitment(blob, ('transit',) + PATH)


def _commitment(transit, path):
    witness = _operation.get()
    if witness is not None:
        return witness.commitment(transit, path)
    return _complete_commitment(transit, path)


def _complete_commitment(transit, path):
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
