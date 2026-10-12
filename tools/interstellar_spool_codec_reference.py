"""Explicit bounded lossless directory carriage, never authentication.

Decode the complete original bytes before canonical JSON, exchange signatures,
custody and Native checks. Both encoded and expanded bytes retain the caller's
original limit. One RFC1950 stream, a 32-KiB window and bounded output; no format
fallback, dictionary, concatenation, trailing bytes or partial output release.
"""
import hashlib
import struct
import zlib

FORMAT = 'RLD-CONTACT-SPOOL-ZLIB-V1'
MAGIC = (FORMAT + '\0').encode('ascii')
HEADER_SIZE = len(MAGIC) + 8 + 32


def require(ok, message):
    if not ok:
        raise ValueError(message)


def expanded_size(header, *, encoded_size, limit):
    """Capacity metadata only; the decoder still checks every original byte."""
    require(type(limit) is int and limit > 0, 'invalid spool codec limit')
    require(type(header) is bytes and len(header) == HEADER_SIZE
            and header.startswith(MAGIC), 'spool codec version/header differs')
    require(HEADER_SIZE < encoded_size <= limit, 'encoded spool bound exceeded')
    size = struct.unpack('>Q', header[len(MAGIC):len(MAGIC) + 8])[0]
    require(0 < size <= limit, 'expanded spool bound exceeded')
    return size


def encode(raw, *, limit):
    require(type(limit) is int and limit > 0, 'invalid spool codec limit')
    require(type(raw) is bytes and 0 < len(raw) <= limit, 'expanded spool bound exceeded')
    # Fixed sender parameters; compression does not change any signed bytes.
    data = MAGIC + struct.pack('>Q', len(raw)) + hashlib.sha256(raw).digest() + zlib.compress(raw, 1)
    require(len(data) <= limit, 'encoded spool bound exceeded')
    return data


def decode(data, *, limit):
    require(type(data) is bytes, 'invalid spool codec bytes')
    size = expanded_size(data[:HEADER_SIZE], encoded_size=len(data), limit=limit)
    try:
        stream = zlib.decompressobj(zlib.MAX_WBITS)
        # Never flush an unbounded stream. An understated length or bomb can
        # produce at most the declared original bound plus one refusal byte.
        raw = stream.decompress(data[HEADER_SIZE:], size + 1)
        require(len(raw) == size and stream.eof and not stream.unused_data
                and not stream.unconsumed_tail, 'incomplete or trailing spool stream')
    except zlib.error as error:
        raise ValueError('invalid spool compression stream') from error
    require(hashlib.sha256(raw).digest() == data[len(MAGIC) + 8:HEADER_SIZE],
            'expanded spool bytes differ')
    return raw
