"""Pure public-byte fragmentation candidate; no TLS, keys, custody or authority.

Receiver supplies a separately retained expected SHA512. Reassembly authenticates
bytes only; actual Core and locally trusted quorum policy still decide acceptance.
"""
import hashlib
import hmac
import struct

DOMAIN = b"RLD-PQ-PUBLIC-CARRIAGE-CANDIDATE-V1\0"
FIELDS = struct.Struct(">IHH64s")
DATA_BYTES = 12000
MAX_PACKET_BYTES = 12288
MAX_WHOLE_BYTES = 32768
MAX_PARTS = 3
assert len(DOMAIN) + FIELDS.size + DATA_BYTES <= MAX_PACKET_BYTES


class IncompletePublicCarriage(ValueError):
    """Preserve incomplete inputs; absence is not a receipt or authorization."""


def split_public_bytes(raw: bytes) -> tuple[bytes, ...]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_WHOLE_BYTES:
        raise ValueError("public whole outside fixed candidate bound")
    digest = hashlib.sha512(raw).digest()
    count = (len(raw) + DATA_BYTES - 1) // DATA_BYTES
    return tuple(
        DOMAIN + FIELDS.pack(len(raw), count, index, digest)
        + raw[index * DATA_BYTES:(index + 1) * DATA_BYTES]
        for index in range(count)
    )


def parse_public_fragment(packet: bytes) -> tuple[int, int, int, bytes, bytes]:
    if (not isinstance(packet, bytes) or len(packet) > MAX_PACKET_BYTES
            or len(packet) < len(DOMAIN) + FIELDS.size or not packet.startswith(DOMAIN)):
        raise ValueError("public fragment format/size refused")
    total, count, index, digest = FIELDS.unpack_from(packet, len(DOMAIN))
    if (not 0 < total <= MAX_WHOLE_BYTES or not 0 < count <= MAX_PARTS
            or count != (total + DATA_BYTES - 1) // DATA_BYTES or index >= count):
        raise ValueError("public fragment whole/count/index refused")
    data = packet[len(DOMAIN) + FIELDS.size:]
    expected = min(DATA_BYTES, total - index * DATA_BYTES)
    if len(data) != expected:
        raise ValueError("public fragment canonical length refused")
    return total, count, index, digest, data


def reassemble_public_bytes(parts: tuple[bytes, ...] | list[bytes], expected_digest: bytes) -> bytes:
    if not isinstance(expected_digest, bytes) or len(expected_digest) != 64:
        raise ValueError("independently retained expected whole SHA512 required")
    if not isinstance(parts, (tuple, list)) or len(parts) > MAX_PARTS:
        raise ValueError("public part inventory exceeds bound")
    if not parts:
        raise IncompletePublicCarriage("no complete public input")
    decoded = [parse_public_fragment(packet) for packet in parts]
    total, count, _, digest, _ = decoded[0]
    if not hmac.compare_digest(digest, expected_digest):
        raise ValueError("fragment does not bind expected public whole")
    indexes = set()
    for other_total, other_count, index, other_digest, _ in decoded:
        if (other_total != total or other_count != count
                or not hmac.compare_digest(other_digest, digest) or index in indexes):
            raise ValueError("mixed or duplicate public fragments")
        indexes.add(index)
    if len(parts) != count or indexes != set(range(count)):
        raise IncompletePublicCarriage("public whole missing fragments")
    raw = b"".join(data for _, _, _, _, data in sorted(decoded, key=lambda value: value[2]))
    if len(raw) != total or not hmac.compare_digest(hashlib.sha512(raw).digest(), expected_digest):
        raise ValueError("complete public bytes fail length/root")
    return raw
