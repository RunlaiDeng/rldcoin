"""Original complete Python transit checks; independent signatures/frame tests only."""
import base64
import hashlib
import interstellar_mesh as mesh
import interstellar_transfer as wire
import interstellar_frame_reference as evidence
from interstellar_crypto_reference import verify_reference as verify
from interstellar_schema_reference import receipt_route_check
require=mesh.require
hex32=mesh.hex32
integer=mesh.integer
MAX_HOPS=mesh.MAX_HOPS
def digest(value):return hashlib.sha256(wire.canonical(value)).hexdigest()

def packet_check(value, network):
    body,raw,_=_packet_frame_check(value,network)
    return body,raw


def _packet_frame_check(value, network):
    # One complete frame authentication for this operation only. No header or
    # payload is retained by the process-local transit witness.
    body = verify(value, 'packet', network)
    require(set(body) == {'format', 'network', 'node_id', 'destination', 'nonce', 'hop_limit', 'frame'}, 'invalid packet fields')
    hex32(body['destination'])
    hex32(body['nonce'])
    integer(body['hop_limit'], 1, MAX_HOPS)
    require(isinstance(body['frame'], str) and len(body['frame']) <= evidence.MAX_FRAME * 2, 'frame outside bound')
    try:
        raw = base64.b64decode(body['frame'], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError('invalid frame encoding') from error
    require(base64.b64encode(raw).decode() == body['frame'], 'noncanonical frame encoding')
    frame, payload = evidence.inspect_frame(raw)
    if frame['kind'] == 'regional-bft':
        require(evidence.decode_json(payload)['currency'] == network,
            'consensus carriage differs from mesh currency')
    return body, raw, frame


def _transit_check(transit, network, recipient=None, sender=None):
    require(isinstance(transit, dict) and set(transit) == {'packet', 'routing', 'hops'}, 'invalid transit fields')
    packet, raw, frame = _packet_frame_check(transit['packet'], network)
    packet_id = digest(transit['packet'])
    routing = receipt_route_check(transit['routing'], network)
    require(routing['node_id'] == packet['node_id'] and routing['packet_id'] == packet_id
            and routing['destination'] == packet['destination'] and routing['frame_id'] == frame['message_id'],
            'receipt routing certificate differs from signed packet')
    hops = transit['hops']
    require(isinstance(hops, list) and len(hops) <= packet['hop_limit'], 'hop limit exceeded')
    previous, current = packet_id, packet['node_id']
    visited = [current]
    for hop in hops:
        body = verify(hop, 'hop', network)
        require(set(body) == {'format', 'network', 'node_id', 'packet_id', 'previous', 'to'}, 'invalid hop fields')
        hex32(body['to'])
        require(body['node_id'] == current and body['previous'] == previous
                and body['packet_id'] == packet_id, 'broken signed hop chain')
        require(body['to'] not in visited, 'routing loop')
        current, previous = body['to'], digest(hop)
        visited.append(current)
    if recipient is not None:
        require(bool(hops) and current == recipient and hops[-1]['body']['node_id'] == sender,
                'hop does not authorize this contact')
    return packet, raw, visited
