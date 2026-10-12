"""Original Python typed mesh schema and independent signature oracle, tests only."""
import interstellar_mesh as mesh
from interstellar_crypto_reference import verify_reference as verify
require=mesh.require
hex32=mesh.hex32
integer=mesh.integer
MAX_CONTACTS=mesh.MAX_CONTACTS
MAX_MESSAGES=mesh.MAX_MESSAGES

def advert_check(value, network):
    body = verify(value, 'advert', network)
    require(set(body) == {'format', 'network', 'node_id', 'region', 'label', 'sequence', 'neighbors'}, 'invalid advertisement fields')
    hex32(body['region'])
    require(isinstance(body['label'], str) and 1 <= len(body['label']) <= 80 and body['label'].isascii()
            and all(ord(c) >= 32 for c in body['label']), 'invalid display label')
    integer(body['sequence'], 1, 2**63 - 1)
    neighbors = body['neighbors']
    require(isinstance(neighbors, list) and len(neighbors) <= MAX_CONTACTS
            and all(isinstance(peer, str) for peer in neighbors), 'invalid neighbor list')
    require(neighbors == sorted(set(neighbors)), 'invalid neighbor order or duplicate')
    for peer in neighbors:
        hex32(peer)
        require(peer != body['node_id'], 'self contact')
    return body


def receipt_route_check(route, network):
    body = verify(route, 'receipt-route', network)
    require(set(body) == {'format', 'network', 'node_id', 'packet_id', 'destination', 'frame_id'},
            'invalid source-signed receipt routing certificate')
    for field in ('packet_id', 'destination', 'frame_id'):hex32(body[field])
    return body


def inventory_check(inventory, network):
    body = verify(inventory, 'inventory', network)
    require(set(body) == {'format', 'network', 'node_id', 'packet_ids'} and isinstance(body['packet_ids'],list)
            and len(body['packet_ids']) <= MAX_MESSAGES, 'invalid peer inventory capacity/schema')
    for ident in body['packet_ids']:hex32(ident)
    require(body['packet_ids'] == sorted(set(body['packet_ids'])), 'peer inventory duplicate/order invalid')
    return body


def receipt_check(receipt, network):
    body = verify(receipt, 'receipt', network)
    require(set(body) == {'format', 'network', 'node_id', 'packet_id', 'frame_id', 'routing', 'outcome'}, 'invalid receipt fields')
    hex32(body['packet_id'])
    hex32(body['frame_id'])
    require(body['outcome'] == 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED', 'wrong receipt outcome')
    routing = receipt_route_check(body['routing'], network)
    require(body['node_id'] == routing['destination'] and body['packet_id'] == routing['packet_id']
            and body['frame_id'] == routing['frame_id'], 'wrong destination receipt')
    return body['packet_id']
