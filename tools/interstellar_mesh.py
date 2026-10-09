#!/usr/bin/env python3
"""Signed, durable contact-spool discovery and multi-hop evidence prototype.

This is a supplemental ground reference, not BPv7, a physical radio, ledger
consensus, payment acceptance or an authenticated claim to govern a region.
Contact adapters move complete *.json files between configured spool directories.
"""
import argparse
import base64
from bisect import bisect_right
from collections import OrderedDict
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import interstellar_transfer as evidence
import interstellar_active_state as active_state
import interstellar_frame_digest as frame_digest
import interstellar_spool_codec as spool_codec

VERSION = 'RLD-CONTACT-MESH-V3'
SPOOL_ONEWAY = 'RLD-CONTACT-SPOOL-ONEWAY-V1'
ARCHIVE_STORAGE = 'RLD-CONTACT-ARCHIVE-SHARED-FRAME-V1'
ARCHIVE_FRAME = 'RLD-CONTACT-ARCHIVE-FRAME-V1'
RECEIPT_SCHEDULER = 'RLD-CONTACT-RECEIPT-SCHEDULER-V2'
TRANSIT_SCHEDULER = 'RLD-CONTACT-TRANSIT-SCHEDULER-V33'
ACTIVE_STORAGE = active_state.STORAGE
MAX_NODES = 64
MAX_CONTACTS = 16
MAX_MESSAGES = 256
MAX_STATE = 64 * 1024 * 1024
MAX_BATCH = 20 * 1024 * 1024
MAX_SPOOL_FILES = 256
MAX_SPOOL_BYTES = 64 * 1024 * 1024
MAX_PACKET_BATCH = 4
MAX_HOPS = 16
HEX = re.compile(r'[0-9a-f]{64}\Z')
STATE_KEYS = {'first_arrivals', 'first_carriage', 'transit_scheduler', 'transit_cursors', 'recent_transits', 'recent_transit_cursors', 'history_transit_cursors', 'transit_class_steps', 'active_storage', 'format', 'archive_storage', 'receipt_scheduler', 'network', 'node_id', 'adverts', 'messages', 'receipts', 'archives', 'peer_inventory', 'cursor', 'receipt_cursors', 'requested_receipt_cursors'}
MAX_RECENT_TRANSITS = 32
# Full native certificates can make a modest packet count a large active
# document. Archive completed custody earlier; retain the same admission,
# archive, batch and pending-evidence bounds.
ARCHIVE_HIGH_WATER = 32
MAX_ARCHIVE_FILES = 4096
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BATCH = 16
MAX_RECEIPT_BATCH = MAX_ARCHIVE_BATCH
MAX_VERIFIED_TRANSITS = 512
_verified_transits = OrderedDict()
_verified_transits_lock = threading.Lock()
# One immutable metadata witness per process. Payloads, disk inventory and
# fresh contacts retain their own checks; this never grants custody or value.
MAX_VERIFIED_ARCHIVE_INDEX_BYTES = 4 * 1024 * 1024
_verified_archive_index = None
_verified_archive_index_lock = threading.Lock()

# Bounded process-local scheduling positions, never authentication or custody.
# Only primitive namespace, destination, complete-frame and packet IDs survive.
# A Native companion may supply exact current Commit frame IDs for spare slots;
# these positions never authenticate a packet or a Native envelope.
MAX_CARRIAGE_POSITIONS = 512
MAX_CARRIAGE_POSITION_BYTES = 4 * 1024 * 1024
_carriage_positions = OrderedDict()
_carriage_position_lock = threading.Lock()
_carriage_position_bytes = 0

def carriage_position(key):
    with _carriage_position_lock:
        row=_carriage_positions.get(key)
        if row is not None:
            _carriage_positions.move_to_end(key)
            return row[0]
    return None

def remember_carriage_position(key, value):
    global _carriage_position_bytes
    size=len(repr((key,value)).encode('utf-8'))
    with _carriage_position_lock:
        old=_carriage_positions.pop(key,None)
        if old is not None:_carriage_position_bytes-=old[1]
        if size<=MAX_CARRIAGE_POSITION_BYTES and MAX_CARRIAGE_POSITIONS>0:
            _carriage_positions[key]=(value,size);_carriage_position_bytes+=size
        while _carriage_positions and (len(_carriage_positions)>MAX_CARRIAGE_POSITIONS
                or _carriage_position_bytes>MAX_CARRIAGE_POSITION_BYTES):
            _,(_,removed)=_carriage_positions.popitem(last=False)
            _carriage_position_bytes-=removed

def forget_carriage_position(key):
    global _carriage_position_bytes
    with _carriage_position_lock:
        row=_carriage_positions.pop(key,None)
        if row is not None:_carriage_position_bytes-=row[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return frame_digest.packet_commitment(value)[0]


def hex32(value):
    require(isinstance(value, str) and HEX.fullmatch(value), 'invalid 32-byte identifier')
    return value


def node_id(public):
    hex32(public)
    return hashlib.sha256((VERSION + '\0node\0').encode() + bytes.fromhex(public)).hexdigest()


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer outside bound')


def safe_dir(path):
    path = Path(path)
    require(path.is_absolute(), 'directory must be absolute')
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'symlink directory refused')
    evidence.ensure_dir(path)
    return path


def load(path, limit):
    raw = evidence.read_file(Path(path), limit)
    value = evidence.decode_json(raw)
    require(raw == evidence.canonical(value), 'noncanonical JSON')
    if isinstance(value, dict) and value.get('format') == ACTIVE_STORAGE:
        return unpack_state_storage(value, value['network'], value['node_id'])
    return value


def pack_state_storage(state):
    return active_state.pack(state, max_state=MAX_STATE, max_messages=MAX_MESSAGES, max_transit=MAX_BATCH)


def unpack_state_storage(value, network, node):
    return active_state.unpack(value, network=network, node_id=node, max_state=MAX_STATE,
                               max_messages=MAX_MESSAGES, max_transit=MAX_BATCH)


def load_state_storage(path, network, node):
    raw=evidence.read_file(Path(path), MAX_STATE)
    return active_state.decode(raw, network=network, node_id=node, max_state=MAX_STATE,
                               max_messages=MAX_MESSAGES, max_transit=MAX_BATCH)


def spool_files(root, adapter=None):
    files, total = [], 0
    for path in root.iterdir():
        require(len(files) < MAX_SPOOL_FILES, 'contact file capacity reached; preserve spool')
        require(re.fullmatch(r'[0-9a-f]{64}\.json', path.name) and path.is_file() and not path.is_symlink(), 'unsafe contact spool file')
        size = path.stat().st_size
        if adapter == spool_codec.FORMAT:
            # Header length grants no authentication. Invalid or understated
            # streams refuse on complete decode; retain them without receipt.
            with path.open('rb') as handle:
                header = handle.read(spool_codec.HEADER_SIZE)
            size = max(size, spool_codec.expanded_size(header, encoded_size=size, limit=MAX_BATCH))
        total += size
        require(total <= MAX_SPOOL_BYTES, 'contact byte capacity reached; preserve spool')
        files.append(path)
    return sorted(files), total


def atomic(path, value):
    if isinstance(value, dict) and 'messages' in value and value.get('active_storage') == ACTIVE_STORAGE:
        value = pack_state_storage(value)
    raw = evidence.canonical(value)
    require(len(raw) <= MAX_STATE, 'durable state capacity reached; retain previous state')
    temporary = path.parent / ('.write-' + os.urandom(16).hex())
    try:
        evidence.write_new(temporary, raw)
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def sync_retained(path):
    """Reaffirm unchanged custody without rewriting the complete archive."""
    descriptor=os.open(path,os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor=os.open(path.parent,os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_retained_many(paths):
    """Same-operation custody: every distinct file, then each parent directory.

    No result survives the call. Failure prevents receive acknowledgment and
    publication; shared frames still require their own complete authentication.
    """
    # Preserve dependency-before-wrapper order while coalescing repeated paths.
    paths = list(dict.fromkeys(paths))
    require(len(paths) <= 2 * (MAX_MESSAGES + MAX_PACKET_BATCH),
            'retained custody sync capacity exceeded')
    parents = set()
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parents.add(path.parent)
    for parent in sorted(parents):
        descriptor = os.open(parent, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def archive_write(path, raw):
    temporary=path.parent/('.archive-write-'+os.urandom(32).hex())
    try:
        evidence.write_new(temporary,raw)
        try:
            os.link(temporary,path)
        except FileExistsError:
            require(evidence.read_file(path,MAX_STATE)==raw,'existing archive differs')
        sync_retained(path)
    finally:
        # This is disposable staging; original active custody is unchanged
        # until the separately durable archive and index transaction succeed.
        temporary.unlink(missing_ok=True)
        descriptor=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)


def sign(key, kind, body):
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {'body': body, 'public_key': public,
            'signature': key.sign((VERSION + '\0' + kind + '\0').encode() + evidence.canonical(body)).hex()}


def verify(value, kind, network):
    require(isinstance(value, dict) and set(value) == {'body', 'public_key', 'signature'}, 'invalid signed object')
    body = value['body']
    require(isinstance(body, dict) and body.get('network') == network and body.get('format') == VERSION, 'wrong network or version')
    public = hex32(value['public_key'])
    require(isinstance(value['signature'], str) and re.fullmatch(r'[0-9a-f]{128}', value['signature']), 'invalid signature encoding')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(value['signature']), (VERSION + '\0' + kind + '\0').encode()
            + (frame_digest.packet_body_bytes(body) if kind == 'packet' else evidence.canonical(body)))
    except InvalidSignature as error:
        raise ValueError('invalid signature') from error
    require(body.get('node_id') == node_id(public), 'node identity mismatch')
    return body


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


def transit_check(transit, network, recipient=None, sender=None, *, include_frame=True):
    """Reuse only a bounded witness for exact previously authenticated bytes.

    No frame, key, mutable result or unchecked state is cached. Ownership and
    archive limits are still checked by the caller; Native Rust verifies value.
    """
    require(type(include_frame) is bool, 'invalid transit frame output choice')
    require(isinstance(transit,dict) and set(transit)=={'packet','routing','hops'}
            and isinstance(transit['packet'],dict) and isinstance(transit['routing'],dict)
            and isinstance(transit['hops'],list),'invalid transit fields')
    namespace=(VERSION,hex32(network),recipient,sender,MAX_HOPS,evidence.FORMAT,evidence.DOMAIN,
               evidence.MAX_FRAME,evidence.MAX_PAYLOAD,tuple(sorted(evidence.KINDS | evidence.CONTROL_KINDS)))
    key=(namespace,active_state.commitment(transit)[0])
    with _verified_transits_lock:
        while len(_verified_transits)>MAX_VERIFIED_TRANSITS:
            _verified_transits.popitem(last=False)
        visited=_verified_transits.get(key)
        if visited is not None:_verified_transits.move_to_end(key)
    if visited is not None:
        packet=transit['packet']['body']
        return packet,(base64.b64decode(packet['frame'],validate=True) if include_frame else None),list(visited)
    packet,raw,visited=_transit_check(transit,network,recipient,sender)
    with _verified_transits_lock:
        if MAX_VERIFIED_TRANSITS>0:
            _verified_transits[key]=tuple(visited)
            _verified_transits.move_to_end(key)
            while len(_verified_transits)>MAX_VERIFIED_TRANSITS:
                _verified_transits.popitem(last=False)
    # A miss always performs the original complete frame checks above. Only
    # this optional output is discarded; witness bounds/domain/bytes stay exact.
    return packet,raw if include_frame else None,visited


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


def receipt_matches(receipt, transit):
    # Full transit verification (or its exact-byte witness) already binds the
    # source-signed route to the completely verified frame ID. Do not decode and
    # canonicalize the large native payload again for every retained receipt.
    packet,_,_=transit_check(transit,transit['packet']['body']['network'])
    _match_receipt(receipt,packet,transit['routing']['body'])


def _match_receipt(receipt, packet, routing):
    # Internal only: callers have authenticated this exact transit earlier in
    # the same operation. Nothing survives the call; external receipt matching
    # still performs complete transit verification/exact-byte witnessing.
    require(receipt['body']['node_id'] == packet['destination']
            and receipt['body']['frame_id'] == routing['frame_id']
            and receipt['body']['routing']['body'] == routing, 'wrong destination receipt')


def initialize(root, network, region, label):
    root = safe_dir(root)
    hex32(network)
    hex32(region)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    identity = {'transit_scheduler': TRANSIT_SCHEDULER, 'active_storage': ACTIVE_STORAGE, 'format': VERSION, 'archive_storage': ARCHIVE_STORAGE, 'receipt_scheduler': RECEIPT_SCHEDULER, 'network': network, 'region': region, 'label': label,
                'public_key': public, 'private_key': key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()}
    # Validate public fields before creating the sole private identity file.
    advert_check(sign(key, 'advert', {'format': VERSION, 'network': network, 'region': region,
                 'label': label, 'node_id': node_id(public), 'sequence': 1, 'neighbors': []}), network)
    evidence.write_new(root / 'identity.private.json', evidence.canonical(identity))
    return {'node_id': node_id(public), 'public_key': public, 'network': network, 'region': region}


def tcp_endpoint(host, port, listening=False):
    require(isinstance(host, str) and len(host) <= 15, 'TCP host must be a literal IPv4 address')
    address = ipaddress.IPv4Address(host)
    integer(port, 0 if listening else 1, 65535)
    require(not address.is_multicast and host != '255.255.255.255'
            and (listening or not address.is_unspecified), 'invalid TCP endpoint')
    return str(address), port


def contact_schema(contact):
    require(isinstance(contact,dict) and set(contact) in
            ({'peer','inbox','outbox'},{'peer','host','port'},
             {'peer','host','port','tls_cert_sha256'},
             {'peer','adapter','inbox'},{'peer','adapter','outbox'},
             {'peer','adapter','inbox','outbox'}),
            'invalid contact')
    if 'adapter' in contact:
        require(contact['adapter'] == spool_codec.FORMAT or
                (contact['adapter'] == SPOOL_ONEWAY and
                 set(contact) in ({'peer','adapter','inbox'}, {'peer','adapter','outbox'})),
                'unsupported spool adapter')
    return contact


def outgoing_contact(contact):
    return 'host' in contact or 'outbox' in contact


def incoming_contact(contact):
    return 'host' in contact or 'inbox' in contact


def empty_first_carriage():
    # Primitive scheduling metadata only; every list is independently owned.
    return {'pending': [], 'prepared': [], 'arrivals': [], 'observed': None,
            'history_after': None, 'next_kind': 0}


class Node:
    def __init__(self, config, nonblocking=False):
        require(isinstance(config, dict) and set(config) == {'format', 'state', 'network', 'contacts'}, 'invalid config fields')
        require(config['format'] == VERSION, 'unsupported config')
        self.root = safe_dir(config['state'])
        self.network = hex32(config['network'])
        self.lock = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
            identity = load(self.root / 'identity.private.json', 8192)
            require(set(identity) == {'transit_scheduler', 'active_storage', 'format', 'archive_storage', 'receipt_scheduler', 'network', 'region', 'label', 'public_key', 'private_key'}
                    and identity['format'] == VERSION and identity['archive_storage'] == ARCHIVE_STORAGE
                    and identity['receipt_scheduler'] == RECEIPT_SCHEDULER
                    and identity['active_storage'] == ACTIVE_STORAGE
                    and identity['transit_scheduler'] == TRANSIT_SCHEDULER
                    and identity['network'] == self.network, 'identity network/storage mismatch')
            require((self.root / 'identity.private.json').stat().st_mode & 0o077 == 0, 'private identity permissions too broad')
            self.key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex32(identity['private_key'])))
            public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            require(public == identity['public_key'], 'private identity mismatch')
            self.id = node_id(public)
            contacts = config['contacts']
            require(isinstance(contacts, list) and len(contacts) <= MAX_CONTACTS, 'contact capacity reached')
            self.contacts = {}
            for contact in contacts:
                contact_schema(contact)
                peer = hex32(contact['peer'])
                require(peer != self.id and peer not in self.contacts, 'duplicate or self contact')
                if 'host' in contact:
                    host, port = tcp_endpoint(contact['host'], contact['port'])
                    self.contacts[peer] = {'host': host, 'port': port}
                    if 'tls_cert_sha256' in contact:
                        self.contacts[peer]['tls_cert_sha256'] = hex32(contact['tls_cert_sha256'])
                else:
                    self.contacts[peer] = {k: safe_dir(contact[k]) for k in ('inbox', 'outbox') if k in contact}
                    if contact.get('adapter') == spool_codec.FORMAT:
                        self.contacts[peer]['adapter'] = spool_codec.FORMAT
                    if 'inbox' in contact and 'outbox' in contact:
                        require(self.contacts[peer]['inbox'] != self.contacts[peer]['outbox'], 'contact directions must differ')
            dirs = [p for contact in self.contacts.values() for name,p in contact.items() if name in ('inbox','outbox')]
            require(len(set(dirs)) == len(dirs), 'contact spools must be distinct')
            self.path = self.root / 'mesh-state.json'
            self.archive_root = safe_dir(self.root / 'archive')
            require(not self.path.is_symlink(), 'symlink state refused')
            existed=self.path.exists()
            if existed:
                self.state = load_state_storage(self.path, self.network, self.id)
                self.validate_state()
            else:
                self.state = {'transit_scheduler': TRANSIT_SCHEDULER, 'transit_cursors': {peer: None for peer in self.contacts}, 'active_storage': ACTIVE_STORAGE, 'format': VERSION, 'archive_storage': ARCHIVE_STORAGE, 'receipt_scheduler': RECEIPT_SCHEDULER, 'network': self.network, 'node_id': self.id,
                              'first_arrivals': [], 'recent_transits': [], 'recent_transit_cursors': {peer: None for peer in self.contacts},
                              'history_transit_cursors': {peer: None for peer in self.contacts},
                              'transit_class_steps': {peer: 0 for peer in self.contacts},
                              'first_carriage': {peer: empty_first_carriage() for peer in self.contacts},
                              'adverts': {}, 'messages': {}, 'receipts': {}, 'archives': {}, 'peer_inventory': {}, 'cursor': 0,
                              'receipt_cursors': {peer: 0 for peer in self.contacts},
                              'requested_receipt_cursors': {peer: 0 for peer in self.contacts}}
            # Inventories are only bounded delivery-demand caches. Removing a
            # configured contact may forget its cache, never messages/receipts.
            inventory_changed=any(i not in self.contacts for i in self.state['peer_inventory'])
            self.state['peer_inventory'] = {i:v for i,v in self.state['peer_inventory'].items() if i in self.contacts}
            # These bounded local cursors schedule only current configured peers.
            # Forgetting a removed peer's cursor never removes carriage evidence.
            receipt_cursors = {peer: self.state['receipt_cursors'].get(peer, 0) for peer in self.contacts}
            receipt_cursors_changed = receipt_cursors != self.state['receipt_cursors']
            self.state['receipt_cursors'] = receipt_cursors
            requested_receipt_cursors = {peer: self.state['requested_receipt_cursors'].get(peer, 0) for peer in self.contacts}
            requested_receipt_cursors_changed = requested_receipt_cursors != self.state['requested_receipt_cursors']
            self.state['requested_receipt_cursors'] = requested_receipt_cursors
            transit_cursors = {peer: self.state['transit_cursors'].get(peer) for peer in self.contacts}
            transit_cursors_changed = transit_cursors != self.state['transit_cursors']
            self.state['transit_cursors'] = transit_cursors
            class_cursors_changed=False
            for name,default in (('recent_transit_cursors',None),('history_transit_cursors',None),('transit_class_steps',0)):
                values={peer:self.state[name].get(peer,default) for peer in self.contacts}
                class_cursors_changed=class_cursors_changed or values!=self.state[name]
                self.state[name]=values
            first_carriage={peer:self.state['first_carriage'].get(peer,empty_first_carriage()) for peer in self.contacts}
            class_cursors_changed=class_cursors_changed or first_carriage!=self.state['first_carriage']
            self.state['first_carriage']=first_carriage
            old = self.state['adverts'].get(self.id)
            body = {'format': VERSION, 'network': self.network, 'node_id': self.id,
                    'region': identity['region'], 'label': identity['label'], 'sequence': 1,
                    'neighbors': sorted(peer for peer,contact in self.contacts.items() if outgoing_contact(contact))}
            if old:
                body['sequence'] = old['body']['sequence']
                if body != old['body']:
                    body['sequence'] += 1
            self.state['adverts'][self.id] = sign(self.key, 'advert', body)
            advert_check(self.state['adverts'][self.id], self.network)
            # Opening a verified archive is a read operation unless configured
            # inventory/advertisement actually changes. Rewriting megabytes on
            # every lock acquisition can prevent bounded contacts completing.
            if not existed or inventory_changed or receipt_cursors_changed or requested_receipt_cursors_changed or transit_cursors_changed or class_cursors_changed or old!=self.state['adverts'][self.id]:
                self.save()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def validate_state(self):
        global _verified_archive_index
        s = self.state
        require(isinstance(s, dict) and set(s) == STATE_KEYS and s['format'] == VERSION
                and s['active_storage'] == ACTIVE_STORAGE
                and s['transit_scheduler'] == TRANSIT_SCHEDULER
                and s['archive_storage'] == ARCHIVE_STORAGE
                and s['receipt_scheduler'] == RECEIPT_SCHEDULER
                and s['network'] == self.network and s['node_id'] == self.id, 'corrupt state identity')
        integer(s['cursor'], 0, 2**63 - 1)
        recent=s['recent_transits']
        require(isinstance(recent,list) and len(recent)<=MAX_RECENT_TRANSITS
                and all(isinstance(ident,str) for ident in recent)
                and len(set(recent))==len(recent),'recent transit metadata capacity/schema invalid')
        for ident in recent:hex32(ident)
        for name in ('recent_transit_cursors','history_transit_cursors','transit_class_steps'):
            require(isinstance(s[name],dict) and len(s[name])<=MAX_CONTACTS,
                    'transit class cursor capacity/schema invalid')
            for peer,value in s[name].items():
                require(hex32(peer)!=self.id,'transit class cursor self peer invalid')
                if name=='transit_class_steps':integer(value,0,2**63-1)
                elif value is not None:hex32(value)
        first=s['first_carriage']
        require(isinstance(first,dict) and len(first)<=MAX_CONTACTS,
                'first carriage peer capacity/schema invalid')
        for peer,value in first.items():
            require(hex32(peer)!=self.id and isinstance(value,dict)
                    and set(value)==set(empty_first_carriage()),'first carriage fields/peer invalid')
            for name,limit in (('pending',MAX_RECENT_TRANSITS),('prepared',MAX_MESSAGES),('arrivals',MAX_MESSAGES),('observed',MAX_MESSAGES)):
                rows=value[name]
                if name=='observed' and rows is None:continue
                require(isinstance(rows,list) and len(rows)<=limit
                        and all(isinstance(i,str) for i in rows)
                        and len(set(rows))==len(rows),'first carriage metadata capacity/schema invalid')
                for ident in rows:hex32(ident)
            require(not set(value['pending'])&set(value['prepared'])
                    and not set(value['arrivals'])&(set(value['pending'])|set(value['prepared'])),
                    'first carriage waiting/prepared overlap')
            integer(value['next_kind'],0,1)
            if value['history_after'] is not None:hex32(value['history_after'])
        require(isinstance(s['receipt_cursors'], dict) and len(s['receipt_cursors']) <= MAX_CONTACTS,
                'receipt scheduler cursor capacity/schema invalid')
        for peer, cursor in s['receipt_cursors'].items():
            require(hex32(peer) != self.id, 'receipt scheduler self peer invalid')
            integer(cursor, 0, 2**63 - 1)
        require(isinstance(s['requested_receipt_cursors'], dict) and len(s['requested_receipt_cursors']) <= MAX_CONTACTS,
                'requested receipt cursor capacity/schema invalid')
        for peer, cursor in s['requested_receipt_cursors'].items():
            require(hex32(peer) != self.id, 'requested receipt scheduler self peer invalid')
            integer(cursor, 0, 2**63 - 1)
        require(isinstance(s['transit_cursors'], dict) and len(s['transit_cursors']) <= MAX_CONTACTS,
                'transit scheduler cursor capacity/schema invalid')
        for peer, cursor in s['transit_cursors'].items():
            require(hex32(peer) != self.id, 'transit scheduler self peer invalid')
            if cursor is not None:hex32(cursor)
        for name, bound in [('adverts', MAX_NODES), ('messages', MAX_MESSAGES), ('receipts', MAX_MESSAGES)]:
            require(isinstance(s[name], dict) and len(s[name]) <= bound, 'state capacity or schema invalid')
        arrivals=s['first_arrivals']
        require(isinstance(arrivals,list) and len(arrivals)<=MAX_MESSAGES
                and all(isinstance(i,str) for i in arrivals)
                and len(set(arrivals))==len(arrivals),'arrival order capacity/schema invalid')
        for ident in arrivals:hex32(ident)
        require(set(arrivals)==set(s['messages']),'arrival order differs from retained pool')
        for ident, advert in s['adverts'].items():
            require(advert_check(advert, self.network)['node_id'] == ident, 'corrupt advert key')
        for ident, receipt in s['receipts'].items():
            require(receipt_check(receipt, self.network) == ident, 'corrupt receipt key')
        for ident, transit in s['messages'].items():
            packet, _, visited = transit_check(transit, self.network, include_frame=False)
            # transit_check has authenticated the exact complete transit and
            # bound this source-signed route ID to its exact packet digest.
            # Reuse that same operation's binding, never unchecked metadata.
            require(transit['routing']['body']['packet_id'] == ident and visited[-1] == self.id,
                    'corrupt message ownership')
            if ident in s['receipts']:
                _match_receipt(s['receipts'][ident],packet,transit['routing']['body'])
        require(isinstance(s['archives'],dict) and len(s['archives'])<=MAX_ARCHIVE_FILES,
                'archive index capacity/schema invalid')
        files,_=self.archive_inventory()
        domain=(str(self.root), self.network, self.id, VERSION, ARCHIVE_STORAGE, ARCHIVE_FRAME, HEX.pattern,
                MAX_STATE, MAX_ARCHIVE_FILES, MAX_ARCHIVE_BYTES,
                MAX_VERIFIED_ARCHIVE_INDEX_BYTES,
                tuple(sorted(evidence.KINDS)), tuple(sorted(evidence.CONTROL_KINDS)))
        raw=evidence.canonical(s['archives'])
        rows=None
        exact_witness=None
        previous_entries=()
        retained_entries=()
        with _verified_archive_index_lock:
            witness=_verified_archive_index
            if witness is not None and witness[3]>MAX_VERIFIED_ARCHIVE_INDEX_BYTES:
                _verified_archive_index=None
                witness=None
            if witness is not None and witness[0]==domain:
                if witness[1]==raw:
                    rows=witness[2]
                    retained_entries=witness[4]
                    exact_witness=witness
                else:
                    previous_entries=witness[4]
        if rows is None:
            # Only the immediately preceding fully checked index in this exact
            # store/domain may supply immutable byte/primitive-row witnesses.
            # A changed row still authenticates completely; a digest is never
            # compared in place of its full canonical signed entry bytes.
            previous={ident:(encoded,row) for ident,encoded,row in previous_entries}
            checked=[]
            candidates=[]
            domain_size=len(evidence.canonical(domain))
            row_bytes=entry_bytes=2
            retain=True
            for ident,entry in s['archives'].items():
                encoded=evidence.canonical(entry).decode('utf-8')
                prior=previous.get(ident)
                if prior is not None and prior[0]==encoded:
                    row=prior[1]
                else:
                    body=self.archive_entry(entry,ident)
                    ref=body['frame_object']
                    row=(ident,body['file_id'],body['size_bytes'],body['kind'] is None,
                         ref['file_id'] if ref else None,ref['size_bytes'] if ref else None)
                checked.append(row)
                if retain:
                    candidate=(ident,encoded,row)
                    comma=int(len(checked)>1)
                    row_bytes+=len(evidence.canonical(row))+comma
                    entry_bytes+=len(evidence.canonical(candidate))+comma
                    if len(raw)+domain_size+row_bytes+entry_bytes<=MAX_VERIFIED_ARCHIVE_INDEX_BYTES:
                        candidates.append(candidate)
                    else:
                        candidates=[]
                        retain=False
            rows=tuple(checked)
            retained_entries=tuple(candidates)
        # Recheck every actual retained file and active/archive overlap even on
        # an exact metadata hit. A changed payload still authenticates on read.
        for ident,file_id,size,receipt_only,frame_id,frame_size in rows:
            require(file_id in files and files[file_id]==size,
                    'archive file missing or size differs; preserve custody')
            require(ident not in s['messages'] or receipt_only,'duplicate active/archived transit')
            require(frame_id is None or frame_id in files and files[frame_id]==frame_size,
                    'archive frame missing or size differs; preserve custody')
        require(isinstance(s['peer_inventory'],dict) and len(s['peer_inventory'])<=MAX_CONTACTS,
                'peer inventory cache capacity/schema invalid')
        for peer, inventory in s['peer_inventory'].items():
            require(inventory_check(inventory,self.network)['node_id']==peer,'peer inventory identity changed')
        if exact_witness is not None:
            retained_size=exact_witness[3]
        else:
            retained_size=len(raw)+len(evidence.canonical(rows))+len(evidence.canonical(domain))
            overlap_size=len(evidence.canonical(retained_entries))
            if retained_size+overlap_size>MAX_VERIFIED_ARCHIVE_INDEX_BYTES:
                # Preserve the original exact-index optimization when complete
                # per-entry retention cannot fit the same original bound.
                retained_entries=()
            else:
                retained_size+=overlap_size
        if retained_size<=MAX_VERIFIED_ARCHIVE_INDEX_BYTES:
            # Publish only after complete validation. Retain exact canonical
            # bytes and primitive tuples, never a mutable signed object.
            with _verified_archive_index_lock:
                _verified_archive_index=(domain,raw,rows,retained_size,retained_entries)
        else:
            with _verified_archive_index_lock:
                _verified_archive_index=None

    def save(self):
        atomic(self.path, self.state)

    def archive_inventory(self):
        files,total={},0
        for path in self.archive_root.iterdir():
            staging=re.fullmatch(r'\.archive-write-[0-9a-f]{64}',path.name)
            require((staging or re.fullmatch(r'[0-9a-f]{64}\.json',path.name))
                    and path.is_file() and not path.is_symlink(),
                    'unsafe archive file')
            size=path.stat().st_size
            require((0 if staging else 1)<=size<=MAX_STATE and len(files)<MAX_ARCHIVE_FILES,'archive file capacity reached')
            total+=size
            require(total<=MAX_ARCHIVE_BYTES,'archive byte capacity reached')
            files[path.stem]=size
        return files,total

    def archive_entry(self,entry,ident):
        body=verify(entry,'archive',self.network)
        require(set(body)=={'format','network','node_id','packet_id','file_id','size_bytes','source',
                           'destination','frame_id','export_id','kind','receipt','frame_object',
                           'expanded_sha256','expanded_size_bytes'} and body['node_id']==self.id
                and body['packet_id']==ident,'archive ownership/schema differs')
        for field in ('packet_id','file_id','source','destination','frame_id'):hex32(body[field])
        integer(body['size_bytes'],1,MAX_STATE)
        hex32(body['expanded_sha256']);integer(body['expanded_size_bytes'],1,MAX_STATE)
        ref=body['frame_object']
        if body['kind'] is None:
            require(ref is None,'receipt-only archive has a shared frame')
        else:
            require(isinstance(ref,dict) and set(ref)=={'file_id','size_bytes'},'archive frame reference schema differs')
            hex32(ref['file_id']);integer(ref['size_bytes'],1,MAX_STATE)
        require(body['kind'] is None or body['kind'] in evidence.KINDS | evidence.CONTROL_KINDS,'archive kind invalid')
        if body['kind'] is None:require(body['export_id'] is None,'receipt-only archive has a frame export')
        else:hex32(body['export_id'])
        require(receipt_check(body['receipt'],self.network)==ident,'archive receipt differs')
        route=body['receipt']['body']['routing']['body']
        require((body['source'],body['destination'],body['frame_id'])==
                (route['node_id'],route['destination'],route['frame_id']),'archive routing differs')
        return body

    def _archive_read(self,name):
        return evidence.read_file(self.archive_root/name,MAX_STATE)

    def archived(self,ident):
        body=self.archive_entry(self.state['archives'][ident],ident)
        raw=self._archive_read(body['file_id']+'.json')
        require(len(raw)==body['size_bytes'] and hashlib.sha256(raw).hexdigest()==body['file_id'],
                'archive bytes differ; preserve custody')
        stored=evidence.decode_json(raw)
        require(raw==evidence.canonical(stored) and isinstance(stored,dict)
                and set(stored)=={'format','network','node_id','packet_id','transit','receipt',
                                  'frame_object','expanded_sha256','expanded_size_bytes'}
                and (stored['format'],stored['network'],stored['node_id'],stored['packet_id'])==
                    (ARCHIVE_STORAGE,self.network,self.id,ident) and stored['receipt']==body['receipt']
                and all(stored[k]==body[k] for k in ('frame_object','expanded_sha256','expanded_size_bytes')),
                'archive contents differ')
        # Reconstruct only this bounded complete archive. Stored references and
        # hashes never replace authentication of its original packet and receipt.
        transit=stored['transit']
        ref=body['frame_object']
        if ref is not None:
            payload=self._archive_read(ref['file_id']+'.json')
            require(len(payload)==ref['size_bytes'] and hashlib.sha256(payload).hexdigest()==ref['file_id'],
                    'archive frame bytes differ; preserve custody')
            frame=evidence.decode_json(payload)
            require(payload==frame_digest.packet_body_bytes(frame) and isinstance(frame,dict)
                    and set(frame)=={'format','network','node_id','frame'}
                    and (frame['format'],frame['network'],frame['node_id'])==(ARCHIVE_FRAME,self.network,self.id)
                    and isinstance(frame['frame'],str),'archive frame domain/schema differs')
            require(isinstance(transit,dict) and set(transit)=={'packet','routing','hops'}
                    and isinstance(transit['packet'],dict) and isinstance(transit['packet'].get('body'),dict)
                    and 'frame' not in transit['packet']['body'],'archive frame substitution differs')
            preview={k:stored[k] for k in ('network','node_id','packet_id','transit','receipt')}
            preview['format']=VERSION
            # Exact canonical insertion length: JSON key/colon plus an extra
            # comma only if this object already has a field. Refuse expansion
            # before constructing a larger unchecked complete archive.
            # The complete frame object was compared to its exact canonical
            # bytes above. Reuse that byte length, including all JSON escapes,
            # by subtracting the same object's empty-string image. No frame
            # encoding or authentication result survives this operation.
            frame_size=len(payload)-len(evidence.canonical(dict(frame,frame='')))+2
            expanded_size=len(evidence.canonical(preview))+frame_size+8+bool(transit['packet']['body'])
            require(expanded_size==body['expanded_size_bytes'] and expanded_size<=MAX_STATE,
                    'expanded archive capacity/size differs; preserve custody')
            transit['packet']['body']['frame']=frame['frame']
        blob={k:stored[k] for k in ('network','node_id','packet_id','transit','receipt')}
        blob['format']=VERSION
        expanded_hash,expanded_size=frame_digest.archive_commitment(blob)
        require(expanded_size==body['expanded_size_bytes'] and expanded_size<=MAX_STATE
                and expanded_hash==body['expanded_sha256'],
                'expanded archive bytes differ; preserve custody')
        transit=blob['transit']
        if body['kind'] is None:
            require(transit is None,'receipt-only archive claims a payload')
        else:
            packet,frame,visited=transit_check(transit,self.network)
            header=evidence.decode_json(frame)  # exact frame authenticated above
            require(digest(transit['packet'])==ident and visited[-1]==self.id
                    and (packet['node_id'],packet['destination'])==(body['source'],body['destination'])
                    and (header['kind'],header['export_id'])==
                        (body['kind'],body['export_id']),'archive transit differs')
            _match_receipt(body['receipt'],packet,transit['routing']['body'])
        return blob

    def sync_archive(self,ident):
        body=self.archive_entry(self.state['archives'][ident],ident)
        paths=[]
        if body['frame_object'] is not None:
            paths.append(self.archive_root/(body['frame_object']['file_id']+'.json'))
        paths.append(self.archive_root/(body['file_id']+'.json'))
        batch=getattr(self,'_archive_sync_paths',None)
        if batch is None:
            for path in paths:sync_retained(path)
        else:
            require(len(set(batch) | set(paths)) <= 2 * (MAX_MESSAGES + MAX_PACKET_BATCH),
                    'retained custody sync capacity exceeded')
            batch.update(dict.fromkeys(paths))

    def transit(self,ident):
        if ident in self.state['messages']:return self.state['messages'][ident]
        value=self.archived(ident)['transit']
        require(value is not None,'receipt-only archive has no frame')
        return value

    def receipts(self):
        values={i:v['body']['receipt'] for i,v in self.state['archives'].items()}
        values.update(self.state['receipts'])
        return values

    def summaries(self):
        values={i:{'source':v['body']['source'],'destination':v['body']['destination'],
                   'frame_id':v['body']['frame_id'],'export_id':v['body']['export_id'],'kind':v['body']['kind']}
                for i,v in self.state['archives'].items() if v['body']['kind'] is not None}
        for ident,transit in self.state['messages'].items():
            packet,raw,_=transit_check(transit,self.network);frame=evidence.decode_json(raw)
            values[ident]={'source':packet['node_id'],'destination':packet['destination'],
                          'frame_id':frame['message_id'],'export_id':frame['export_id'],'kind':frame['kind']}
        return values

    def archive_completed(self):
        if max(len(self.state['messages']),len(self.state['receipts']))<ARCHIVE_HIGH_WATER:return 0
        files,total=self.archive_inventory();updated=copy.deepcopy(self.state);count=0
        for ident in sorted(self.state['receipts'])[:MAX_ARCHIVE_BATCH]:
            receipt=self.state['receipts'][ident];receipt_check(receipt,self.network)
            transit=self.state['messages'].get(ident);kind=export=None
            if transit is not None:
                packet,raw,visited=transit_check(transit,self.network)
                require(visited[-1]==self.id,'archive transit owner differs')
                _match_receipt(receipt,packet,transit['routing']['body']);frame=evidence.decode_json(raw);kind,export=frame['kind'],frame['export_id']
            route=receipt['body']['routing']['body']
            blob={'format':VERSION,'network':self.network,'node_id':self.id,'packet_id':ident,
                  'transit':transit,'receipt':receipt}
            complete=evidence.canonical(blob)
            require(len(complete)<=MAX_STATE and (ident in updated['archives'] or len(updated['archives'])<MAX_ARCHIVE_FILES),
                    'archive index/record capacity; retain active evidence')
            stored=copy.deepcopy(blob);stored['format']=ARCHIVE_STORAGE
            objects=[];ref=None
            if transit is not None:
                frame=stored['transit']['packet']['body'].pop('frame')
                payload=evidence.canonical({'format':ARCHIVE_FRAME,'network':self.network,'node_id':self.id,'frame':frame})
                ref={'file_id':hashlib.sha256(payload).hexdigest(),'size_bytes':len(payload)}
                objects.append((ref['file_id'],payload))
            stored.update(frame_object=ref,expanded_sha256=hashlib.sha256(complete).hexdigest(),expanded_size_bytes=len(complete))
            raw=evidence.canonical(stored);file_id=hashlib.sha256(raw).hexdigest();objects.append((file_id,raw))
            require(all(1<=len(data)<=MAX_STATE for _,data in objects),'archive object capacity; retain active evidence')
            missing=[(i,data) for i,data in objects if i not in files]
            # A staged object and its hard-linked final name coexist until
            # cleanup. Count the peak directory inventory, including residue
            # after a process dies in that window, under the same limits.
            staging_files=1 if missing else 0
            staging_bytes=max((len(data) for _,data in missing),default=0)
            require(len(files)+len(missing)+staging_files<=MAX_ARCHIVE_FILES
                    and total+sum(len(data) for _,data in missing)+staging_bytes<=MAX_ARCHIVE_BYTES,
                    'archive capacity reached; retain active evidence')
            for object_id,data in objects:
                path=self.archive_root/(object_id+'.json')
                if object_id in files:
                    require(evidence.read_file(path,MAX_STATE)==data,'existing archive differs')
                    sync_retained(path)
                else:
                    # Payload then wrapper, both durable before index/active
                    # publication. Failed publication leaves all objects kept.
                    archive_write(path,data);files[object_id]=len(data);total+=len(data)
            entry=sign(self.key,'archive',{'format':VERSION,'network':self.network,'node_id':self.id,
                'packet_id':ident,'file_id':file_id,'size_bytes':len(raw),'source':route['node_id'],
                'destination':route['destination'],'frame_id':route['frame_id'],'export_id':export,'kind':kind,'receipt':receipt,
                'frame_object':ref,'expanded_sha256':stored['expanded_sha256'],'expanded_size_bytes':len(complete)})
            updated['archives'][ident]=entry;updated['messages'].pop(ident,None);updated['receipts'].pop(ident,None);count+=1
        if count:
            self.refresh_recent(updated)
            atomic(self.path,updated);self.state=updated
        return count

    def route(self, destination, excluded=(), first_hop=None):
        if destination == self.id:
            return [self.id]
        frontier, seen = [[self.id]], set(excluded) | {self.id}
        while frontier:
            path = frontier.pop(0)
            advert = self.state['adverts'].get(path[-1])
            if not advert:
                continue
            for peer in advert['body']['neighbors']:
                if peer in seen or (len(path) == 1 and
                        (peer not in self.contacts or not outgoing_contact(self.contacts[peer])
                         or (first_hop is not None and peer != first_hop))):
                    continue
                if peer == destination:
                    return path + [peer]
                seen.add(peer)
                frontier.append(path + [peer])
        return None

    def enqueue(self, frame, destination, hop_limit=MAX_HOPS):
        hex32(destination)
        evidence.inspect_frame(frame)
        integer(hop_limit, 1, MAX_HOPS)
        require(len(self.state['messages']) < MAX_MESSAGES, 'message capacity reached; retain existing evidence')
        packet = sign(self.key, 'packet', {'format': VERSION, 'network': self.network, 'node_id': self.id,
                      'destination': destination, 'nonce': os.urandom(32).hex(), 'hop_limit': hop_limit,
                      'frame': base64.b64encode(frame).decode()})
        ident = digest(packet)
        header, _ = evidence.inspect_frame(frame)
        routing = sign(self.key,'receipt-route',{'format':VERSION,'network':self.network,'node_id':self.id,
            'packet_id':ident,'destination':destination,'frame_id':header['message_id']})
        self.state['messages'][ident] = {'packet': packet, 'routing': routing, 'hops': []}
        self.deliver_local(self.state)
        self.refresh_recent(self.state,[ident])
        self.save()
        return ident

    def enqueue_batch(self, items, hop_limit=MAX_HOPS):
        """Publish at most one ordinary four-item carriage selection durably.

        No acknowledgment or in-memory adoption precedes atomic publication.
        A publication error requires closing/reopening this Node: the retained
        disk image may already include the complete batch after response loss.
        """
        require(isinstance(items, (list, tuple)) and 1 <= len(items) <= MAX_PACKET_BATCH,
                'enqueue batch item capacity/schema invalid')
        integer(hop_limit, 1, MAX_HOPS)
        require(len(self.state['messages']) + len(items) <= MAX_MESSAGES,
                'message capacity reached; retain existing evidence')
        checked=[]
        for item in items:
            require(isinstance(item, (list, tuple)) and len(item)==2,
                    'enqueue batch item schema invalid')
            frame,destination=item
            hex32(destination)
            header,_=evidence.inspect_frame(frame)
            checked.append((frame,destination,header['message_id']))
        updated=copy.deepcopy(self.state);identifiers=[]
        for frame,destination,frame_id in checked:
            packet=sign(self.key,'packet',{'format':VERSION,'network':self.network,'node_id':self.id,
                'destination':destination,'nonce':os.urandom(32).hex(),'hop_limit':hop_limit,
                'frame':base64.b64encode(frame).decode()})
            ident=digest(packet)
            require(ident not in updated['messages'] and ident not in updated['archives'],
                    'enqueue batch packet collision; retain existing evidence')
            routing=sign(self.key,'receipt-route',{'format':VERSION,'network':self.network,'node_id':self.id,
                'packet_id':ident,'destination':destination,'frame_id':frame_id})
            updated['messages'][ident]={'packet':packet,'routing':routing,'hops':[]}
            identifiers.append(ident)
        self.deliver_local(updated)
        self.refresh_recent(updated,identifiers)
        atomic(self.path,updated)
        self.state=updated
        return identifiers

    def deliver_local(self, state):
        for ident, transit in state['messages'].items():
            if ident in state['receipts']:
                receipt_matches(state['receipts'][ident], transit)
            if transit['packet']['body']['destination'] == self.id and ident not in state['receipts']:
                require(len(state['receipts']) < MAX_MESSAGES, 'receipt capacity reached')
                _, raw = packet_check(transit['packet'], self.network)
                frame, _ = evidence.inspect_frame(raw)
                state['receipts'][ident] = sign(self.key, 'receipt', {'format': VERSION, 'network': self.network,
                    'node_id': self.id, 'packet_id': ident, 'frame_id': frame['message_id'],
                    'routing': transit['routing'],
                    'outcome': 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'})

    def refresh_recent(self, state, added=()):
        added=tuple(added)
        # Scheduling labels only. Eviction/receipt removes no packet or proof.
        values=[ident for ident in state['recent_transits']
                if ident in state['messages'] and ident not in state['receipts']]
        for ident in added:
            require(ident in state['messages'],'recent transit absent from retained pool')
            if ident not in state['receipts'] and ident not in values:values.append(ident)
        state['recent_transits']=values[-MAX_RECENT_TRANSITS:] if MAX_RECENT_TRANSITS else []
        # Full retained arrival order survives canonical sorting/recent eviction.
        # Only packet IDs are stored; complete original packets remain active.
        arrivals=[i for i in state['first_arrivals'] if i in state['messages']]
        for ident in added:
            if ident not in arrivals:arrivals.append(ident)
        require(len(arrivals)<=MAX_MESSAGES,'arrival ID capacity')
        state['first_arrivals']=arrivals

    def carriage_position_domain(self):
        return (str(self.root),self.network,self.id,VERSION,TRANSIT_SCHEDULER,
                MAX_MESSAGES,MAX_NODES,MAX_CONTACTS,MAX_HOPS,MAX_BATCH,
                MAX_PACKET_BATCH,MAX_RECENT_TRANSITS,MAX_RECEIPT_BATCH,
                evidence.FORMAT,evidence.DOMAIN,evidence.MAX_FRAME,evidence.MAX_PAYLOAD,
                MAX_CARRIAGE_POSITIONS,MAX_CARRIAGE_POSITION_BYTES,
                tuple((p,tuple(sorted(c.items()))) for p,c in sorted(self.contacts.items())))

    def set_carriage_priority(self, scope, frame_ids, *, ordered_frames=False):
        """Process-local spare-slot hint, never receipt or Native authority."""
        hex32(scope)
        require(type(frame_ids) is tuple and len(frame_ids)<=MAX_CARRIAGE_POSITIONS
                and len(set(frame_ids))==len(frame_ids), 'invalid carriage priority IDs')
        for ident in frame_ids:hex32(ident)
        require(type(ordered_frames) is bool, 'invalid carriage frame order mode')
        key=(self.carriage_position_domain(),'native-commit-spare')
        remember_carriage_position(key,(scope,frame_ids,True)
                                   if ordered_frames and frame_ids else (scope,frame_ids))
        return key

    def first_carriage_plan(self,peer):
        """Bounded first admission with durable arrival waiting, never authority."""
        value=self.state['first_carriage'][peer];active=self.state['messages'];receipted=self.state['receipts'];prepared=[i for i in value['prepared'] if i in active]
        def eligible(ident):
            if ident not in active or ident in receipted:return False
            transit=active[ident];packet,_,visited=transit_check(transit,self.network,include_frame=False);route=self.route(packet['destination'],visited[:-1],first_hop=peer)
            return bool(route and len(route)>=2 and route[1]==peer and len(transit['hops'])+len(route)-1<=packet['hop_limit'])
        pending=[i for i in value['pending'] if eligible(i)];known=set(prepared)|set(pending);initial=value['observed'] is None
        # At this peer's first preparation, existing recent traffic takes its
        # previous32 admission places; older history remains ordinary/background.
        # Afterwards new complete IDs retain original arrival order independent of
        # recent label and sorted canonical mapping keys. Never replace pending IDs.
        if initial:
            for ident in self.state['recent_transits']:
                if len(pending)==MAX_RECENT_TRANSITS:break
                if ident not in known and eligible(ident):pending.append(ident);known.add(ident)
            arrivals=[]
        else:
            arrivals=[i for i in value['arrivals'] if i not in known and eligible(i)];seen=set(value['observed']);already=set(arrivals)
            for ident in self.state['first_arrivals']:
                if ident not in seen and ident not in known and ident not in already and eligible(ident):arrivals.append(ident);already.add(ident)
        require(len(arrivals)<=MAX_MESSAGES,'first arrival backlog capacity')
        priority=iter(arrivals);reserved=set(arrivals);history=sorted(i for i in active if i not in known and i not in reserved and i not in receipted);after=value['history_after'];start=0 if after is None or not history else bisect_right(history,after)%len(history);background=iter(history[start:]+history[:start]);next_kind=value['next_kind']
        def take(kind):
            for ident in priority if kind==0 else background:
                if ident not in known and eligible(ident):return ident
            return None
        while len(pending)<MAX_RECENT_TRANSITS:
            kind=next_kind;ident=take(kind)
            if ident is None:kind=1-kind;ident=take(kind)
            if ident is None:break
            pending.append(ident);known.add(ident)
            if kind==1:after=ident
            next_kind=1-kind
        # Plan construction is pure. The existing complete atomic preparation
        # publishes this provisional ID metadata only on success; full4retry skips.
        return dict(pending=pending,prepared=prepared,arrivals=[i for i in arrivals if i not in known],observed=sorted(active),history_after=after,next_kind=next_kind)

    def transit_groups(self, peer):
        pending=sorted(self.state['messages'])
        recent=set(self.state['recent_transits']);groups=[]
        domain=self.carriage_position_domain()
        for name,selected in (('recent_transit_cursors',True),('history_transit_cursors',False)):
            buckets={}
            for ident in pending:
                if (ident in recent)!=selected:continue
                # Node open authenticated every complete transit and its exact
                # signed frame binding. These rows choose carriage only; each
                # eligible selected transit still takes ordinary validation.
                transit=self.state['messages'][ident]
                route=transit['routing']['body']
                bucket=(transit['packet']['body']['destination'],route['frame_id'])
                buckets.setdefault(bucket,[]).append(ident)
            keys=sorted(buckets);last=carriage_position((domain,peer,name,'ring'))
            missing=[bucket for bucket in keys
                     if carriage_position((domain,peer,name,bucket)) is None]
            for bucket in missing:
                remember_carriage_position((domain,peer,name,bucket),
                                            self.state[name][peer] or '')
            if last is None:
                # A cold/missing/evicted scheduling hint must retain the
                # original durable whole-class rotation for this preparation.
                # Initialize only primitive positions from its checked cursor;
                # no unchecked packet/header or authority is retained.
                items=[ident for ident in pending if (ident in recent)==selected]
                after=self.state[name][peer]
                offset=0 if after is None or not items else bisect_right(items,after)%len(items)
                groups.append(items[offset:]+items[:offset])
                continue
            start=0 if not keys else bisect_right(keys,last)%len(keys)
            keys=keys[start:]+keys[:start];rows=[]
            for bucket in keys:
                items=buckets[bucket]
                after=carriage_position((domain,peer,name,bucket))
                offset=0 if after=='' else bisect_right(items,after)%len(items)
                rows.append(items[offset:]+items[:offset])
            groups.append([items[index] for index in range(max(map(len,rows),default=0))
                           for items in rows if index<len(items)])
        if self.state['transit_class_steps'][peer]%2:groups.reverse()
        return groups

    def remember_carriage(self, peer, bundle):
        domain=self.carriage_position_domain();recent=set(self.state['recent_transits'])
        for transit in bundle['body']['transits']:
            ident=transit['routing']['body']['packet_id']
            name='recent_transit_cursors' if ident in recent else 'history_transit_cursors'
            bucket=(transit['packet']['body']['destination'],transit['routing']['body']['frame_id'])
            remember_carriage_position((domain,peer,name,bucket),ident)
            remember_carriage_position((domain,peer,name,'ring'),bucket)

    def transit_order(self, peer):
        groups=self.transit_groups(peer)
        return [items[index] for index in range(max(map(len,groups),default=0))
                for items in groups if index<len(items)]

    def failed_carriage(self, peer):
        return carriage_position((self.carriage_position_domain(),peer,'failed-carriage')) or ()

    def forget_failed_carriage(self, peer):
        forget_carriage_position((self.carriage_position_domain(),peer,'failed-carriage'))

    def receive(self, bundle, peer):
        require(getattr(self,'_archive_sync_paths',None) is None,
                'nested custody receive refused')
        self._archive_sync_paths={}
        try:
            return self._receive(bundle,peer)
        finally:
            self._archive_sync_paths=None

    def _receive(self, bundle, peer):
        body = verify(bundle, 'exchange', self.network)
        require(set(body) == {'format', 'network', 'node_id', 'to', 'adverts', 'transits', 'receipts', 'inventory'}
                and body['node_id'] == peer and body['to'] == self.id, 'wrong contact peer')
        require(peer in self.contacts and incoming_contact(self.contacts[peer]),
                'unconfigured incoming inventory peer')
        require(inventory_check(body['inventory'],self.network)['node_id']==peer,'exchange inventory differs from sender')
        for name, bound in [('adverts', MAX_NODES), ('transits', MAX_PACKET_BATCH), ('receipts', MAX_MESSAGES)]:
            require(isinstance(body[name], list) and len(body[name]) <= bound, 'exchange item limit')
        updated = copy.deepcopy(self.state)
        added=[]
        updated['peer_inventory'][peer] = body['inventory']
        for advert in body['adverts']:
            a = advert_check(advert, self.network)
            old = updated['adverts'].get(a['node_id'])
            if old and a['sequence'] == old['body']['sequence']:
                require(advert == old, 'conflicting signed advertisement; preserve incoming file')
            elif not old or a['sequence'] > old['body']['sequence']:
                require(a['node_id'] != self.id, 'remote cannot revise local advertisement')
                require(old is not None or len(updated['adverts']) < MAX_NODES, 'discovery capacity reached')
                updated['adverts'][a['node_id']] = advert
        for transit in body['transits']:
            packet, _, _ = transit_check(transit, self.network, self.id, peer)
            ident = digest(transit['packet'])
            archived=updated['archives'].get(ident)
            if archived is not None:
                stored=self.archived(ident)
                receipt_matches(stored['receipt'],transit)
                self.sync_archive(ident)
                if stored['transit'] is not None:
                    require(stored['transit']['packet']==transit['packet'],'archived packet ID collision')
                    continue
                updated['receipts'][ident]=stored['receipt']
            old = updated['messages'].get(ident)
            if old:
                require(old['packet'] == transit['packet'], 'packet ID collision')
                # A shorter valid custody path can enable a later alternate route.
                if len(transit['hops']) < len(old['hops']):
                    updated['messages'][ident] = transit
            else:
                require(len(updated['messages']) < MAX_MESSAGES, 'message capacity reached; retain incoming file')
                updated['messages'][ident] = transit
                # A receipt-only archive can precede this first complete active
                # transit. It still needs arrival metadata; the retained receipt
                # keeps it out of recent/unreceipted service and grants no value.
                added.append(ident)
        for receipt in body['receipts']:
            ident = receipt_check(receipt, self.network)
            archived=updated['archives'].get(ident)
            if archived is not None:
                require(receipt['body']['routing']['body']==archived['body']['receipt']['body']['routing']['body'],
                        'archived receipt routing differs')
                self.archived(ident);self.sync_archive(ident)
                if ident not in updated['messages']:continue
            if ident in updated['messages']:
                receipt_matches(receipt, updated['messages'][ident])
            require(ident in updated['receipts'] or len(updated['receipts']) < MAX_MESSAGES, 'receipt capacity reached')
            updated['receipts'][ident] = receipt
        self.deliver_local(updated)
        self.refresh_recent(updated,added)
        # Reaffirm every completely checked retained archive dependency before
        # publishing the updated state or releasing any custody reply. Repeated
        # paths in this one exchange need one real file/directory fsync each.
        sync_retained_many(self._archive_sync_paths)
        # The entire exchange is checked and durably committed before inbox removal.
        if updated!=self.state:
            atomic(self.path, updated)
        else:
            # Even an exact repeated exchange must reaffirm durable custody
            # before its socket acknowledgment or inbox consumption. A sync
            # failure refuses custody; it never deletes or refunds evidence.
            sync_retained(self.path)
        self.state = updated

    def _exchange_plan(self, peer, accepted_transits=None, retry_packet_ids=(), *, current_carriage=None):
        require(peer in self.contacts and outgoing_contact(self.contacts[peer]),
                'unconfigured outgoing exchange peer')
        require(isinstance(retry_packet_ids,tuple) and len(retry_packet_ids)<=MAX_PACKET_BATCH
                and all(isinstance(i,str) and re.fullmatch(r'[0-9a-f]{64}',i) for i in retry_packet_ids)
                and len(set(retry_packet_ids))==len(retry_packet_ids),'invalid failed carriage IDs')
        require(current_carriage is None or type(current_carriage) is dict and not current_carriage,
                'current carriage operation tracker must start empty')
        transits = []
        requested=set(self.state['peer_inventory'].get(peer,{}).get('body',{}).get('packet_ids',[]))
        receipts=[]
        all_receipts=self.receipts()
        for ident in sorted(all_receipts):
            receipt=all_receipts[ident]
            source=receipt['body']['routing']['body']['node_id']
            route=self.route(source,first_hop=peer) if source!=self.id else None
            if ident in requested or route and 1<len(route)<=MAX_HOPS+1:
                receipts.append(receipt)
        if receipts:
            # A peer-signed inventory is bounded scheduling demand only. Reserve
            # half the unchanged batch for exact requested IDs and half for
            # historical reverse routes; neither class can starve the other.
            wanted=[r for r in receipts if r['body']['packet_id'] in requested]
            history=[r for r in receipts if r['body']['packet_id'] not in requested]
            def rotated(items, cursor):
                if not items:return []
                start=cursor%len(items)
                return items[start:]+items[:start]
            wanted=rotated(wanted,self.state['requested_receipt_cursors'][peer])
            history=rotated(history,self.state['receipt_cursors'][peer])
            count=min(len(wanted),max(MAX_RECEIPT_BATCH//2,MAX_RECEIPT_BATCH-len(history)))
            wanted=wanted[:count]
            history=history[:MAX_RECEIPT_BATCH-count]
            # Alternate the first class by durable *actual* advancement. Even
            # a tightened wire bound carrying only one receipt rotates classes.
            first_wanted=(self.state['requested_receipt_cursors'][peer]+self.state['receipt_cursors'][peer])%2==0
            receipts=[]
            for index in range(max(len(wanted),len(history))):
                for group in ((wanted,history) if first_wanted else (history,wanted)):
                    if index<len(group):receipts.append(group[index])
        body = {'format': VERSION, 'network': self.network, 'node_id': self.id,
                'to': peer, 'adverts': [self.state['adverts'][i] for i in sorted(self.state['adverts'])],
                'transits': transits, 'receipts': receipts,
                'inventory':sign(self.key,'inventory',{'format':VERSION,'network':self.network,
                    'node_id':self.id,'packet_ids':sorted(self.state['messages'])})}
        # Keep the wire ceiling under tightened validation limits, advancing
        # preparation only by the actual complete receipts carried.
        while receipts and len(evidence.canonical(body)) + 512 > MAX_BATCH:
            receipts.pop()
        def eligible(items):
            # Skip within this class before allocating its slot. Interleaving
            # raw IDs could let repeated/unroutable rows starve later eligible
            # history forever. Every examined transit still authenticates.
            for ident in items:
                if ident not in self.state['messages']:continue
                if ident in self.state['receipts']:continue
                transit=self.state['messages'][ident]
                packet,_,visited=transit_check(transit,self.network,include_frame=False)
                route=self.route(packet['destination'],visited[:-1],first_hop=peer)
                if not route or len(route)<2 or route[1]!=peer or len(transit['hops'])+len(route)-1>packet['hop_limit']:continue
                hop=sign(self.key,'hop',{'format':VERSION,'network':self.network,'node_id':self.id,
                    'packet_id':ident,'previous':digest(transit['hops'][-1]) if transit['hops'] else ident,'to':peer})
                candidate={'packet':transit['packet'],'routing':transit['routing'],'hops':transit['hops']+[hop]}
                if accepted_transits is not None and digest(candidate) in accepted_transits:continue
                yield candidate
        # Retry IDs grant scheduling priority only. Rebuild and authenticate
        # every original packet/hop; never reuse an exchange or socket nonce.
        for candidate in eligible(retry_packet_ids):
            if len(evidence.canonical({**body,'transits':transits+[candidate]}))+512>MAX_BATCH:
                break
            transits.append(candidate)
        # At most half the original batch offers first service. The remainder
        # keeps ordinary traffic eligible, including historical retransmission.
        first_ids=();first_plan=None
        if len(transits)<MAX_PACKET_BATCH:
            first_plan=self.first_carriage_plan(peer)
            waiting=set(first_plan['pending'])|set(first_plan['arrivals'])
            def direct_waiting_copies(items):
                # Reorder only existing places of one exact complete frame.
                # A connected recipient's still-unprepared copy precedes its
                # detours, without moving another frame or crossing classes.
                # Once prepared it loses this preference: unresolved detours
                # retain service, including after cold restart or failed send.
                result=list(items);positions={}
                for index,ident in enumerate(result):
                    transit=self.state['messages'][ident]
                    positions.setdefault(transit['routing']['body']['frame_id'],[]).append(index)
                for indices in positions.values():
                    copies=[result[index] for index in indices]
                    copies.sort(key=lambda ident:not (ident in waiting and ident not in self.state['receipts']
                        and self.state['messages'][ident]['packet']['body']['destination']==peer))
                    for index,ident in zip(indices,copies):result[index]=ident
                return result
            first_ids=tuple(first_plan['pending'])
            offered=0
            for candidate in eligible(i for i in first_ids if i not in retry_packet_ids):
                if offered>=MAX_PACKET_BATCH//2 or len(transits)==MAX_PACKET_BATCH:break
                if len(evidence.canonical({**body,'transits':transits+[candidate]}))+512>MAX_BATCH:continue
                transits.append(candidate);offered+=1
        # A full replay must not initialize/touch ordinary LRU positions: those
        # optional bounded hints can otherwise change the next ordinary turn.
        priority_pair=(first_plan is not None and (self.state['transit_class_steps'][peer]//2)%2==0)
        # Read the primitive hint before group initialization may evict it.
        # A full retry or an already missing hint retains ordinary fallback.
        available_hint=None
        if first_plan is not None:
            hint_key=(self.carriage_position_domain(),'native-commit-spare')
            # Inspect opt-in mode without changing legacy nonpriority LRU
            # order. A full retry never reads or advances any spare position.
            with _carriage_position_lock:
                retained_hint=_carriage_positions.get(hint_key)
                mode=retained_hint[0] if retained_hint is not None else None
            if priority_pair or mode is not None and len(mode)==3 and mode[2] is True:
                available_hint=carriage_position(hint_key)
        ordered_turn_key=None
        if available_hint is not None and len(available_hint)==3 and available_hint[2] is True:
            ordered_turn_key=(self.carriage_position_domain(),peer,'native-ordered-spare-turn')
            # Alternate completed preparations, independently of whether two
            # or four ordinary packets advanced the original class counter.
            priority_pair=carriage_position(ordered_turn_key) is not True
            if current_carriage is not None:
                current_carriage.update(ordered_turn_key=ordered_turn_key,
                                        ordered_priority_pair=priority_pair)
        hint=available_hint if priority_pair else None
        # Keep same-frame recipient rotation separate from the ordinary ring.
        # Capture only primitive positions before group initialization can evict
        # them. They select carriage; each original packet still authenticates.
        current_classes={};current_positions={};frame_positions={};current_origin=None
        if hint is not None:
            frames=set(hint[1]);recent=set(self.state['recent_transits'])
            current_classes={ident:(ident in recent,t['routing']['body']['frame_id'])
                             for ident,t in self.state['messages'].items()
                             if t['routing']['body']['frame_id'] in frames}
            domain=self.carriage_position_domain()
            if (self.state['transit_class_steps'][peer]//4)%2==0:
                current_origin=carriage_position((domain,peer,'native-current-origin',hint[0]))
            for kind,frame in sorted(set(current_classes.values())):
                current_positions[(kind,frame)]=carriage_position(
                    (domain,peer,'native-current-copy',hint[0],kind,frame))
                # Moving an exact frame copy between recent/history must not
                # reset its recipient turn. Only the newest priority pair may
                # borrow the identical peer/scope/frame's other-class position.
                # Missing positions in both classes preserve cold ordering.
                if (current_positions[(kind,frame)] is None
                        and (self.state['transit_class_steps'][peer]//4)%2==0):
                    current_positions[(kind,frame)]=carriage_position(
                        (domain,peer,'native-current-copy',hint[0],not kind,frame))
            for kind in sorted({kind for kind,_ in current_classes.values()}):
                frame_positions[kind]=carriage_position(
                    (domain,peer,'native-current-frame',hint[0],hint[1],kind))
            if current_carriage is not None:
                current_carriage.update(scope=hint[0],frame_set=hint[1],classes=current_classes,
                    newest=(self.state['transit_class_steps'][peer]//4)%2==0)
        pending=self.transit_groups(peer) if len(transits)<MAX_PACKET_BATCH else []
        selected_ids={digest(t['packet']) for t in transits}
        # Alternate priority pairs between newest and oldest unprepared arrival
        # order, including IDs admitted into pending. Retain the two offers and
        # one stream per recent/history class. The other pairs keep the original
        # retransmission order. Full four-packet replay still bypasses both.
        if priority_pair:
            arrivals=[i for i in self.state['first_arrivals']
                      if i in first_plan['pending'] or i in first_plan['arrivals']]
            if (self.state['transit_class_steps'][peer]//4)%2==0:arrivals.reverse()
            frames=set(hint[1]) if hint is not None else set()
            # Exact full-frame IDs came from the companion's Native-checked
            # retained envelopes, not a body identity. Every selected original
            # transit still authenticates below. Missing/evicted hints retain V13.
            # Prepared is only local selection, not a destination receipt. A
            # current signed frame whose send/replay failed remains spare-eligible;
            # ordinary transit checks still skip receipts and accepted hops.
            commits=[i for items in pending for i in items if i in current_classes]
            copies={}
            for index,ident in enumerate(commits):
                copies.setdefault(current_classes[ident],[]).append(index)
            for group,positions in copies.items():
                after=current_positions[group]
                if after is None:continue
                ordered=sorted(commits[index] for index in positions)
                start=bisect_right(ordered,after)%len(ordered)
                # Replace only this same-frame/class group's existing places.
                # Other frame positions and original two classes stay exact.
                for index,ident in zip(positions,ordered[start:]+ordered[:start]):
                    commits[index]=ident
            # Within a stable exact current-frame set, ordinary ring movement
            # must not repeatedly displace a different current envelope. Rotate
            # only current places in the same original class; changed/missing
            # hints retain the original order and all packets authenticate below.
            for kind,after in frame_positions.items():
                ordered_hint=(len(hint)==3 and hint[2] is True)
                if after is None and not ordered_hint:continue
                positions=[j for j,i in enumerate(commits) if current_classes[i][0]==kind]
                by_frame={}
                for j in positions:
                    by_frame.setdefault(current_classes[commits[j]][1],[]).append(commits[j])
                ordered=([frame for frame in hint[1] if frame in by_frame]
                         if ordered_hint else sorted(by_frame))
                if not ordered:continue
                start=((ordered.index(after)+1)%len(ordered) if after in ordered else 0
                       ) if ordered_hint else bisect_right(ordered,after)%len(ordered)
                rotated=[i for frame in ordered[start:]+ordered[:start] for i in by_frame[frame]]
                for j,i in zip(positions,rotated):commits[j]=i
            # Start a cold newest pair with forwarded current carriage. After
            # actually preparing one origin, offer the other on the next newest
            # pair in this exact context. Retained failed sends stay eligible;
            # neither origin monopolizes these existing spare slots. Preserve
            # within-origin order and the oldest failed-send selection.
            if (self.state['transit_class_steps'][peer]//4)%2==0:
                forwarded=[i for i in commits
                           if self.state['messages'][i]['packet']['body']['node_id']!=self.id]
                local=[i for i in commits
                       if self.state['messages'][i]['packet']['body']['node_id']==self.id]
                # Within each origin, first offer a current frame not yet
                # prepared for this peer. Otherwise failed prepared copies can
                # displace a waiting current Prepare on every newest pair.
                # Oldest pairs retain their failed-send order; preparation is
                # still neither remote custody nor a destination receipt.
                waiting=set(first_plan['pending'])|set(first_plan['arrivals'])
                forwarded.sort(key=lambda ident:ident not in waiting)
                local.sort(key=lambda ident:ident not in waiting)
                commits=local+forwarded if current_origin is False else forwarded+local
            arrivals=list(dict.fromkeys(commits+arrivals))
            pending=[list(dict.fromkeys([i for i in arrivals if i in set(items)]+items))
                     for items in pending]
        # Preserve the original recent/history and distinct-frame interleaving.
        # Only an unprepared direct copy may exchange places with a detour of
        # the identical complete frame. Eligibility still authenticates packet,
        # routing, visited hops and suppression before allocating any slot.
        pending=[direct_waiting_copies(items) for items in pending]
        streams=[iter(eligible([i for i in items if i not in retry_packet_ids and i not in selected_ids])) for items in pending]
        def finish_plan():
            bundle=sign(self.key,'exchange',body)
            if current_carriage is not None:
                self._trace_prepare_selection(peer,bundle,first_plan,retry_packet_ids,
                    available_hint,priority_pair,current_positions,frame_positions,current_origin)
            return bundle,first_plan
        while streams and len(transits)<MAX_PACKET_BATCH:
            remaining=[]
            for stream in streams:
                candidate=next(stream,None)
                if candidate is None:continue
                # Keep the original signed-wire ceiling and whole-packet
                # refusal. Class preparation rotates on the following call.
                if len(evidence.canonical({**body,'transits':transits+[candidate]}))+512>MAX_BATCH:
                    return finish_plan()
                transits.append(candidate);remaining.append(stream)
                if len(transits)==MAX_PACKET_BATCH:break
            streams=remaining
        return finish_plan()

    def exchange(self, peer, accepted_transits=None, retry_packet_ids=()):
        bundle, _ = self._exchange_plan(peer, accepted_transits, retry_packet_ids)
        return bundle

    def prepare_exchange(self, peer, accepted_transits=None, advance_active=False, retry_packet_ids=()):
        """Durably rotate this peer's active start and selected receipts before I/O.

        Preparation grants no custody. Failed/lost sends retain every receipt
        and revisit it after bounded rotation; cold open retains these cursors.
        """
        self._trace_prepare_event('prepare_start',peer)
        current_carriage={}
        bundle, first_plan = self._exchange_plan(peer, accepted_transits, retry_packet_ids,
                                                 current_carriage=current_carriage)
        require(len(evidence.canonical(bundle)) <= MAX_BATCH, 'exchange bytes exceed bound')
        # The diagnostic global cursor preserves its historical cadence.
        # Active selection depends only on this prepared peer, including failed
        # sends; another peer or the final ordinary tick cannot stride over it.
        updated = dict(self.state, cursor=(self.state['cursor'] + 1) % (2**63) if advance_active else self.state['cursor'],
                       receipt_cursors=dict(self.state['receipt_cursors']),
                       requested_receipt_cursors=dict(self.state['requested_receipt_cursors']),
                       transit_cursors=dict(self.state['transit_cursors']))
        for name in ('recent_transit_cursors','history_transit_cursors','transit_class_steps'):
            updated[name]=dict(self.state[name])
        requested=set(self.state['peer_inventory'].get(peer,{}).get('body',{}).get('packet_ids',[]))
        wanted=sum(r['body']['packet_id'] in requested for r in bundle['body']['receipts'])
        updated['requested_receipt_cursors'][peer]=(updated['requested_receipt_cursors'][peer]+wanted)%(2**63)
        updated['receipt_cursors'][peer] = (updated['receipt_cursors'][peer]
                                          + len(bundle['body']['receipts'])-wanted) % (2**63)
        pending = sorted(self.state['messages'])
        carried_rows=[t for t in bundle['body']['transits'] if digest(t['packet']) not in retry_packet_ids]
        require(not carried_rows or first_plan is not None, 'prepared first plan missing')
        offered=[]
        for transit in carried_rows:
            ident=digest(transit['packet'])
            if len(offered)==MAX_PACKET_BATCH//2 or ident not in first_plan['pending']:break
            offered.append(ident)
        ordinary=[t for t in carried_rows if digest(t['packet']) not in offered]
        if ordinary:
            last = digest(ordinary[-1]['packet'])
            require(last in self.state['messages'], 'prepared transit absent from retained pool')
            # Continue after the last actually carried original packet, including
            # route/suppression skips. Failed sends revisit it on the next full
            # cycle without repeating three of four slots on every preparation.
            # Preserve the actual packet identity when completed custody removes
            # earlier rows or new packets shift their ranks. Never prune evidence.
            updated['transit_cursors'][peer] = last
            recent=set(self.state['recent_transits'])
            for transit in ordinary:
                ident=digest(transit['packet'])
                name='recent_transit_cursors' if ident in recent else 'history_transit_cursors'
                updated[name][peer]=ident
            updated['transit_class_steps'][peer]=(updated['transit_class_steps'][peer]+len(ordinary))%(2**63)
        elif pending and not bundle['body']['transits']:
            # A zero-carriage byte/route/suppression attempt examines one start;
            # durably rotate past it without granting custody or dropping bytes.
            ident=self.transit_order(peer)[0]
            updated['transit_cursors'][peer] = ident
            name='recent_transit_cursors' if ident in self.state['recent_transits'] else 'history_transit_cursors'
            updated[name][peer]=ident
            updated['transit_class_steps'][peer]=(updated['transit_class_steps'][peer]+1)%(2**63)
        # Persist the offer only after this complete bounded preparation.
        # A full retry leaves ordinary first-service metadata untouched.
        if len(bundle['body']['transits'])<MAX_PACKET_BATCH or carried_rows:
            first=first_plan if first_plan is not None else self.first_carriage_plan(peer)
            carried={digest(t['packet']) for t in carried_rows}
            first['pending']=[i for i in first['pending'] if i not in carried]
            first['arrivals']=[i for i in first['arrivals'] if i not in carried]
            first['prepared']=sorted(set(first['prepared'])|carried)
            require(len(first['pending'])<=MAX_RECENT_TRANSITS
                    and len(first['prepared'])<=MAX_MESSAGES,'first carriage metadata capacity')
            updated['first_carriage']={**self.state['first_carriage'],peer:first}
        if updated != self.state:atomic(self.path, updated)
        self.state = updated
        # Advance optional positions only after durable ordinary preparation.
        # Eviction/restart forgets hints and never deletes retained packets.
        background_ordinary=ordinary
        ordered_turn_key=current_carriage.get('ordered_turn_key')
        if ordered_turn_key is not None:
            # Current-copy positions advance separately below. A prioritized
            # spare must not move the ordinary ring past waiting background.
            classes=current_carriage.get('classes',{})
            background_ordinary=[t for t in ordinary if digest(t['packet']) not in classes]
        self.remember_carriage(peer,{'body':{'transits':background_ordinary}})
        # Publish optional current-copy positions only after original durable
        # preparation. Lost sends rotate recipients, never grant custody; a
        # full4 retry, nonpriority pair or miss does not advance these positions.
        if 'classes' in current_carriage:
            domain=self.carriage_position_domain()
            for transit in carried_rows:
                ident=digest(transit['packet'])
                group=current_carriage['classes'].get(ident)
                if group is not None:
                    remember_carriage_position((domain,peer,'native-current-copy',
                                               current_carriage['scope'],*group),ident)
                    remember_carriage_position((domain,peer,'native-current-frame',
                                               current_carriage['scope'],
                                               current_carriage['frame_set'],group[0]),group[1])
            if current_carriage['newest']:
                for transit in ordinary:
                    if digest(transit['packet']) in current_carriage['classes']:
                        remember_carriage_position((domain,peer,'native-current-origin',
                            current_carriage['scope']),transit['packet']['body']['node_id']==self.id)
        if ordered_turn_key is not None and carried_rows:
            remember_carriage_position(ordered_turn_key,current_carriage['ordered_priority_pair'])
        self._trace_spool('prepare_retained',peer,bundle)
        return bundle

    def _trace_prepare_event(self,stage,peer,**fields):
        trace=getattr(self,'contact_trace',None)
        if trace is not None:
            try:trace.event(stage,peer,**fields)
            except Exception:
                try:trace.reject()
                except Exception:pass

    def _trace_prepare_selection(self,peer,bundle,first,retry,hint,priority,copies,frames,origin):
        # Only this operation's scalar selections survive. This neither reads
        # nor advances optional positions and never supplies a packet/proof or
        # prepared state to a later call. A selection is not durable custody.
        trace=getattr(self,'contact_trace',None)
        if trace is None:return
        try:
            rows=trace.packet_rows(bundle);selected={ident for ident,_ in rows}
            pending=set(first['pending']) if first is not None else set()
            arrivals=set(first['arrivals']) if first is not None else set()
            offered=0
            for ident,_ in rows:
                if ident in retry:continue
                if offered==MAX_PACKET_BATCH//2 or ident not in pending:break
                offered+=1
            newest=(self.state['transit_class_steps'][peer]//4)%2==0
            fields=dict(class_step=self.state['transit_class_steps'][peer],
                first_pending=len(pending),first_arrivals=len(arrivals),offered=offered,
                retry_count=len(retry),selected=len(rows),ordered=hint is not None and len(hint)==3,
                priority=priority,newest=newest,
                origin_turn=('local_first' if origin is False else 'forwarded_first') if newest else 'oldest')
            if hint is not None:
                fields['scope_id']=hint[0]
                if hint[1]:
                    frame=hint[1][0];fields['frame_id']=frame
                    direct=[i for i,t in self.state['messages'].items()
                            if t['routing']['body']['frame_id']==frame
                            and t['packet']['body']['node_id']==self.id
                            and t['packet']['body']['destination']==peer]
                    require(len(direct)<=1,'diagnostic exact direct copy differs')
                    if direct:
                        ident=direct[0];recent=ident in self.state['recent_transits']
                        fields.update(direct_id=ident,direct_waiting=ident in pending or ident in arrivals,
                            direct_recent=recent,direct_prepared=first is not None and ident in first['prepared'],
                            direct_selected=ident in selected)
                        after=copies.get((recent,frame))
                        if after is not None:fields['copy_after']=after
                        after=frames.get(recent)
                        if after is not None:fields['frame_after']=after
            trace.event('prepare_selection',peer,**fields)
            trace.packets('prepare_selected',peer,rows)
        except Exception:
            try:trace.reject()
            except Exception:pass

    def _trace_spool(self, stage, peer, bundle):
        """Opt-in primitive timing only; failures never change carriage."""
        trace = getattr(self, 'contact_trace', None)
        if trace is not None:
            try:
                trace.packets(stage, peer, trace.packet_rows(bundle))
            except Exception:
                # Observation loss cannot become a transport or custody result.
                try:trace.reject()
                except Exception:pass

    def _send_spool(self, peer, contact):
        """One existing bounded prepared exchange; durable rotation precedes I/O."""
        bundle = self.prepare_exchange(peer)
        data = evidence.canonical(bundle)
        require(len(data) <= MAX_BATCH, 'exchange bytes exceed bound')
        adapter = contact.get('adapter')
        encoded = spool_codec.encode(data, limit=MAX_BATCH) if adapter == spool_codec.FORMAT else data
        target = contact['outbox'] / (digest(bundle) + '.json')
        files, total = spool_files(contact['outbox'], adapter)
        if not target.exists():
            require(len(files) < MAX_SPOOL_FILES and total + max(len(data), len(encoded)) <= MAX_SPOOL_BYTES,
                    'contact capacity reached; retain queued evidence')
            evidence.write_new(target, encoded)
        else:
            retained = evidence.read_file(target, MAX_BATCH)
            if adapter == spool_codec.FORMAT:
                retained = spool_codec.decode(retained, limit=MAX_BATCH)
            require(retained == data, 'exchange file collision')
        self._trace_spool('spool_outgoing_published', peer, bundle)

    def flush_spool_outgoing(self):
        """Send the one deferred directory batch after Native release/enqueue.

        No intake, archive, global cursor advance, receipt or ledger authority.
        Each peer uses the original prepare/write path and unchanged limits.
        """
        errors = []
        for peer, contact in sorted(self.contacts.items()):
            if 'host' in contact or 'outbox' not in contact:continue
            try:self._send_spool(peer, contact)
            except (OSError, ValueError) as error:errors.append(str(error))
        return errors[:16]

    def tick(self, *, defer_spool_outgoing=False):
        require(type(defer_spool_outgoing) is bool, 'invalid spool scheduling mode')
        errors = []
        try:self.archive_completed()
        except (OSError,ValueError) as error:errors.append(str(error))
        for peer, contact in sorted(self.contacts.items()):
            if 'host' in contact:
                continue  # Socket I/O runs outside the mesh lock via the contact service.
            try:
                incoming, _ = spool_files(contact['inbox'], contact.get('adapter')) if 'inbox' in contact else ([],0)
            except (OSError, ValueError) as error:
                errors.append(str(error))
                incoming = []
            for path in incoming:
                try:
                    require(re.fullmatch(r'[0-9a-f]{64}\.json', path.name), 'unexpected inbox file')
                    if contact.get('adapter') == spool_codec.FORMAT:
                        raw = spool_codec.decode(evidence.read_file(path, MAX_BATCH), limit=MAX_BATCH)
                        bundle = evidence.decode_json(raw)
                        require(raw == evidence.canonical(bundle), 'noncanonical JSON')
                    else:
                        bundle = load(path, MAX_BATCH)
                    require(path.stem == digest(bundle), 'exchange filename mismatch')
                    self._trace_spool('spool_incoming_read', peer, bundle)
                    self.receive(bundle, peer)
                    self._trace_spool('spool_incoming_custody', peer, bundle)
                    path.unlink()
                    fd = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                except (OSError, ValueError) as error:
                    errors.append(str(error))
            if 'outbox' not in contact:continue
            if defer_spool_outgoing:continue
            try:self._send_spool(peer, contact)
            except (OSError, ValueError) as error:errors.append(str(error))
        # Socket preparation owns its durable cursors outside this spool tick.
        # Archive publication above remains mandatory; an otherwise idle socket
        # observation need not repack and rewrite all pending signed frames.
        if not self.contacts or any('host' not in contact for contact in self.contacts.values()):
            self.state['cursor'] = (self.state['cursor'] + 1) % (2**63 - 1)
            self.save()
        report = self.status()
        report['errors'] = errors[:16]
        atomic(self.root / 'status.json', report)
        return report

    def status(self):
        return {'format': VERSION, 'network': self.network, 'node_id': self.id,
                'research_only': True, 'physical_route_verified': False, 'payment_authorized': False,
                'observed_at_unix': int(time.time()), 'nodes': len(self.state['adverts']),
                'regions': sorted({a['body']['region'] for a in self.state['adverts'].values()}),
                'routes_are_advertised_candidates': True,
                'active_messages':len(self.state['messages']),
                'archived_records':len(self.state['archives']),
                'archive_bytes_checked_on_read':True,
                'routes': {i: self.route(i) for i in sorted(self.state['adverts']) if i != self.id},
                'messages': {i: ('EVIDENCE_STORED_NOT_LEDGER_ACCEPTED' if i in self.state['receipts'] else
                    'QUEUED_WAITING_CONTACT_OR_ROUTE') for i in sorted(self.state['messages'])}
                    | {i:'ARCHIVED_EVIDENCE_STORED_NOT_LEDGER_ACCEPTED' for i,v in self.state['archives'].items()
                       if v['body']['kind'] is not None}}

    def export_received(self, ident, output):
        hex32(ident)
        transit = self.transit(ident)
        packet, raw, _ = transit_check(transit, self.network)
        require(packet['destination'] == self.id and ident in self.receipts(), 'not a locally received frame')
        evidence.write_new(Path(output), raw)
        return evidence.inspect_frame(raw)[0]['message_id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--state', type=Path, required=True)
    init.add_argument('--network', required=True)
    init.add_argument('--region', required=True)
    init.add_argument('--label', required=True)
    for name in ['run', 'tick', 'status', 'enqueue', 'export-received']:
        command = sub.add_parser(name)
        command.add_argument('--config', type=Path, required=True)
        if name == 'run':
            command.add_argument('--interval', type=float, default=1)
        if name == 'enqueue':
            command.add_argument('--destination-node', required=True)
            command.add_argument('--frame', type=Path, required=True)
            command.add_argument('--hop-limit', type=int, default=MAX_HOPS)
        if name == 'export-received':
            command.add_argument('--packet-id', required=True)
            command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'init':
        print(json.dumps(initialize(args.state.absolute(), args.network, args.region, args.label)))
        return
    config = load(args.config, 64 * 1024)
    if args.action == 'run':
        require(0.1 <= args.interval <= 3600, 'poll interval outside bound')
        running = True
        def stop(*_):
            nonlocal running
            running = False
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        previous = None
        while running:
            with Node(config) as node:
                report = node.tick()
            comparable = {k: v for k, v in report.items() if k != 'observed_at_unix'}
            if comparable != previous:
                print(json.dumps(report), flush=True)
                previous = comparable
            deadline = time.monotonic() + args.interval
            while running and time.monotonic() < deadline:
                time.sleep(min(0.1, args.interval))
        return
    with Node(config) as node:
        if args.action == 'enqueue':
            result = {'packet_id': node.enqueue(evidence.read_file(args.frame, evidence.MAX_FRAME), args.destination_node, args.hop_limit)}
        elif args.action == 'export-received':
            result = {'frame_id': node.export_received(args.packet_id, args.output), 'ledger_accepted': False}
        elif args.action == 'tick':
            result = node.tick()
        else:
            result = node.status()
        print(json.dumps(result))


if __name__ == '__main__':
    main()
