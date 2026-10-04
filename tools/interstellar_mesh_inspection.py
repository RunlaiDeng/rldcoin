"""Strict stopped-store transport inspection; external public anchors required.

This is transport authentication only. It grants no receipt issuance, native
ledger authority, current freshness, signing or recovered custody.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat

import interstellar_mesh as mesh
import interstellar_transfer as evidence


def config_commitment(config):
    """Compute at trusted setup, retain independently; never adopt on inspection."""
    return hashlib.sha256(evidence.canonical(config)).hexdigest()


def _open_directory(path):
    path = Path(path)
    mesh.require(path.is_absolute(), 'inspection directory must be absolute')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open('/', flags)
    try:
        for component in path.parts[1:]:
            mesh.require(component not in ('.', '..'), 'unsafe inspection path')
            following = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_regular(directory, name):
    mesh.require(isinstance(name, str) and '/' not in name and name not in ('', '.', '..'),
                 'unsafe inspection file name')
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        mesh.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                     'inspection file must be a regular single-link file')
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read(directory, name, limit):
    descriptor = _open_regular(directory, name)
    try:
        before = os.fstat(descriptor)
        mesh.require(0 <= before.st_size <= limit, 'inspection file capacity exceeded')
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            mesh.require(size <= limit, 'inspection file grew beyond bound')
        after = os.fstat(descriptor)
        mesh.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                     == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                     and size == after.st_size, 'inspection file changed while reading')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


class MeshInspection:
    """No Node inheritance, private key, write method, initialization or recovery.

    The caller supplies public_key/node_id/network/config_sha256 retained at
    trusted fixture setup. Deriving these from the inspected state is forbidden.
    The existing lock is acquired exclusively and nonblocking, read-only.
    """
    archive_entry = mesh.Node.archive_entry
    archived = mesh.Node.archived
    transit = mesh.Node.transit
    receipts = mesh.Node.receipts
    summaries = mesh.Node.summaries

    def __init__(self, config, *, public_key, node_id, network, config_sha256):
        self.lock = self._root_fd = self._archive_fd = None
        mesh.require(isinstance(config, dict) and set(config) == {'format', 'state', 'network', 'contacts'}
                     and config['format'] == mesh.VERSION, 'invalid inspection config')
        self.config = copy.deepcopy(config)
        self.network = mesh.hex32(network)
        self.id = mesh.hex32(node_id)
        self.public_key = mesh.hex32(public_key)
        mesh.require(mesh.node_id(self.public_key) == self.id, 'external public/node anchor differs')
        mesh.require(config['network'] == self.network
                     and mesh.hex32(config_sha256) == config_commitment(config),
                     'external network/config anchor differs')
        self.root = Path(config['state'])
        self.archive_root = self.root / 'archive'
        self.path = self.root / 'mesh-state.json'
        try:
            self._root_fd = _open_directory(self.root)
            self.lock = _open_regular(self._root_fd, '.lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._archive_fd = os.open('archive', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=self._root_fd)
            self.contacts = self._contacts(config['contacts'])
            raw = _read(self._root_fd, 'mesh-state.json', mesh.MAX_STATE)
            image = evidence.decode_json(raw)
            mesh.require(raw == evidence.canonical(image), 'noncanonical inspection state')
            self.state = mesh.unpack_state_storage(image, self.network, self.id)
            mesh.Node.validate_state(self)
            own = self.state['adverts'].get(self.id)
            mesh.require(own is not None and own['public_key'] == self.public_key,
                         'own advertisement lacks external public anchor')
            advert = mesh.advert_check(own, self.network)
            mesh.require(advert['neighbors'] == sorted(peer for peer,contact in self.contacts.items() if mesh.outgoing_contact(contact))
                         and set(self.state['peer_inventory']).issubset(self.contacts)
                         and set(self.state['receipt_cursors']) == set(self.contacts)
                         and set(self.state['requested_receipt_cursors']) == set(self.contacts)
                         and all(set(self.state[name]) == set(self.contacts) for name in
                                 ('transit_cursors', 'recent_transit_cursors',
                                  'history_transit_cursors', 'transit_class_steps')),
                         'retained advertisement/inventory differs from pinned config')
            referenced = set()
            for ident, entry in self.state['archives'].items():
                body = self.archive_entry(entry, ident)
                referenced.add(body['file_id'])
                if body['frame_object'] is not None:
                    referenced.add(body['frame_object']['file_id'])
                self.archived(ident)  # Always read full objects, including warm index hits.
            inventory, total = self.archive_inventory()
            mesh.require(set(inventory) == referenced,
                         'unindexed archive residue requires separate inspection; preserve it')
            self.summary = dict(node_id=self.id, network=self.network,
                                active_messages=len(self.state['messages']),
                                active_receipts=len(self.state['receipts']),
                                indexed_archives=len(self.state['archives']),
                                retained_files=len(inventory), retained_bytes=total,
                                all_indexed_transport_archives_authenticated=True,
                                native_value_authenticated=False)
        except BaseException:
            self.close()
            raise

    def _contacts(self, contacts):
        mesh.require(isinstance(contacts, list) and len(contacts) <= mesh.MAX_CONTACTS,
                     'inspection contact capacity')
        result, spool_dirs = {}, []
        for contact in contacts:
            mesh.contact_schema(contact)
            peer = mesh.hex32(contact['peer'])
            mesh.require(peer != self.id and peer not in result, 'duplicate or self inspection contact')
            if 'host' in contact:
                host, port = mesh.tcp_endpoint(contact['host'], contact['port'])
                result[peer] = dict(host=host, port=port)
                if 'tls_cert_sha256' in contact:
                    result[peer]['tls_cert_sha256'] = mesh.hex32(contact['tls_cert_sha256'])
            else:
                result[peer] = {}
                for name in ('inbox', 'outbox'):
                    if name not in contact:continue
                    path = Path(contact[name])
                    descriptor = _open_directory(path)
                    os.close(descriptor)
                    result[peer][name] = path
                    spool_dirs.append(path)
        mesh.require(len(set(spool_dirs)) == len(spool_dirs), 'inspection spools must be distinct')
        return result

    def archive_inventory(self):
        inventory, total = {}, 0
        for name in os.listdir(self._archive_fd):
            staging = re.fullmatch(r'\.archive-write-[0-9a-f]{64}', name)
            info = os.stat(name, dir_fd=self._archive_fd, follow_symlinks=False)
            mesh.require((staging or re.fullmatch(r'[0-9a-f]{64}\.json', name))
                         and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                         'unsafe inspection archive file')
            size = info.st_size
            mesh.require((0 if staging else 1) <= size <= mesh.MAX_STATE
                         and len(inventory) < mesh.MAX_ARCHIVE_FILES, 'inspection archive file capacity')
            total += size
            mesh.require(total <= mesh.MAX_ARCHIVE_BYTES, 'inspection archive byte capacity')
            inventory[Path(name).stem] = size
        return inventory, total

    def _archive_read(self, name):
        return _read(self._archive_fd, name, mesh.MAX_STATE)

    def close(self):
        for name in ('_archive_fd', 'lock', '_root_fd'):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
