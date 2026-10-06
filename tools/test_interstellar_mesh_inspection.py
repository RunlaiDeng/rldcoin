"""Pure synthetic transport fixtures; no Runtime, native CLI or private keys on disk."""
import base64
import builtins
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import interstellar_mesh as mesh
import interstellar_transfer as evidence
from interstellar_mesh_inspection import MeshInspection, config_commitment


NETWORK = 'a' * 64


def write_json(path, value):
    path.write_bytes(evidence.canonical(value))


def snapshot(root):
    result = {}
    for path in root.rglob('*'):
        info = path.lstat()
        result[str(path.relative_to(root))] = (path.read_bytes() if path.is_file() else None,
                                               info.st_uid, info.st_mode, info.st_nlink,
                                               info.st_size, info.st_mtime_ns)
    return result


class Fixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        (self.root / 'archive').mkdir()
        (self.root / '.lock').write_bytes(b'')
        # A poison marker, not a key; the inspector must never open this name.
        (self.root / 'identity.private.json').write_bytes(b'FORBIDDEN-TO-READ')
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.node = mesh.node_id(self.public)
        self.config = dict(format=mesh.VERSION, state=str(self.root), network=NETWORK, contacts=[])
        self.anchor = dict(public_key=self.public, node_id=self.node, network=NETWORK,
                           config_sha256=config_commitment(self.config))
        advert = mesh.sign(self.key, 'advert', dict(format=mesh.VERSION, network=NETWORK,
            node_id=self.node, region='b' * 64, label='synthetic-inspection', sequence=1, neighbors=[]))
        self.state = dict(first_arrivals=[], first_carriage={}, transit_scheduler=mesh.TRANSIT_SCHEDULER, transit_cursors={},
                          recent_transits=[], recent_transit_cursors={}, history_transit_cursors={},
                          transit_class_steps={}, active_storage=mesh.ACTIVE_STORAGE, format=mesh.VERSION, archive_storage=mesh.ARCHIVE_STORAGE,
                          receipt_scheduler=mesh.RECEIPT_SCHEDULER, receipt_cursors={}, requested_receipt_cursors={},
                          network=NETWORK, node_id=self.node, adverts={self.node: advert},
                          messages={}, receipts={}, archives={}, peer_inventory={}, cursor=0)
        self.packet_id, transit, receipt = self.packet(1)
        self.archive(self.packet_id, transit, receipt)
        self.active_id, transit, receipt = self.packet(2)
        self.state['messages'][self.active_id] = transit
        self.state['first_arrivals'].append(self.active_id)
        self.state['receipts'][self.active_id] = receipt
        self.persist()

    def packet(self, nonce):
        frame = evidence.make_frame('source-finality', '1' * 64, '2' * 64, '3' * 64,
                                    b'{"synthetic":true,"requires_native_validation":true}')
        header, _ = evidence.inspect_frame(frame)
        packet = mesh.sign(self.key, 'packet', dict(format=mesh.VERSION, network=NETWORK,
            node_id=self.node, destination=self.node, nonce=bytes([nonce] * 32).hex(),
            hop_limit=mesh.MAX_HOPS, frame=base64.b64encode(frame).decode()))
        ident = mesh.digest(packet)
        routing = mesh.sign(self.key, 'receipt-route', dict(format=mesh.VERSION, network=NETWORK,
            node_id=self.node, packet_id=ident, destination=self.node, frame_id=header['message_id']))
        transit = dict(packet=packet, routing=routing, hops=[])
        receipt = mesh.sign(self.key, 'receipt', dict(format=mesh.VERSION, network=NETWORK,
            node_id=self.node, packet_id=ident, frame_id=header['message_id'], routing=routing,
            outcome='EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'))
        return ident, transit, receipt

    def archive(self, ident, transit, receipt):
        complete = dict(format=mesh.VERSION, network=NETWORK, node_id=self.node,
                        packet_id=ident, transit=transit, receipt=receipt)
        stored = copy.deepcopy(complete)
        stored['format'] = mesh.ARCHIVE_STORAGE
        frame = stored['transit']['packet']['body'].pop('frame')
        payload = evidence.canonical(dict(format=mesh.ARCHIVE_FRAME, network=NETWORK,
                                           node_id=self.node, frame=frame))
        self.frame_id = hashlib.sha256(payload).hexdigest()
        self.frame_path = self.root / 'archive' / (self.frame_id + '.json')
        self.frame_path.write_bytes(payload)
        ref = dict(file_id=self.frame_id, size_bytes=len(payload))
        expanded = evidence.canonical(complete)
        stored.update(frame_object=ref, expanded_sha256=hashlib.sha256(expanded).hexdigest(),
                      expanded_size_bytes=len(expanded))
        raw = evidence.canonical(stored)
        file_id = hashlib.sha256(raw).hexdigest()
        self.wrapper_path = self.root / 'archive' / (file_id + '.json')
        self.wrapper_path.write_bytes(raw)
        route = receipt['body']['routing']['body']
        self.state['archives'][ident] = mesh.sign(self.key, 'archive', dict(format=mesh.VERSION,
            network=NETWORK, node_id=self.node, packet_id=ident, file_id=file_id,
            size_bytes=len(raw), source=self.node, destination=self.node,
            frame_id=route['frame_id'], export_id='3' * 64, kind='source-finality', receipt=receipt,
            frame_object=ref, expanded_sha256=stored['expanded_sha256'], expanded_size_bytes=len(expanded)))

    def persist(self):
        write_json(self.root / 'mesh-state.json', mesh.pack_state_storage(self.state))


@contextmanager
def readonly_guard():
    real_open = os.open
    opened = []
    def guarded_open(path, flags, *args, **kwargs):
        name = os.fspath(path)
        if isinstance(name, bytes):
            name = name.decode()
        if 'identity.private.json' in name:
            raise AssertionError('private identity opened')
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('write-capable descriptor requested')
        opened.append(name)
        return real_open(path, flags, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError('private/signing/mutating API used during inspection')
    with ExitStack() as stack:
        stack.enter_context(patch.object(os, 'open', guarded_open))
        for owner, names in [(mesh, ('sign', 'safe_dir', 'atomic', 'archive_write', 'sync_retained')),
                             (mesh.Node, ('__init__', 'save')),
                             (evidence, ('ensure_dir', 'write_new')),
                             (builtins, ('open',)), (io, ('open',)),
                             (Path, ('open', 'mkdir', 'write_bytes', 'write_text', 'unlink')),
                             (os, ('write', 'fsync', 'mkdir', 'makedirs', 'replace', 'rename', 'link', 'unlink',
                                   'truncate', 'ftruncate', 'fdopen'))]:
            for name in names:
                stack.enter_context(patch.object(owner, name, forbidden))
        yield opened


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-synthetic-inspection-')
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(self.temp.name)
        mesh._verified_archive_index = None
        with mesh._verified_transits_lock:
            mesh._verified_transits.clear()

    def inspect(self, config=None, anchor=None):
        f = self.fixture
        return MeshInspection(config or f.config, **(anchor or f.anchor))

    def test_complete_state_archive_receipt_transit_without_private_or_writes(self):
        f = self.fixture
        before = snapshot(f.root)
        with readonly_guard() as opened:
            with self.inspect() as node:
                self.assertEqual(node.summary['indexed_archives'], 1)
                self.assertEqual(node.summary['retained_files'], 2)
                self.assertTrue(node.summary['all_indexed_transport_archives_authenticated'])
                self.assertFalse(node.summary['native_value_authenticated'])
                self.assertEqual(node.transit(f.packet_id)['packet']['body']['node_id'], f.node)
                self.assertEqual(set(node.receipts()), {f.packet_id, f.active_id})
                self.assertIn(f.packet_id, node.summaries())
                self.assertFalse(hasattr(node, 'save'))
                self.assertFalse(hasattr(node, 'key'))
        self.assertTrue(opened)
        self.assertEqual(snapshot(f.root), before)

    def test_transit_cursor_map_must_match_pinned_contacts_without_repair(self):
        f=self.fixture
        for name, value in (('transit_cursors',None),('recent_transit_cursors',None),
                            ('history_transit_cursors',None),('transit_class_steps',0)):
            f.state[name]={'f'*64:value};f.persist();before=snapshot(f.root)
            with readonly_guard(),self.assertRaisesRegex(ValueError,'pinned config'):self.inspect()
            self.assertEqual(snapshot(f.root),before)
            f.state[name]={}

    def test_requested_receipt_cursor_map_must_match_external_contacts_without_repair(self):
        f=self.fixture;f.state['requested_receipt_cursors']={'f'*64:0};f.persist()
        before=snapshot(f.root)
        with readonly_guard(),self.assertRaisesRegex(ValueError,'pinned config'):self.inspect()
        self.assertEqual(snapshot(f.root),before)

    def test_missing_lock_state_archive_or_root_never_created(self):
        f = self.fixture
        for path in (f.root / '.lock', f.root / 'mesh-state.json'):
            raw = path.read_bytes()
            path.unlink()
            before = snapshot(f.root)
            with readonly_guard(), self.assertRaises(FileNotFoundError):
                self.inspect()
            self.assertEqual(snapshot(f.root), before)
            self.assertFalse(path.exists())
            path.write_bytes(raw)
        missing = f.root / 'absent'
        config = dict(f.config, state=str(missing))
        anchor = dict(f.anchor, config_sha256=config_commitment(config))
        with readonly_guard(), self.assertRaises(FileNotFoundError):
            self.inspect(config, anchor)
        self.assertFalse(missing.exists())
        archive = f.root / 'archive'
        archive.rename(f.root / 'kept-archive')
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaises(FileNotFoundError):
            self.inspect()
        self.assertEqual(snapshot(f.root), before)

    def test_external_anchors_required_and_identity_not_inferred(self):
        f = self.fixture
        with readonly_guard(), self.assertRaises(TypeError):
            MeshInspection(f.config)
        for field in ('public_key', 'node_id', 'network', 'config_sha256'):
            anchor = dict(f.anchor, **{field: 'f' * 64})
            with readonly_guard(), self.assertRaises(ValueError):
                self.inspect(anchor=anchor)
        another = Ed25519PrivateKey.from_private_bytes(bytes([72]) * 32)
        public = another.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        anchor = dict(f.anchor, public_key=public, node_id=mesh.node_id(public))
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'state identity'):
            self.inspect(anchor=anchor)

    def test_private_identity_absent_still_authenticates_public_anchored_store(self):
        f = self.fixture
        (f.root / 'identity.private.json').unlink()
        before = snapshot(f.root)
        with readonly_guard(), self.inspect() as node:
            self.assertEqual(node.id, f.node)
        self.assertEqual(snapshot(f.root), before)

    def test_config_drift_refuses_without_rewriting_advert_or_inventory(self):
        f = self.fixture
        peer = mesh.node_id('f' * 64)
        changed = dict(f.config, contacts=[dict(peer=peer, host='127.0.0.1', port=9000)])
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'config anchor'):
            self.inspect(config=changed)
        # Even if a caller explicitly pins a new config, retained old neighbors refuse.
        anchor = dict(f.anchor, config_sha256=config_commitment(changed))
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'advertisement/inventory'):
            self.inspect(config=changed, anchor=anchor)
        self.assertEqual(snapshot(f.root), before)

    def test_missing_spool_directory_not_created(self):
        f = self.fixture
        absent = f.root / 'missing-spool'
        config = dict(f.config, contacts=[dict(peer=mesh.node_id('f' * 64),
                     inbox=str(absent), outbox=str(f.root / 'missing-outbox'))])
        anchor = dict(f.anchor, config_sha256=config_commitment(config))
        with readonly_guard(), self.assertRaises(FileNotFoundError):
            self.inspect(config, anchor)
        self.assertFalse(absent.exists())

    def test_bad_advert_active_packet_active_receipt_and_archive_signatures(self):
        f = self.fixture
        cases = [('adverts', f.node), ('messages', f.active_id),
                 ('receipts', f.active_id), ('archives', f.packet_id)]
        original = copy.deepcopy(f.state)
        for kind, ident in cases:
            f.state = copy.deepcopy(original)
            target = f.state[kind][ident]
            if kind == 'messages':
                target = target['packet']
            target['signature'] = '0' * 128
            f.persist()
            before = snapshot(f.root)
            with readonly_guard(), self.assertRaisesRegex(ValueError, 'signature'):
                self.inspect()
            self.assertEqual(snapshot(f.root), before)

    def test_shared_payload_and_wrapper_corruption_refuse_under_warm_witness(self):
        f = self.fixture
        for path in (f.frame_path, f.wrapper_path):
            with readonly_guard(), self.inspect():
                pass
            self.assertIsNotNone(mesh._verified_archive_index)
            good = path.read_bytes()
            bad = bytearray(good)
            bad[-2] ^= 1  # Same length: metadata witness remains an exact hit.
            path.write_bytes(bad)
            before = snapshot(f.root)
            with readonly_guard(), self.assertRaisesRegex(ValueError, 'bytes differ'):
                self.inspect()
            self.assertEqual(snapshot(f.root), before)
            path.write_bytes(good)

    def test_valid_outer_archive_hashes_and_signature_do_not_hide_bad_inner_packet(self):
        f = self.fixture
        ident, transit, receipt = f.packet(3)
        transit['packet']['signature'] = '0' * 128
        # Fresh outer signatures and exact object hashes do not authenticate the packet.
        f.archive(ident, transit, receipt)
        f.persist()
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'signature'):
            self.inspect()
        self.assertEqual(snapshot(f.root), before)

    def test_valid_outer_archive_signature_does_not_hide_bad_embedded_receipt(self):
        f = self.fixture
        ident, transit, receipt = f.packet(3)
        receipt['signature'] = '0' * 128
        f.archive(ident, transit, receipt)
        f.persist()
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'signature'):
            self.inspect()
        self.assertEqual(snapshot(f.root), before)

    def test_missing_shared_object_and_unindexed_residue_preserved(self):
        f = self.fixture
        good = f.frame_path.read_bytes()
        with readonly_guard(), self.inspect():
            pass
        f.frame_path.unlink()
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'frame missing'):
            self.inspect()
        self.assertEqual(snapshot(f.root), before)
        f.frame_path.write_bytes(good)
        orphan = f.root / 'archive' / ('e' * 64 + '.json')
        orphan.write_bytes(b'{"retained_residue":true}')
        before = snapshot(f.root)
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'unindexed archive residue'):
            self.inspect()
        self.assertEqual(snapshot(f.root), before)

    def test_symlink_lock_state_archive_object_and_root_refuse(self):
        f = self.fixture
        for path in (f.root / '.lock', f.root / 'mesh-state.json', f.frame_path):
            raw = path.read_bytes()
            kept = f.root / 'retained-original'
            path.rename(kept)
            path.symlink_to(kept)
            with readonly_guard(), self.assertRaises((OSError, ValueError)):
                self.inspect()
            path.unlink()
            kept.rename(path)
            self.assertEqual(path.read_bytes(), raw)

    def test_existing_lock_contention_fails_without_waiting_or_modification(self):
        import fcntl
        f = self.fixture
        descriptor = os.open(f.root / '.lock', os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = snapshot(f.root)
            with readonly_guard(), self.assertRaises(BlockingIOError):
                self.inspect()
            self.assertEqual(snapshot(f.root), before)
        finally:
            os.close(descriptor)


if __name__ == '__main__':
    unittest.main()
