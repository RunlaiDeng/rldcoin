"""Fault setup bindings and real signed transport inspection; no Native claims."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import interstellar_mesh as mesh
from interstellar_mesh_inspection import MeshInspection, config_commitment
from regional_bft_sustained_campaign import retain_fault_inspection_anchors, digest, NativeReceiptProbe
from verify_regional_bft_cycle import inspection_anchors
from test_interstellar_mesh_inspection import Fixture, NETWORK, readonly_guard, snapshot, write_json


class FaultInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-fault-anchor-component-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        transport = self.root/'transport'
        transport.mkdir()
        self.fixture = Fixture(transport)
        self.source = dict(format='RLD-MULTIREGION-MESH-INSPECTION-ANCHORS-V1',
                           network=NETWORK, nodes={})
        self.ids = {}
        for index, (name, n) in enumerate((name, n) for name in ('earth', 'proxima', 'andromeda')
                                          for n in range(4)):
            public = Ed25519PrivateKey.from_private_bytes(bytes([71+index])*32).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw).hex()
            ident = mesh.node_id(public)
            self.ids[name,n] = ident
            config = self.fixture.config if index == 0 else dict(
                format=mesh.VERSION, state=str(self.root/f'new-{name}-{n}'), network=NETWORK, contacts=[])
            write_json(self.root/f'mesh-config-{name}-{n}.json', config)
            self.source['nodes'][f'{name}-{n}'] = dict(public_key=public, node_id=ident,
                network=NETWORK, config_sha256='0'*64)
        self.inherited = self.root/'mesh-inspection-anchors.json'
        write_json(self.inherited, self.source)

    def pin(self, source=None, ids=None):
        return retain_fault_inspection_anchors(self.root, source or self.source, NETWORK, ids or self.ids)

    def load(self, digest_value):
        return inspection_anchors(self.root, dict(currency=NETWORK,
            mesh_inspection_anchors_sha256=digest_value), path_name='fault-mesh-inspection-anchors.json')

    def test_new_config_bindings_keep_original_public_anchor_bytes(self):
        before = self.inherited.read_bytes()
        digest_value = self.pin()
        actual = self.load(digest_value)
        self.assertEqual(self.inherited.read_bytes(), before)
        for label, row in actual['nodes'].items():
            original = self.source['nodes'][label]
            self.assertEqual({k:row[k] for k in ('public_key', 'node_id', 'network')},
                             {k:original[k] for k in ('public_key', 'node_id', 'network')})
            config = mesh.load(self.root/f'mesh-config-{label}.json', 65536)
            self.assertEqual(row['config_sha256'], config_commitment(config))

    def test_existing_fault_anchor_refuses_without_overwriting(self):
        self.pin()
        before = snapshot(self.root)
        with self.assertRaisesRegex(ValueError, 'retain existing'):
            self.pin()
        self.assertEqual(snapshot(self.root), before)

    def test_changed_source_identity_or_missing_carrier_refuses_before_publication(self):
        for change in ('identity', 'inventory', 'network'):
            source = copy.deepcopy(self.source)
            if change == 'identity':
                source['nodes']['earth-0']['public_key'] = source['nodes']['earth-1']['public_key']
            elif change == 'inventory':
                del source['nodes']['earth-3']
            else:
                source['network'] = 'f'*64
            with self.assertRaises(ValueError):
                self.pin(source)
            self.assertFalse((self.root/'fault-mesh-inspection-anchors.json').exists())

    def test_current_config_wrong_network_cannot_be_pinned(self):
        config = dict(self.fixture.config, network='f'*64)
        write_json(self.root/'mesh-config-earth-0.json', config)
        with self.assertRaisesRegex(ValueError, 'network differs'):
            self.pin()
        self.assertFalse((self.root/'fault-mesh-inspection-anchors.json').exists())

    def test_missing_or_changed_report_anchor_refuses_without_conversion(self):
        with self.assertRaises(FileNotFoundError):
            self.load('0'*64)
        digest_value = self.pin()
        with self.assertRaisesRegex(ValueError, 'anchors changed'):
            self.load('f'*64)
        self.assertEqual(digest(self.root/'fault-mesh-inspection-anchors.json'), digest_value)

    def test_pinned_real_transit_receipt_archive_inspection_never_loads_private_identity(self):
        anchors = self.load(self.pin())
        before = snapshot(self.root)
        with readonly_guard() as opened:
            with MeshInspection(self.fixture.config, **anchors['nodes']['earth-0']) as inspector:
                self.assertTrue(inspector.summary['all_indexed_transport_archives_authenticated'])
                self.assertEqual(inspector.summary['indexed_archives'], 1)
                self.assertFalse(inspector.summary['native_value_authenticated'])
        self.assertFalse(any('identity.private.json' in name for name in opened))
        self.assertEqual(snapshot(self.root), before)

    def test_later_config_change_is_rejected_by_retained_anchor(self):
        anchors = self.load(self.pin())
        changed = dict(self.fixture.config, contacts=[{}])
        with readonly_guard(), self.assertRaisesRegex(ValueError, 'config anchor differs'):
            MeshInspection(changed, **anchors['nodes']['earth-0'])


class ReceiptProbeTests(unittest.TestCase):
    def test_receipt_result_is_never_reused_during_skipped_probe(self):
        probe = NativeReceiptProbe()
        first, second = {'current': 1}, {'current': 2}
        read = Mock(side_effect=[first, second])
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=1):
            self.assertIs(probe.attempt(read, lambda value:True), first)
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=2):
            self.assertIs(probe.attempt(read, lambda value:True), False)
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=3):
            self.assertIs(probe.attempt(read, lambda value:True), second)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(set(vars(probe)), {'next_read', 'attempts'})

    def test_failed_current_native_receipt_cannot_pass_with_an_earlier_result(self):
        probe = NativeReceiptProbe()
        read = Mock(side_effect=[{'valid':True}, {'valid':False}])
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=1):
            self.assertEqual(probe.attempt(read, lambda value:value['valid']), {'valid':True})
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=3):
            self.assertIs(probe.attempt(read, lambda value:value['valid']), False)
        self.assertEqual(read.call_count, 2)

    def test_native_refusal_propagates_and_never_returns_partial_authority(self):
        probe = NativeReceiptProbe()
        read = Mock(side_effect=ValueError('native lock refusal'))
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=1):
            with self.assertRaisesRegex(ValueError, 'native lock refusal'):
                probe.attempt(read, lambda value:True)
        with patch('regional_bft_sustained_campaign.time.monotonic', return_value=2):
            self.assertIs(probe.attempt(read, lambda value:True), False)
        self.assertEqual(read.call_count, 1)


if __name__ == '__main__':
    unittest.main()
