"""Atomic bounded carriage publication, failures and full cold authentication."""
import copy
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name)

    def test_four_local_packets_publish_once_and_cold_receipts_bind_exact_bytes(self):
        with self.f.node('earth') as node:
            original=mesh.atomic
            with patch.object(mesh,'atomic',wraps=original) as saved:
                ids=node.enqueue_batch([(self.f.frame(),node.id)]*4)
            self.assertEqual(saved.call_count,1);self.assertEqual(len(set(ids)),4)
            self.assertTrue(all(i in node.state['receipts'] for i in ids))
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('earth') as node:
            for ident in ids:
                transit=node.transit(ident);mesh.transit_check(transit,node.network)
                mesh.receipt_matches(node.state['receipts'][ident],transit)
                self.assertEqual(node.state['receipts'][ident]['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_invalid_last_item_and_excess_capacity_leave_disk_and_memory_unchanged(self):
        with self.f.node('earth') as node:
            before=node.path.read_bytes();state=copy.deepcopy(node.state)
            for items in ([(self.f.frame(),node.id)]*3+[(b'{}',node.id)],
                          [(self.f.frame(),node.id)]*5,[],[(self.f.frame(),'bad')]):
                with self.assertRaises(ValueError):node.enqueue_batch(items)
                self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)
            with patch.object(mesh,'MAX_MESSAGES',3):
                with self.assertRaisesRegex(ValueError,'capacity'):node.enqueue_batch([(self.f.frame(),node.id)]*4)
            self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)

    def test_prepublication_failure_keeps_original_state(self):
        with self.f.node('earth') as node:
            before=node.path.read_bytes();state=copy.deepcopy(node.state)
            with patch.object(mesh,'atomic',side_effect=OSError('injected before publication')):
                with self.assertRaises(OSError):node.enqueue_batch([(self.f.frame(),node.id)]*4)
            self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)
        with self.f.node('earth') as node:self.assertEqual(len(node.state['messages']),0)

    def test_lost_response_after_atomic_publication_retains_whole_batch(self):
        with self.f.node('earth') as node:
            original=mesh.atomic
            def lost(path,state):
                original(path,state);raise OSError('injected lost publication response')
            with patch.object(mesh,'atomic',side_effect=lost):
                with self.assertRaises(OSError):node.enqueue_batch([(self.f.frame(),node.id)]*4)
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('earth') as node:
            self.assertEqual(len(node.state['messages']),4);self.assertEqual(len(node.state['receipts']),4)
            for ident,transit in node.state['messages'].items():
                mesh.transit_check(transit,node.network);mesh.receipt_matches(node.state['receipts'][ident],transit)

    def test_local_receipt_capacity_failure_publishes_no_partial_batch(self):
        with self.f.node('earth') as node:
            before=node.path.read_bytes();state=copy.deepcopy(node.state)
            original=node.deliver_local
            def limited(value):
                with patch.object(mesh,'MAX_MESSAGES',2):original(value)
            with patch.object(node,'deliver_local',side_effect=limited):
                with self.assertRaisesRegex(ValueError,'receipt capacity'):node.enqueue_batch([(self.f.frame(),node.id)]*4)
            self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)


if __name__=='__main__':unittest.main()
