"""One previous fully authenticated index reuses only exact immutable entries."""
import copy
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture

class ArchiveEntryWitnessTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.f=Fixture(temporary.name)
        with self.f.node('earth') as node:
            for _ in range(3):node.enqueue(self.f.frame(),node.id)
            with patch.object(mesh,'ARCHIVE_HIGH_WATER',1):node.archive_completed()
            self.state=copy.deepcopy(node.state)
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None

    def test_changed_index_reuses_exact_preceding_rows_but_restart_rechecks(self):
        with self.f.node('earth') as node:
            original=copy.deepcopy(node.state)
            node.state=copy.deepcopy(original);node.state['archives'].pop(next(iter(node.state['archives'])))
            with patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                node.validate_state();self.assertEqual(check.call_count,0)
                # Returning the omitted row now requires full verification: only
                # the immediately preceding index remains, not an ever-growing cache.
                node.state=original;node.validate_state();self.assertEqual(check.call_count,1)
            with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
            with patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                node.validate_state();self.assertEqual(check.call_count,3)

    def test_actual_new_signed_archive_entry_authenticates_once(self):
        with self.f.node('earth') as node:
            node.enqueue(self.f.frame(),node.id)
            with patch.object(mesh,'ARCHIVE_HIGH_WATER',1):node.archive_completed()
            self.assertEqual(len(node.state['archives']),4)
            with patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                node.validate_state();self.assertEqual(check.call_count,1)
                node.validate_state();self.assertEqual(check.call_count,1)

    def test_changed_later_signature_refuses_and_cannot_publish_witness(self):
        with self.f.node('earth') as node:
            witness=mesh._verified_archive_index
            ident=next(iter(node.state['archives']));entry=node.state['archives'][ident]
            entry['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):node.validate_state()
            self.assertIs(mesh._verified_archive_index,witness)

    def test_signed_changed_receipt_role_requires_full_recheck(self):
        with self.f.node('earth') as node:
            ident=next(iter(node.state['archives']));entry=copy.deepcopy(node.state['archives'][ident]['body'])
            entry['receipt']['body']['outcome']='LEDGER_ACCEPTED'
            node.state['archives'][ident]=mesh.sign(node.key,'archive',entry)
            with self.assertRaises(ValueError):node.validate_state()

    def test_missing_file_and_active_overlap_refuse_on_overlap_hit(self):
        for failure in ('missing','overlap'):
            with self.subTest(failure=failure),self.f.node('earth') as node:
                node.state=copy.deepcopy(self.state)
                removed=next(iter(node.state['archives']));node.state['archives'].pop(removed)
                ident=next(iter(node.state['archives']))
                if failure=='missing':
                    inventory=node.archive_inventory()
                    files=dict(inventory[0]);files.pop(node.state['archives'][ident]['body']['file_id'])
                    with patch.object(node,'archive_inventory',return_value=(files,inventory[1])):
                        with self.assertRaisesRegex(ValueError,'file missing'):node.validate_state()
                else:
                    node.state['messages'][ident]=node.archived(ident)['transit']
                    node.state['first_arrivals'].append(ident)
                    with self.assertRaisesRegex(ValueError,'duplicate active/archived'):node.validate_state()

    def test_bound_reduction_and_changed_store_force_full_verification(self):
        with self.f.node('earth') as node:
            node.state['archives'].pop(next(iter(node.state['archives'])))
            with patch.object(mesh,'MAX_VERIFIED_ARCHIVE_INDEX_BYTES',1),patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                node.validate_state();self.assertEqual(check.call_count,2)
                self.assertIsNone(mesh._verified_archive_index)
            node.validate_state()
            node.root=node.root/'different-synthetic-scope'
            with patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                node.validate_state();self.assertEqual(check.call_count,2)

    def test_optional_entry_retention_falls_back_to_original_exact_index(self):
        with self.f.node('earth') as node:
            witness=mesh._verified_archive_index
            base=len(witness[1])+len(mesh.evidence.canonical(witness[2]))+len(mesh.evidence.canonical(witness[0]))
            # A limit change creates a different trust domain and forces a miss.
            with patch.object(mesh,'MAX_VERIFIED_ARCHIVE_INDEX_BYTES',base+512):
                node.validate_state();limited=mesh._verified_archive_index
                self.assertIsNotNone(limited);self.assertEqual(limited[4],())
                self.assertLessEqual(limited[3],base+512)
                with patch.object(node,'archive_entry',wraps=node.archive_entry) as check:
                    node.validate_state();self.assertEqual(check.call_count,0)

if __name__=='__main__':unittest.main()
