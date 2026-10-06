from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
assert tests.mesh.TRANSIT_SCHEDULER=='RLD-CONTACT-TRANSIT-SCHEDULER-V13'
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture(r/'tmp/default-relay-20260930/bft-older-spare-related-v13-private-20261006'/self._testMethodName)
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in ['test_older_unserved_gets_alternate_priority_pair_without_displacing_offers', 'test_older_pending_advances_under_new_arrivals_and_full_replay', 'test_promoted_latest_waiter_keeps_priority_until_prepared', 'test_latest_waiting_arrival_gets_spare_slot_without_displacing_pending_pair', 'test_new_arrival_uses_ordinary_class_slot_with_full_waiting_queue', 'test_arrival_waiting_survives_preparation_gap_atomic_failure_and_cold_open', 'test_arrival_waiting_survives_full_admission_queue_and_cold_open', 'test_arrival_metadata_schema_and_original_capacity_refuse_without_write', 'test_first_offer_queue_is_scoped_to_actual_outgoing_branch', 'test_ineligible_waiting_metadata_changes_only_after_atomic_preparation', 'test_first_offer_survives_recent_eviction_and_cold_positions', 'test_first_offer_authentication_and_failed_atomic_do_not_publish_metadata', 'test_first_offer_metadata_schema_and_original_capacities_refuse', 'test_retry_preserves_ordinary_positions_and_retains_original_packets', 'test_retry_still_authenticates_and_obeys_suppression', 'test_receipt_only_archive_then_original_transit_retains_arrival_order_on_cold_open']))
raise SystemExit(0 if result.wasSuccessful() else 1)
