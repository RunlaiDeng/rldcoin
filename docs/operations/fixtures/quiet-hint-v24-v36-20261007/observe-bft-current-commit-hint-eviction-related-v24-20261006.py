from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/bft-current-commit-hint-eviction-related-v24-private-20261006'+'/'+self._testMethodName)
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in ['test_evicted_current_proposal_hint_restored_before_quiet_return', 'test_new_remote_current_frame_invalidates_complete_broadcast_quiet_inventory', 'test_current_frame_hint_survives_group_position_pressure_in_same_plan', 'test_current_frame_hint_pressure_ordinary_delivery']))
raise SystemExit(0 if result.wasSuccessful() else 1)
