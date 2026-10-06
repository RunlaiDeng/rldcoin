from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/bft-current-commit-warm-owner-related-delivery-v22-v2-private-20261006'+'/'+self._testMethodName)
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in ['test_warm_state_owner_check_avoids_unused_decode_but_cold_misses_fully_authenticate', 'test_exact_transit_witness_cannot_authorize_changed_bytes_or_contact', 'test_current_frame_hint_pressure_ordinary_delivery']))
raise SystemExit(0 if result.wasSuccessful() else 1)
