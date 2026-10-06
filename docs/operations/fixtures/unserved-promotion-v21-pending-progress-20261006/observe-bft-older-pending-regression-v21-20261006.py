from pathlib import Path
import sys, unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
class Retained(tests.MeshTests):
    def setUp(self):
        self.f=tests.Fixture(r/'tmp/default-relay-20260930/bft-older-pending-regression-v21-private-20261006/fixture')
suite=unittest.TestSuite([Retained('test_older_pending_advances_under_new_arrivals_and_full_replay')])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
