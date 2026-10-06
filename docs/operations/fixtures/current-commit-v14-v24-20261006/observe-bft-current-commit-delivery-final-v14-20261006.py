from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/bft-current-commit-delivery-final-v14-private-20261006'+'/'+self._testMethodName)
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in ['test_native_context_commit_hint_reaches_destination_via_ordinary_ticks']))
raise SystemExit(0 if result.wasSuccessful() else 1)
