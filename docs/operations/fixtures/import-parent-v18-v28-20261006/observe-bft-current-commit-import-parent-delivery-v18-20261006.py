from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/bft-current-commit-import-parent-delivery-v18-private-20261006'+'/'+self._testMethodName)
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in ['test_prepared_import_parent_proposal_priority_reaches_destination_after_full_retry']))
raise SystemExit(0 if result.wasSuccessful() else 1)
