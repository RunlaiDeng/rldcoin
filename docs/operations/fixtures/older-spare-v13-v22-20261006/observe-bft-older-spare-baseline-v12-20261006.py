from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
assert tests.mesh.TRANSIT_SCHEDULER=='RLD-CONTACT-TRANSIT-SCHEDULER-V12'
class Retained(tests.MeshTests):
    def setUp(self):self.f=tests.Fixture(r/'tmp/default-relay-20260930/bft-older-spare-baseline-v12-private-20261006/fixture')
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Retained('test_older_unserved_gets_alternate_priority_pair_without_displacing_offers')]))
raise SystemExit(0 if result.wasSuccessful() else 1)
