from pathlib import Path
import importlib.util,json,sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));sys.path.insert(0,str(r/'tmp/default-relay-20260930'))
import test_interstellar_mesh as tests
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import first_service_diagnostic_observer_v4_20261007 as diag
class Retained(tests.MeshTests):
 def setUp(self):
  self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/priority-hint-observer-v4-ground-v2-private-20261007'+'/'+self._testMethodName)
  self.ring=diag.Ring(dict(process_id=999999,scope=str(self.f.root),slot=0,contract_sha256='a'*64))
  self.observer=diag.Observer(mesh,tcp,self.f.root/'earth',self.ring);self.observer.install()
 def tearDown(self):
  self.observer.restore();value=self.ring.snapshot();assert value['available'] and value['rejected']==0 and value['records'];assert all('priority' in z for z in value['records']);assert any(z['priority']['hint_scope'] is not None and z['priority']['matching_packet_ids'] for z in value['records']);print('primitive-observation-result '+json.dumps(dict(available=True,rejected=0,records=value['sequence'],diagnostic_profile=diag.FORMAT,original_signed_ordinary_assertions_passed=True)))
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([Retained('test_current_frame_hint_pressure_ordinary_delivery')]))
raise SystemExit(0 if result.wasSuccessful() else 1)
