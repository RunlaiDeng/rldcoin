from pathlib import Path
import sys,unittest,threading
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_tcp as tests
class Retained(tests.TcpTests):
 def setUp(self):
  self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/input-release-wake-tcp-related-v27-private-20261007'+'/'+self._testMethodName)
  self.addCleanup(self.f.close)
suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(tests.DeferredAdmissionTests))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(tests.InputReleaseWakeTests))
suite.addTests(Retained(n) for n in ['test_authenticated_refusal_hands_off_after_busy_original_input_slot_releases', 'test_exhausted_local_lock_wait_refuses_without_custody_then_fresh_attempt_recovers', 'test_unverified_reply_or_failed_local_custody_never_suppresses_retry', 'test_response_loss_new_connection_retry_deduplicates_exact_packet_custody'])
import test_interstellar_mesh as mesh_tests
class MeshRetained(mesh_tests.MeshTests):
 def setUp(self):self.f=mesh_tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/input-release-wake-ordinary-v27-private-20261007'+'/'+self._testMethodName)
suite.addTest(MeshRetained('test_current_frame_hint_pressure_ordinary_delivery'))
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite)
owned=[t.name for t in threading.enumerate() if t is not threading.main_thread() and t.name.startswith('rld-')]
print('owned-ground-threads '+repr(owned),flush=True)
raise SystemExit(0 if result.wasSuccessful() and not owned else 1)
