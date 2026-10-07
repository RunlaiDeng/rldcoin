from pathlib import Path
import tempfile
import unittest
import interstellar_mesh as mesh
from keyless_stale_observation_model_provider_v1 import StoppedObservationTests

class ShutdownObservationTests(StoppedObservationTests):
    def test_exact_shutdown_marker_only_after_clean_stop_is_unknown(self):
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
            d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence'];mesh.atomic(p,v)
            before=p.read_bytes();d.stop_all();self.restart(d)
            self.assertEqual(d.observations(),{('earth',0):None});self.assertFalse(d.tls_observations)
            self.assertEqual(p.read_bytes(),before)
            v['process_id']=102;v['consensus']['autonomous_signing_enabled']=False;mesh.atomic(p,v)
            with self.assertRaisesRegex(ValueError,'actual Native/Service error'):d.observations()
            v['errors']=[];mesh.atomic(p,v);self.assertEqual(d.observations(),{('earth',0):12})
    def test_shutdown_marker_never_hides_other_stop_errors(self):
        for error in ('native rejected: invalid complete finality proof','[Errno 22] Invalid argument','TCP runtime is stopping; preserve evidence extra','regional candidate rejected: Permission denied (os error 13)'):
            with self.subTest(error=error),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
                d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence',error];mesh.atomic(p,v)
                d.stop_all();self.assertFalse(d.stopped_observations);self.restart(d)
                with self.assertRaises(ValueError):d.observations()
        with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp') as t:
            d,p,v=self.setup_model(Path(t));v['errors']=['TCP runtime is stopping; preserve evidence'];v['rejected']=['complete envelope'];mesh.atomic(p,v)
            d.stop_all();self.assertFalse(d.stopped_observations);self.restart(d)
            with self.assertRaises(ValueError):d.observations()
