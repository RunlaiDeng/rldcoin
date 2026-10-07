"""A completed contact unit must not start consensus after runtime stop.

Control-flow models have no Native, transport, signing or ledger authority.
"""
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

import interstellar_tcp as tcp
import test_regional_contact_observation_scope as scope


class StopBoundaryTests(unittest.TestCase):
    def exercise(self, after_receive):
        fixture = scope.ObservationScopeTests(methodName='runTest')
        service = fixture.service(kind='regional-bft' if after_receive else None)
        service.tcp.running = True
        started = []
        service.bft.tick = lambda: started.append('consensus') or {}
        completed = []
        if after_receive:
            original = service.receive_bft_batch
            def receive(*args):
                original(*args)
                completed.append('receive')
                service.tcp.running = False
            service.receive_bft_batch = receive
        else:
            original = service.contact_observation
            def observe():
                result = original()
                completed.append('observation')
                service.tcp.running = False
                return result
            service.contact_observation = observe
        with self.assertRaises(tcp.MeshRuntimeStopping):
            fixture.tick(service)
        self.assertEqual(completed, ['receive'] if after_receive else ['observation'])
        self.assertEqual(started, [], 'stopped contact unit must not initiate consensus')
        if after_receive:
            self.assertIn('bft-receive', service.calls)
        # No interruption of the complete receive or signer unit is modelled.

    def test_stop_after_completed_native_observation_prevents_new_consensus(self):
        self.exercise(False)

    def test_stop_after_completed_bft_receive_prevents_new_consensus(self):
        self.exercise(True)


@unittest.skipUnless(os.environ.get('RLD_CONTACT_STOP_FIXTURE') and
                     os.environ.get('RLD_CONTACT_BINARY'),
                     'explicit fresh retained Native fixture and binary required')
class NativeStopBoundaryTests(unittest.TestCase):
    def test_actual_sigterm_after_native_read_closes_within_original_five_seconds(self):
        from regional_bft_network_campaign import Campaign
        from regional_contact_campaign import public
        from regional_fixture_native_json import decode_native_json
        root = Path(os.environ['RLD_CONTACT_STOP_FIXTURE'])
        self.assertTrue(root.is_absolute())
        self.assertFalse(root.exists())
        root.mkdir(mode=0o700)
        binary = Path(os.environ['RLD_CONTACT_BINARY']).resolve(strict=True)
        campaign = Campaign(binary, root/'fixture')
        ledger = campaign.node('earth', 1)
        config = campaign.root/'bft-config-1.json'
        gate = root/'native-read-completed'
        log = root/'ordinary-node.log'
        before = (ledger/'journal.json').read_bytes()
        code = """import sys,time
from pathlib import Path
import regional_contact_node as contact
from regional_bft_node import Runtime
original=contact.Service.contact_observation
marker=Path(sys.argv[1]);args=sys.argv[2:]
def stop_boundary(self):
 value=original(self)
 marker.write_text('full Native read completed')
 while self.tcp.running:time.sleep(0.005)
 return value
def forbidden(self):raise AssertionError('consensus started after received stop')
contact.Service.contact_observation=stop_boundary
Runtime.tick=forbidden
sys.argv=['ordinary-contact',*args]
contact.main()
"""
        args=['--binary',str(binary),'--ledger',str(ledger),'--authority',public(1),
              '--currency',campaign.currency,'--mesh-config',str(campaign.root/'mesh-config-1.json'),
              '--bft-config',str(config),'--interval','0.1']
        project=Path(__file__).resolve().parents[1]
        env=dict(os.environ,PYTHONPATH=str(project/'tools'),PYTHONDONTWRITEBYTECODE='1')
        with log.open('w') as output:
            process=subprocess.Popen([sys.executable,'-B','-c',code,str(gate),*args],
                cwd=project,stdout=output,stderr=subprocess.STDOUT,env=env,start_new_session=True)
            try:
                deadline=time.monotonic()+15
                while not gate.exists() and process.poll() is None and time.monotonic()<deadline:
                    time.sleep(0.01)
                self.assertTrue(gate.exists(),log.read_text()[-1500:])
                conf=decode_native_json(config.read_bytes())
                caller=Path(conf['head_file']);caller_before=caller.read_bytes()
                stopping=time.monotonic();process.terminate()
                terminal=process.wait(timeout=5)
                self.assertLess(time.monotonic()-stopping,5)
                self.assertEqual(terminal,0,log.read_text()[-1500:])
                self.assertEqual((ledger/'journal.json').read_bytes(),before)
                self.assertEqual(caller.read_bytes(),caller_before)
                head=decode_native_json(caller.read_bytes())
                self.assertIsNone(head['pending']);self.assertIsNone(head['outbox'])
                self.assertNotIn('consensus started after received stop',log.read_text())
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,__import__('signal').SIGKILL)
                    process.wait(timeout=5)
                campaign.cleanup()
        # One actual fresh Native read/signal boundary; no all12/full-scope claim.


if __name__ == '__main__':
    unittest.main()
