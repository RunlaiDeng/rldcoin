"""Real SIGTERM at local admission, with native stores and private bytes retained."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from regional_contact_campaign import Campaign, public

BINARY=Path(os.environ['RLD_CONTACT_BINARY']).resolve()


class ContactShutdownTests(unittest.TestCase):
    def exercise(self, stopping, unexpected_stop=False):
        with tempfile.TemporaryDirectory(prefix='rld-contact-shutdown-') as scratch:
            root=Path(scratch).resolve();c=Campaign(BINARY,root/'fixture');gate=root/'admission-ready';log=root/'child.log'
            journal=c.root/'proxima/journal.json';before=journal.read_bytes()
            # This wrapper pauses only the test child at the actual admission.
            # It never changes production timing or performs native progress.
            code='''import sys,time
from pathlib import Path
import interstellar_tcp as tcp
import regional_contact_node as contact
original=tcp.Server._claim_mesh_turn
gate,mode,binary,ledger,authority,currency=sys.argv[1:]
def paused(self,ordinary):
 if ordinary:
  Path(gate).write_text('ordinary admission reached')
  if mode=='stop':
   while self.running:time.sleep(0.005)
  elif mode=='unexpected':self.running=False
  else:raise ValueError('damaged retained evidence test')
 return original(self,ordinary)
tcp.Server._claim_mesh_turn=paused
sys.argv=['contact','--binary',binary,'--ledger',ledger,'--authority',authority,'--currency',currency,'--interval','0.1']
contact.main()
'''
            tools=Path(os.environ.get('RLD_CONTACT_SHUTDOWN_SOURCE',str(Path(__file__).resolve().parent))).resolve()
            self.assertTrue(tools.is_dir())
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(tools))
            with log.open('w') as output:
                mode='stop' if stopping else 'unexpected' if unexpected_stop else 'invalid'
                child=subprocess.Popen([sys.executable,'-B','-c',code,str(gate),mode,str(BINARY),str(c.root/'proxima'),public(1),c.currency],stdout=output,stderr=subprocess.STDOUT,env=env)
                try:
                    deadline=time.monotonic()+10
                    while not gate.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(0.01)
                    self.assertTrue(gate.exists(),log.read_text()[-1200:])
                    if stopping:child.terminate()
                    terminal=child.wait(timeout=10)
                    self.assertEqual(journal.read_bytes(),before)
                    if stopping:self.assertEqual(terminal,0,log.read_text()[-1200:])
                    else:
                        self.assertNotEqual(terminal,0)
                        self.assertIn('TCP runtime is stopping' if unexpected_stop else 'damaged retained evidence test',log.read_text())
                finally:
                    if child.poll() is None:child.kill();child.wait(timeout=10)
                    c.cleanup()

    def test_actual_signal_during_pending_admission_exits_cleanly_without_native_change(self):self.exercise(True)
    def test_nonsignal_evidence_error_still_refuses_and_preserves_native_journal(self):self.exercise(False)
    def test_runtime_stopping_without_received_signal_remains_a_failure(self):self.exercise(False,unexpected_stop=True)


if __name__=='__main__':unittest.main()
