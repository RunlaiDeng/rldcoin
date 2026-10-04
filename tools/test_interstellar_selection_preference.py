"""Scheduling intent grants no custody; original deadlines and TLS still apply."""
import errno
import tempfile
import threading
import time
import unittest
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from test_interstellar_tcp import Fixture


class SelectionPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name,names=('earth','proxima'))
        self.addCleanup(self.f.close)

    def foreign(self,action):
        results=[]
        def run():
            try:results.append(('ok',action()))
            except BaseException as error:results.append(('error',error))
        thread=threading.Thread(target=run);thread.start();thread.join(5)
        self.assertFalse(thread.is_alive());return results[0]

    def test_foreign_tcp_yields_with_original_bound_and_resumes_after_selection(self):
        server=self.f.servers['earth'];server.request_selection()
        before=(self.f.root/'earth/mesh-state.json').read_bytes()
        def attempt():
            start=time.monotonic()
            try:
                with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS):return 'incorrectly acquired'
            except OSError as error:return error.errno,time.monotonic()-start
        with server.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS):
            kind,result=self.foreign(attempt)
        self.assertEqual(kind,'ok')
        self.assertEqual(result[0],errno.EAGAIN);self.assertLess(result[1],1)
        self.assertEqual((self.f.root/'earth/mesh-state.json').read_bytes(),before)
        self.assertIs(server.selection_owner,threading.current_thread())
        server.finish_selection()
        def opened():
            with server.mesh_node(time.monotonic()+tcp.ATTEMPT_SECONDS) as node:return node.id
        self.assertEqual(self.foreign(opened),('ok',self.f.ids['earth']))

    def test_other_thread_cannot_reassign_or_clear_the_pending_selection(self):
        server=self.f.servers['earth'];server.request_selection()
        for action in (server.request_selection,server.finish_selection):
            kind,error=self.foreign(action);self.assertEqual(kind,'error');self.assertIsInstance(error,ValueError)
            self.assertIs(server.selection_owner,threading.current_thread())
        server.finish_selection();self.assertIsNone(server.selection_owner)

    def test_real_pinned_tls_refusal_preserves_queue_and_retry_gets_actual_receipt(self):
        source=self.f.servers['earth'];destination=self.f.servers['proxima']
        raw=wire.make_frame('source-finality','1'*64,'2'*64,'4'*64,b'{"ground_fixture":true}')
        with mesh.Node(self.f.configs['earth']) as node:ident=node.enqueue(raw,self.f.ids['proxima'])
        destination.request_selection()
        with destination.selection_mesh_node(time.monotonic()+tcp.MAX_LOCAL_LOCK_WAIT_SECONDS) as held:
            result=source.tick()
            self.assertNotIn(ident,held.receipts())
        self.assertTrue(result['errors']);self.assertNotIn(ident,source.suppressed(self.f.ids['proxima']))
        with mesh.Node(self.f.configs['earth']) as node:self.assertIn(ident,node.state['messages'])
        destination.finish_selection();result=source.tick();self.assertEqual(result['errors'],[])
        with mesh.Node(self.f.configs['proxima']) as node:
            receipt=node.receipts()[ident];mesh.receipt_matches(receipt,node.transit(ident))
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_close_clears_intent_and_never_reopens_custody(self):
        server=self.f.servers['earth'];server.request_selection();self.f.stop('earth')
        self.assertIsNone(server.selection_owner)
        with self.assertRaisesRegex(ValueError,'stopping'):server.request_selection()


if __name__=='__main__':unittest.main()
