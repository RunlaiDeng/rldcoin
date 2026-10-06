from pathlib import Path
import hashlib,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';p=r/'tools/interstellar_tcp.py';m=r/'tools/interstellar_mesh.py';t=r/'tools/test_interstellar_tcp.py';sha=lambda s:hashlib.sha256(s.encode()).hexdigest();old=p.read_text();oldmesh=m.read_text();oldtests=t.read_text()
for name,s in (('tcp-before-input-release-wake-v27-20261007.py',old),('mesh-before-input-release-wake-v27-20261007.py',oldmesh),('tests-before-input-release-wake-v27-20261007.py',oldtests)):
 z=b/name;assert not z.exists();z.write_text(s)
a="            self.local_mesh_owner=None\n\n    @contextmanager";z="""            self.local_mesh_owner=None
            # A retained original input already has a live bounded waiter. Its
            # existing event follows an actual lease release instead of waiting
            # out the polling interval. No new slot, queue or custody is granted.
            input_owner=getattr(self,'input_thread',None)
            if (getattr(self,'running',False) and input_owner is not threading.current_thread()
                    and input_owner in getattr(self,'tcp_mesh_waiters',())
                    and getattr(self,'input_active',None) is not None and input_owner.is_alive()):
                self.input_wake.set()

    @contextmanager"""
assert old.count(a)==1;s=old.replace(a,z);assert s.replace(z,a,1)==old;compile(s,str(p),'exec');p.write_text(s)
newmesh=oldmesh.replace('RLD-CONTACT-TRANSIT-SCHEDULER-V26','RLD-CONTACT-TRANSIT-SCHEDULER-V27');assert newmesh!=oldmesh;m.write_text(newmesh)
addition='''

class InputReleaseWakeTests(unittest.TestCase):
    def server(self):
        server=object.__new__(tcp.Server);server.guard=threading.Lock()
        server.running=True;server.input_wake=threading.Event()
        server.input_active=('original-unacknowledged-input-model',)
        server.tcp_mesh_waiters=set();server.local_mesh_owner=threading.current_thread()
        return server

    def test_actual_waiting_input_wakes_on_other_original_lease_release(self):
        server=self.server();ready=threading.Event();done=threading.Event();observed=[]
        def waiting_input():
            with server.guard:server.tcp_mesh_waiters.add(threading.current_thread())
            ready.set();observed.append(server.input_wake.wait(.25));done.set()
        thread=threading.Thread(target=waiting_input,name='rld-input-release-wake-test')
        server.input_thread=thread;thread.start();self.assertTrue(ready.wait(1))
        try:
            server._release_mesh_turn();self.assertIsNone(server.local_mesh_owner)
            self.assertTrue(done.wait(.1));self.assertEqual(observed,[True])
            self.assertEqual(server.input_active,('original-unacknowledged-input-model',))
            self.assertEqual(server.tcp_mesh_waiters,{thread})
        finally:
            server.input_wake.set();thread.join(1);self.assertFalse(thread.is_alive())

    def test_release_does_not_wake_absent_job_waiter_stopped_or_self_owner(self):
        for mode in ('no-job','no-waiter','stopped','self'):
            with self.subTest(mode=mode):
                server=self.server();other=threading.Thread(target=lambda:None)
                server.input_thread=threading.current_thread() if mode=='self' else other
                server.tcp_mesh_waiters={server.input_thread} if mode!='no-waiter' else set()
                if mode=='no-job':server.input_active=None
                if mode=='stopped':server.running=False
                server._release_mesh_turn();self.assertIsNone(server.local_mesh_owner)
                self.assertFalse(server.input_wake.is_set())

    def test_wrong_release_owner_cannot_clear_lease_or_signal_input(self):
        server=self.server();other=threading.Thread(target=lambda:None)
        server.input_thread=other;server.local_mesh_owner=other;server.tcp_mesh_waiters={other}
        with self.assertRaises(ValueError):server._release_mesh_turn()
        self.assertIs(server.local_mesh_owner,other);self.assertFalse(server.input_wake.is_set())
'''
marker="\nif __name__=='__main__':";assert oldtests.count(marker)==1;newtests=oldtests.replace(marker,addition+marker);compile(newtests,str(t),'exec');t.write_text(newtests)
report=b/'input-release-wake-v27-reversal-20261007.json';assert not report.exists();report.write_text(json.dumps(dict(tcp_replacement=[a,z],tcp_original_sha256=sha(old),tcp_candidate_sha256=sha(s),tcp_whole_source_reversal=True,mesh_profile_only=True,mesh_original_sha256=sha(oldmesh),mesh_candidate_sha256=sha(newmesh),tests_addition=addition,tests_original_sha256=sha(oldtests),tests_candidate_sha256=sha(newtests),all_original_test_text_exact=True),indent=2)+'\n');print(report)
