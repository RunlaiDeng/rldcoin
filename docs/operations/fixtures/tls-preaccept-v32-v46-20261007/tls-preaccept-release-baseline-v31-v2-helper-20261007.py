from pathlib import Path
import sys,unittest,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_tcp as tests
from test_interstellar_tcp import mesh,tcp,wire,socket,threading,time,copy,patch,NETWORK
def test_original_tls_connection_waits_for_imminent_slot_release(self):
    source=self.f.servers['earth'];destination=self.f.servers['proxima'];peer=self.f.ids['proxima'];self.f.rounds()
    with self.f.node('earth') as node:
        ident=node.enqueue(self.f.frame(808),peer);original=copy.deepcopy(node.state['messages'][ident])
    clients=[socket.create_connection(destination.address,timeout=2) for _ in range(tcp.MAX_WORKERS)];released=threading.Event();release_thread=None;real_connect=tcp.client_connect;connects=[]
    def release():
        time.sleep(.030)
        for client in clients:client.close()
        released.set()
    def observed_connect(*args,**kwargs):
        nonlocal release_thread
        self.assertIsNone(release_thread);release_thread=threading.Thread(target=release);release_thread.start();started=time.monotonic()
        try:
            connection=real_connect(*args,**kwargs);connects.append(dict(succeeded=True,seconds=time.monotonic()-started));return connection
        except OSError as error:
            connects.append(dict(succeeded=False,error_class=type(error).__name__,seconds=time.monotonic()-started));raise
    try:
        self.await_condition(lambda:len(destination.workers)==tcp.MAX_WORKERS)
        with patch.object(tcp,'client_connect',side_effect=observed_connect):result=source.tick()
    finally:
        for client in clients:client.close()
        if release_thread is not None:release_thread.join()
    self.assertTrue(released.is_set());self.assertEqual(len(connects),1);self.assertLess(connects[0]['seconds'],tcp.ATTEMPT_SECONDS);self.assertEqual(tcp.MAX_WORKERS,2);self.assertEqual(tcp.MAX_LOCAL_LOCK_WAIT_SECONDS,.2);self.assertEqual(tcp.ATTEMPT_SECONDS,3)
    self.capacity_release_result=dict(connection=connects[0],source_errors=result['errors'],refused_connections=destination.report()['refused_connections'],original_slots=tcp.MAX_WORKERS,one_actual_source_tick=True,new_native_calls=0)
    self.assertFalse(result['errors'],'original pinned TLS connection was closed while original2slots freed30ms later inside original.2s local allowance')
    with self.f.node('earth') as node:
        self.assertEqual(node.state['messages'][ident]['packet'],original['packet']);self.assertEqual(node.state['messages'][ident]['routing'],original['routing']);receipt=node.receipts()[ident];self.assertEqual(mesh.receipt_check(receipt,NETWORK),ident);mesh.receipt_matches(receipt,node.state['messages'][ident])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('proxima') as node:
        transit=node.state['messages'][ident];mesh.transit_check(transit,NETWORK,peer,self.f.ids['earth']);self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],self.f.frame(808));self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing']);receipt=node.receipts()[ident];mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),ident);self.assertEqual(len(transit['hops']),1)

class Retained(tests.TcpTests):
 def setUp(self):
  self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/tls-preaccept-release-baseline-v31-v2-private-20261007',names=('earth','proxima'));self.addCleanup(self.f.close)
Retained.test_original_tls_connection_waits_for_imminent_slot_release=test_original_tls_connection_waits_for_imminent_slot_release;test=Retained('test_original_tls_connection_waits_for_imminent_slot_release')
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([test]));print(json.dumps(getattr(test,'capacity_release_result',{})));raise SystemExit(0 if result.wasSuccessful() else 1)
