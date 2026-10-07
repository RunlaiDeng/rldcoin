"""Actual loopback sockets: multi-hop custody, restart and hostile admission."""
import copy
import datetime
import ssl
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire

NETWORK = 'a'*64


class Fixture:
    def __init__(self, root, names=('earth','proxima','andromeda'), edges=None, insecure=False):
        self.root=Path(root).resolve()
        self.names=list(names)
        self.ids={n:mesh.initialize(self.root/n,NETWORK,str(i+1)*64,n)['node_id']
            for i,n in enumerate(names)}
        self.insecure=insecure
        self.pins={n:tcp.public_tls_identity({'format':mesh.VERSION,'state':str(self.root/n),
            'network':NETWORK,'contacts':[]})['tls_cert_sha256'] for n in names}
        self.ports={}
        self.servers={}
        held=[]
        try:
            for name in names:
                s=socket.socket()
                s.bind(('127.0.0.1',0))
                held.append(s)
                self.ports[name]=s.getsockname()[1]
            self.configs={n:{'format':mesh.VERSION,'state':str(self.root/n),
                'network':NETWORK,'contacts':[]} for n in names}
            for a,b in edges or list(zip(names,names[1:])):
                for source,target in [(a,b),(b,a)]:
                    c={'peer':self.ids[target],'host':'127.0.0.1','port':self.ports[target]}
                    if not insecure:
                        c['tls_cert_sha256']=self.pins[target]
                    self.configs[source]['contacts'].append(c)
        finally:
            for s in held:
                s.close()
        for name in names:
            self.start(name)

    def start(self,name):
        self.servers[name]=tcp.Server(self.configs[name],('127.0.0.1',self.ports[name]),insecure=self.insecure)

    def stop(self,name):
        self.servers.pop(name).close()

    def close(self):
        for name in list(self.servers):
            self.stop(name)

    def rounds(self,count=5):
        for _ in range(count):
            for server in list(self.servers.values()):
                server.tick()

    def node(self,name):
        return mesh.Node(self.configs[name])

    def frame(self,index=0):
        return wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,
            wire.canonical({'ground_fixture':index,'ledger_validation':'required'}))


class TcpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name)
        self.addCleanup(self.f.close)

    def connect(self,target='proxima'):
        deadline=time.monotonic()+tcp.ATTEMPT_SECONDS
        c=tcp.client_connect(self.f.servers[target].address,self.f.pins[target],NETWORK,self.f.ids[target],deadline)
        try:
            nonce=tcp.check_challenge(tcp.receive(c,deadline),NETWORK,self.f.ids[target],self.f.pins[target])
            return c,nonce
        except BaseException:
            c.close()
            raise

    def bind(self,value,nonce):
        name=next((n for n in self.f.names if self.f.ids[n]==value['body']['node_id']),None)
        if name:
            with self.f.node(name) as node:
                bound=mesh.sign(node.key,'tcp-request',{**value['body'],'challenge':nonce})
            value.clear()
            value.update(bound)
        return value

    def exchange(self,value,target='proxima',bind=True):
        c,nonce=self.connect(target)
        with c:
            deadline=time.monotonic()+tcp.ATTEMPT_SECONDS
            if bind:
                self.bind(value,nonce)
            tcp.send(c,value,deadline)
            return tcp.receive(c,deadline)

    def sent(self):
        with self.f.node('earth') as node:
            return tcp.request(node,self.f.ids['proxima'],'0'*64)

    def await_condition(self,condition):
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            if condition():
                return
            time.sleep(0.01)
        self.fail('bounded socket test observation timeout')

    def test_actual_two_hop_transfer_receipt_and_restart_without_shared_spools(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            self.assertEqual(node.route(self.f.ids['andromeda']),[self.f.ids[n] for n in self.f.names])
            raw=self.f.frame()
            ident=node.enqueue(raw,self.f.ids['andromeda'])
        self.f.rounds()
        self.f.stop('andromeda')
        self.f.start('andromeda')
        self.f.rounds(1)
        with self.f.node('andromeda') as node:
            self.assertEqual(len(node.state['messages'][ident]['hops']),2)
            target=self.f.root/'received.frame.json'
            node.export_received(ident,target)
            self.assertEqual(target.read_bytes(),raw)
            self.assertFalse(node.status()['payment_authorized'])
        with self.f.node('earth') as node:
            self.assertEqual(node.status()['messages'][ident],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            self.assertIn(ident,node.state['messages'])
        self.assertFalse((self.f.root/'links').exists())
        for name,server in self.f.servers.items():
            self.assertTrue(server.report()['observations'])
            self.assertTrue(all('host' in c and 'inbox' not in c for c in self.f.configs[name]['contacts']))

    def test_brief_local_lock_contention_recovers_in_the_same_authenticated_connection(self):
        self.f.rounds()
        raw=self.f.frame(901)
        with self.f.node('earth') as node:ident=node.enqueue(raw,self.f.ids['proxima'])
        server=self.f.servers['proxima'];before=server.report()['local_lock_retries']
        held=self.f.node('proxima');results=[]
        thread=threading.Thread(target=lambda:results.append(self.f.servers['earth'].tick()))
        try:
            thread.start()
            self.await_condition(lambda:server.report()['local_lock_retries']>before)
        finally:
            held.close();thread.join(timeout=tcp.ATTEMPT_SECONDS+2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]['errors'],[])
        with self.f.node('proxima') as node:
            self.assertIn(ident,node.state['receipts'])
            self.assertEqual(mesh.transit_check(node.state['messages'][ident],NETWORK)[1],raw)
            self.assertFalse(node.status()['payment_authorized'])
        with self.f.node('earth') as node:self.assertIn(ident,node.state['receipts'])

    def test_exhausted_local_lock_wait_refuses_without_custody_then_fresh_attempt_recovers(self):
        self.f.rounds()
        with self.f.node('earth') as node:ident=node.enqueue(self.f.frame(902),self.f.ids['proxima'])
        server=self.f.servers['proxima'];before=server.report()['local_lock_exhaustions']
        with self.f.node('proxima') as held:
            retained=held.path.read_bytes()
            started=time.monotonic();result=self.f.servers['earth'].tick()
            self.assertLess(time.monotonic()-started,tcp.ATTEMPT_SECONDS)
            self.assertTrue(result['errors'])
            self.assertEqual(held.path.read_bytes(),retained)
            self.assertNotIn(ident,held.state['messages'])
        self.assertEqual(server.report()['local_lock_exhaustions'],before+1)
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages']);self.assertNotIn(ident,node.state['receipts'])
        self.f.rounds(1)
        with self.f.node('proxima') as node:self.assertIn(ident,node.state['receipts'])

    def test_disconnected_middle_and_sender_restart_retain_then_resume(self):
        self.f.rounds()
        self.f.stop('proxima')
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['andromeda'])
        self.assertTrue(self.f.servers['earth'].tick()['errors'])
        self.f.stop('earth')
        self.f.start('earth')
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])
        self.f.start('proxima')
        self.f.rounds()
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['receipts'])

    def test_added_alternate_socket_route_delivers_after_preferred_relay_stops(self):
        f=Fixture(self.f.root/'diamond',('source','left','right','destination'),
            [('source','left'),('left','destination'),('source','right'),('right','destination')])
        self.addCleanup(f.close)
        f.stop('right')
        f.rounds()
        with f.node('source') as node:
            self.assertEqual(len(node.state['adverts']),3)
        f.start('right')
        f.rounds()
        with f.node('source') as node:
            self.assertEqual(len(node.state['adverts']),4)
            preferred=node.route(f.ids['destination'])[1]
            ident=node.enqueue(f.frame(),f.ids['destination'])
        stopped=next(n for n in ('left','right') if f.ids[n]==preferred)
        f.stop(stopped)
        f.rounds()
        with f.node('destination') as node:
            self.assertIn(ident,node.state['receipts'])
            self.assertNotIn(preferred,mesh.transit_check(node.state['messages'][ident],NETWORK)[2])

    def test_verified_hop_suppression_retains_evidence_and_reprobes_after_restart(self):
        self.f.rounds()
        self.f.stop('andromeda')
        peer=self.f.ids['proxima'];server=self.f.servers['earth']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(701),self.f.ids['andromeda'])
        self.assertFalse(server.tick()['errors'])
        self.assertTrue(server.suppressed(peer))
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])
            self.assertEqual(len(node.exchange(peer)['body']['transits']),1)
            self.assertEqual(node.exchange(peer,server.suppressed(peer))['body']['transits'],[])
        sent=[];original=tcp.send
        def observe(connection,value,deadline):
            body=value['body']
            if body.get('node_id')==self.f.ids['earth'] and 'bundle' in body and 'accepted' not in body:
                sent.append(len(body['bundle']['body']['transits']))
            return original(connection,value,deadline)
        with patch.object(tcp,'send',side_effect=observe):
            self.assertFalse(server.tick()['errors'])
            with server.guard:server.peer_attempts[peer]=63
            self.assertFalse(server.tick()['errors'])
        self.assertEqual(sent,[0,1])
        self.f.stop('earth');self.f.start('earth')
        self.assertEqual(self.f.servers['earth'].suppressed(peer),set())
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_unverified_reply_or_failed_local_custody_never_suppresses_retry(self):
        self.f.rounds();self.f.stop('andromeda')
        peer=self.f.ids['proxima'];server=self.f.servers['earth']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(702),self.f.ids['andromeda'])
        with patch.object(tcp,'check_response',side_effect=ValueError('injected lost/unverified reply')):
            self.assertTrue(server.tick()['errors'])
        self.assertEqual(server.suppressed(peer),set())
        receive=mesh.Node.receive
        def fail(node,*args,**kwargs):
            if node.id==self.f.ids['earth']:raise OSError('injected local reply custody failure')
            return receive(node,*args,**kwargs)
        with patch.object(mesh.Node,'receive',new=fail):
            self.assertTrue(server.tick()['errors'])
        self.assertEqual(server.suppressed(peer),set())
        self.assertFalse(server.tick()['errors'])
        self.assertTrue(server.suppressed(peer))
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_duplex_concurrent_contacts_do_not_hold_mesh_locks_across_waits(self):
        errors=[]
        threads=[threading.Thread(target=lambda s=s:errors.extend(s.tick()['errors']))
            for s in self.f.servers.values()]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=8)
            self.assertFalse(thread.is_alive(),'cross-node lock deadlock')
        # A simultaneous local writer may conservatively refuse; retry succeeds.
        self.f.rounds()
        with self.f.node('earth') as node:
            self.assertEqual(len(node.state['adverts']),3)

    def test_failed_batch_replays_once_then_returns_to_ordinary_rotation(self):
        self.f.rounds()
        server=self.f.servers['earth'];peer=self.f.ids['proxima'];batches=[]
        with self.f.node('earth') as node:
            original={node.enqueue(self.f.frame(810+i),self.f.ids['andromeda']) for i in range(8)}
        outgoing=tcp.outgoing
        def recorded(node,*args,**kwargs):
            bundle=outgoing(node,*args,**kwargs)
            batches.append(tuple(mesh.digest(t['packet']) for t in bundle['body']['transits']))
            return bundle
        with patch.object(tcp,'outgoing',side_effect=recorded),patch.object(tcp,'client_connect',side_effect=OSError('lost before send')):
            for _ in range(3):self.assertTrue(server.tick()['errors'])
        self.assertEqual(len(batches[0]),4)
        self.assertEqual(batches[1],batches[0])
        self.assertTrue(set(batches[2])-set(batches[0]))
        self.assertEqual(server.suppressed(peer),set())
        with self.f.node('earth') as node:
            self.assertTrue(original<=set(node.state['messages']))
            self.assertFalse(original & set(node.receipts()))

    def test_failed_local_preparation_preserves_waiting_replay(self):
        self.f.rounds()
        server=self.f.servers['earth'];peer=self.f.ids['proxima']
        with self.f.node('earth') as node:ident=node.enqueue(self.f.frame(820),peer)
        with patch.object(tcp,'client_connect',side_effect=OSError('lost before send')):
            self.assertTrue(server.tick()['errors'])
        with self.f.node('earth') as node:self.assertEqual(node.failed_carriage(peer),(ident,))
        with patch.object(tcp,'outgoing',side_effect=OSError('preparation did not commit')):
            self.assertTrue(server.tick()['errors'])
        with self.f.node('earth') as node:self.assertEqual(node.failed_carriage(peer),(ident,))
        self.assertFalse(server.tick()['errors'])
        with self.f.node('earth') as node:
            self.assertEqual(node.failed_carriage(peer),())
            self.assertIn(ident,node.receipts())

    def test_cold_outbound_preparation_precedes_connection_and_keeps_fresh_challenge(self):
        self.f.rounds()
        server=self.f.servers['earth'];peer=self.f.ids['proxima']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(703),peer)
        outgoing=tcp.outgoing;connect=tcp.client_connect;events=[]
        def cold(node,*args,**kwargs):
            if node.id==server.id:
                events.append('preparing')
                time.sleep(1.1)
            result=outgoing(node,*args,**kwargs)
            if node.id==server.id:events.append('prepared')
            return result
        def admitted(*args,**kwargs):
            events.append('connect')
            # The configured origin is unlocked before any socket wait.
            with mesh.Node(self.f.configs['earth'],nonblocking=True):pass
            return connect(*args,**kwargs)
        with patch.object(tcp,'ATTEMPT_SECONDS',1.0),patch.object(tcp,'outgoing',side_effect=cold),patch.object(tcp,'client_connect',side_effect=admitted):
            report=server.tick()
        self.assertEqual(report['errors'],[])
        self.assertEqual(events,['preparing','prepared','connect'])
        with self.f.node('earth') as node:
            self.assertIn(ident,node.receipts())
        with self.f.node('proxima') as node:
            self.assertIn(ident,node.receipts())

    def test_response_loss_new_connection_retry_deduplicates_exact_packet_custody(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        sent=self.sent()
        c,nonce=self.connect()
        with c:
            self.bind(sent,nonce)
            tcp.send(c,sent,time.monotonic()+tcp.ATTEMPT_SECONDS)
            # Sender disappears before reading an acknowledgment.
        path=self.f.root/'proxima/mesh-state.json'
        self.await_condition(lambda:ident in mesh.load(path,mesh.MAX_STATE)['messages'])
        response=self.exchange(sent)
        tcp.check_response(response,NETWORK,self.f.ids['earth'],self.f.ids['proxima'],sent)
        with self.f.node('proxima') as node:
            self.assertEqual(list(node.state['messages']),[ident])
            self.assertIn(ident,node.state['receipts'])
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_wrong_nonce_recipient_network_and_identity_cannot_acknowledge(self):
        sent=self.sent()
        response=self.exchange(sent)
        body=response['body']
        with self.f.node('proxima') as node:
            for field,value in [('nonce','f'*64),('to',self.f.ids['andromeda']),('network','f'*64),
                    ('exchange_id','e'*64),('accepted','true')]:
                forged=mesh.sign(node.key,'tcp-response',{**body,field:value})
                with self.assertRaises(ValueError):
                    tcp.check_response(forged,NETWORK,self.f.ids['earth'],node.id,sent)
        with self.f.node('andromeda') as node:
            forged=mesh.sign(node.key,'tcp-response',{**body,'node_id':node.id})
        with self.assertRaises(ValueError):
            tcp.check_response(forged,NETWORK,self.f.ids['earth'],self.f.ids['proxima'],sent)
        newer=self.sent()
        with self.assertRaises(ValueError):
            tcp.check_response(response,NETWORK,self.f.ids['earth'],self.f.ids['proxima'],newer)

    def test_unconfigured_peer_tamper_and_oversize_frame_leave_receiver_unchanged(self):
        sent=self.sent()
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        with self.f.node('earth') as node:
            wrong_to=mesh.sign(node.key,'tcp-request',{**sent['body'],'to':self.f.ids['andromeda']})
            wrong_net=mesh.sign(node.key,'tcp-request',{**sent['body'],'network':'f'*64})
        with self.f.node('andromeda') as node:
            forged=mesh.sign(node.key,'tcp-request',{**sent['body'],'node_id':node.id})
        # Andromeda is a configured neighbor of Proxima; Earth cannot impersonate it.
        tamper=copy.deepcopy(sent)
        tamper['body']['bundle']['body']['adverts'][0]['body']['label']='forged'
        stranger=mesh.initialize(self.f.root/'stranger',NETWORK,'f'*64,'stranger')
        # The stranger may pin Proxima for its own outgoing request; Proxima
        # has never admitted the stranger and must still refuse its request.
        config={'format':mesh.VERSION,'state':str(self.f.root/'stranger'),'network':NETWORK,
                'contacts':[{'peer':self.f.ids['proxima'],'host':'127.0.0.1',
                             'port':self.f.ports['proxima'],'tls_cert_sha256':self.f.pins['proxima']}]}
        with mesh.Node(config) as node:
            unknown=tcp.request(node,self.f.ids['proxima'],'0'*64)
        self.assertNotIn(stranger['node_id'],self.f.servers['proxima'].peers)
        for value in (wrong_to,wrong_net,forged,tamper,unknown):
            with self.assertRaises((OSError,ValueError)):
                self.exchange(value)
        c,_=self.connect()
        with c:
            c.sendall(struct.pack('!I',tcp.MAX_WIRE+1))
            self.assertEqual(c.recv(1),b'')
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())

    def test_busy_receiver_or_failed_commit_refuses_ack_and_keeps_evidence(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        sent=self.sent()
        with self.f.node('proxima') as node:
            before=node.path.read_bytes()
            response=self.exchange(sent)
            self.assertFalse(response['body']['accepted'])
            self.assertEqual(before,node.path.read_bytes())
        original=mesh.atomic
        target=self.f.root/'proxima/mesh-state.json'
        def fail_custody(path,value):
            if Path(path)==target and ident in value.get('messages',{}):
                raise OSError('injected durable write failure')
            return original(path,value)
        with patch.object(mesh,'atomic',side_effect=fail_custody):
            response=self.exchange(sent)
            self.assertFalse(response['body']['accepted'])
        self.assertEqual(before,target.read_bytes())
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
        self.f.rounds()
        with self.f.node('proxima') as node:
            self.assertIn(ident,node.state['receipts'])

    def test_bounded_capacity_refusal_preserves_prior_state_and_source_queue(self):
        self.f.rounds()
        with self.f.node('proxima') as node:
            node.enqueue(self.f.frame(1),'b'*64)
            before=node.path.read_bytes()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(2),self.f.ids['proxima'])
        sent=self.sent()
        with patch.object(mesh,'MAX_MESSAGES',1):
            response=self.exchange(sent)
        self.assertFalse(response['body']['accepted'])
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_tls_capacity_connect_failure_retains_original_and_replays_after_release(self):
        from regional_contact_trace import ContactTrace
        self.f.rounds()
        source=self.f.servers['earth'];destination=self.f.servers['proxima']
        peer=self.f.ids['proxima'];trace=ContactTrace();trace.bind(NETWORK,self.f.ids['earth'])
        source.contact_trace=trace
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(801),self.f.ids['andromeda'])
            original=copy.deepcopy(node.state['messages'][ident])
        # Two real unauthenticated TLS handshakes occupy the original slots.
        # No packet/request/receipt is acknowledged by opening a raw socket.
        clients=[socket.create_connection(destination.address,timeout=2) for _ in range(tcp.MAX_WORKERS)]
        before=destination.report()['refused_connections'];failures=[]
        real_connect=tcp.client_connect
        def observed_connect(*args,**kwargs):
            started=time.monotonic()
            try:return real_connect(*args,**kwargs)
            except OSError as error:
                failures.append((type(error).__name__,time.monotonic()-started))
                raise
        try:
            self.await_condition(lambda:len(destination.workers)==tcp.MAX_WORKERS)
            with patch.object(tcp,'client_connect',side_effect=observed_connect):result=source.tick()
            self.assertTrue(result['errors'])
            self.await_condition(lambda:destination.report()['refused_connections']==before+1)
            self.assertEqual(len(failures),1)
            events=trace.snapshot()['events']
            refused=[v for v in events if v['stage']=='outgoing_failed' and v.get('packet_id')==ident]
            self.assertEqual(len(refused),1)
            self.assertEqual(refused[0]['failure_stage'],'connect')
            self.assertEqual(refused[0]['error_class'],failures[0][0])
            self.assertFalse(any(v['stage']=='request_sent' and v.get('packet_id')==ident for v in events))
            with self.f.node('earth') as node:
                self.assertEqual(node.state['messages'][ident],original)
                self.assertNotIn(ident,node.receipts())
                self.assertEqual(node.failed_carriage(peer),(ident,))
            self.assertFalse(source.suppressed(peer))
        finally:
            for client in clients:client.close()
        self.await_condition(lambda:not destination.workers)
        self.assertFalse(source.tick()['errors'])
        self.assertTrue(source.suppressed(peer))
        with self.f.node('proxima') as node:
            packet,raw,visited=mesh.transit_check(node.transit(ident),NETWORK)
            self.assertEqual(raw,self.f.frame(801))
            self.assertEqual(visited[-1],peer)
            self.assertNotIn(ident,node.receipts())  # next-hop custody is not final-destination receipt
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'][ident],original)
            self.assertEqual(node.failed_carriage(peer),())
            self.assertNotIn(ident,node.receipts())
        self.capacity_observation=dict(connect_exception=failures[0][0],
            connect_failure_seconds=failures[0][1],original_inbound_slots=tcp.MAX_WORKERS,
            source_original_retained=True,unacknowledged_refusal=True,
            exact_one_replay_after_slot_release=True,pinned_tls_next_hop_custody=True,
            destination_receipt_or_native_authority=False)

    def test_bounded_workers_oversize_and_incomplete_input_close_cleanly(self):
        server=self.f.servers['proxima']
        clients=[socket.create_connection(server.address,timeout=2) for _ in range(tcp.MAX_WORKERS)]
        for c in clients:
            self.addCleanup(c.close)
            c.sendall(b'\x00')
        self.await_condition(lambda:len(server.workers)==tcp.MAX_WORKERS)
        with socket.create_connection(server.address,timeout=2) as c:
            self.assertEqual(c.recv(1),b'')
        self.await_condition(lambda:server.report()['refused_connections']==1)
        server.close()
        self.assertFalse(server.thread.is_alive())
        self.assertFalse(server.workers)
        self.assertFalse(server.connections)

    def test_more_than_one_batch_rotates_and_delivers_all_retained_packets(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ids=[node.enqueue(self.f.frame(i),self.f.ids['andromeda']) for i in range(11)]
        self.f.rounds(14)
        with self.f.node('earth') as node:
            self.assertEqual(set(ids),set(node.state['receipts']))
            self.assertEqual(set(ids),set(node.state['messages']))

    def test_operator_endpoint_schema_rejects_dns_urls_ipv6_and_zero_contact_port(self):
        for host,port in [('localhost',1000),('https://example.com',80),('::1',1000),
                ('127.0.0.1',0),('0.0.0.0',1000),('224.0.0.1',1000),('127.0.0.1',True)]:
            config=copy.deepcopy(self.f.configs['earth'])
            config['contacts'][0].update(host=host,port=port)
            with self.assertRaises(ValueError):
                mesh.Node(config)

    def test_deep_invalid_json_is_rejected_and_listener_still_accepts_valid_exchange(self):
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        raw=b'['*2000+b'0'+b']'*2000
        c,_=self.connect()
        with c:
            c.sendall(struct.pack('!I',len(raw))+raw)
            self.assertEqual(c.recv(1),b'')
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())
        response=self.exchange(self.sent())
        self.assertTrue(response['body']['accepted'])

    def test_tls13_is_default_and_certificate_key_survives_restart(self):
        server=self.f.servers['proxima']
        before=(self.f.root/'proxima/tcp-tls.private.pem').read_bytes()
        pin=server.fingerprint
        c,_=self.connect()
        with c:
            self.assertEqual(c.version(),'TLSv1.3')
            self.assertIsNotNone(c.cipher())
        self.f.stop('proxima')
        self.f.start('proxima')
        self.assertEqual(before,(self.f.root/'proxima/tcp-tls.private.pem').read_bytes())
        report=self.f.servers['proxima'].tick()
        self.assertEqual(report['tls_cert_sha256'],pin)
        self.assertTrue(report['encrypted'])
        self.assertFalse(report['fallback_to_plaintext'])

    def test_missing_pin_or_plaintext_selection_for_pinned_peer_refuses_startup(self):
        config=copy.deepcopy(self.f.configs['earth'])
        config['contacts'][0].pop('tls_cert_sha256')
        with self.assertRaisesRegex(ValueError,'pin required'):
            tcp.Server(config)
        with self.assertRaisesRegex(ValueError,'no fallback'):
            tcp.Server(self.f.configs['earth'],insecure=True)

    def test_wrong_certificate_pin_retains_source_and_sends_no_payment_evidence(self):
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        self.f.servers['earth'].peers[self.f.ids['proxima']]['tls_cert_sha256']='f'*64
        result=self.f.servers['earth'].tick()
        self.assertTrue(any('pin mismatch' in e for e in result['errors']))
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_tls12_and_plaintext_cannot_downgrade_default_listener(self):
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False
        context.verify_mode=ssl.CERT_NONE
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
        raw=socket.create_connection(self.f.servers['proxima'].address,timeout=2)
        with self.assertRaises(ssl.SSLError):
            context.wrap_socket(raw,server_hostname=None)
        raw.close()
        with socket.create_connection(self.f.servers['proxima'].address,timeout=2) as c:
            sent=self.sent()
            tcp.send(c,sent,time.monotonic()+2)
            with self.assertRaises((OSError,ValueError)):
                tcp.receive(c,time.monotonic()+2)
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())
        self.assertTrue(self.exchange(self.sent())['body']['accepted'])

    def test_captured_authenticated_request_cannot_replay_on_another_tls_connection(self):
        sent=self.sent()
        response=self.exchange(sent)
        self.assertTrue(response['body']['accepted'])
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        with self.assertRaises((OSError,ValueError)):
            self.exchange(sent,bind=False)
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())

    def test_signed_challenge_wrong_identity_network_certificate_and_nonce_refused(self):
        with self.f.node('proxima') as node:
            value=tcp.challenge(node.key,NETWORK,node.id,self.f.pins['proxima'])
            for field,changed in [('network','b'*64),('node_id',self.f.ids['earth']),
                    ('tls_cert_sha256','f'*64),('nonce',1)]:
                wrong=mesh.sign(node.key,'tcp-challenge',{**value['body'],field:changed})
                with self.assertRaises(ValueError):
                    tcp.check_challenge(wrong,NETWORK,self.f.ids['proxima'],self.f.pins['proxima'])

    def test_expired_certificate_blocks_contact_without_dropping_queued_evidence(self):
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        before=(self.f.root/'proxima/mesh-state.json').read_bytes()
        original=tcp.certificate_check
        def expired(cert,network,peer,now=None):
            return original(cert,network,peer,cert.not_valid_after_utc+datetime.timedelta(seconds=1))
        with patch.object(tcp,'certificate_check',side_effect=expired):
            report=self.f.servers['earth'].tick()
        self.assertTrue(any('validity' in e for e in report['errors']))
        self.assertEqual(before,(self.f.root/'proxima/mesh-state.json').read_bytes())
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['messages'])
            self.assertNotIn(ident,node.state['receipts'])

    def test_corrupt_private_tls_material_is_preserved_and_not_replaced(self):
        self.f.stop('proxima')
        path=self.f.root/'proxima/tcp-tls.private.pem'
        path.write_bytes(b'partial private TLS commit')
        with self.assertRaises(ValueError):
            self.f.start('proxima')
        self.assertEqual(path.read_bytes(),b'partial private TLS commit')

    def test_private_tls_permissions_symlink_and_key_pair_mismatch_refused(self):
        self.f.stop('proxima')
        path=self.f.root/'proxima/tcp-tls.private.pem'
        original=path.read_bytes()
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'permissions'):
            self.f.start('proxima')
        self.assertEqual(path.read_bytes(),original)
        path.chmod(0o600)
        other=self.f.root/'copy-of-private.pem'
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(ValueError):
            self.f.start('proxima')
        path.unlink()
        other.rename(path)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography import x509
        cert=x509.load_pem_x509_certificate(original)
        wrong=cert.public_bytes(serialization.Encoding.PEM)+Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        path.write_bytes(wrong)
        with self.assertRaisesRegex(ValueError,'key/certificate mismatch'):
            self.f.start('proxima')
        self.assertEqual(path.read_bytes(),wrong)

    def test_explicit_plaintext_ground_mode_still_requires_fresh_signed_challenge(self):
        f=Fixture(self.f.root/'plaintext',('left','right'),insecure=True)
        self.addCleanup(f.close)
        with f.node('left') as node:
            ident=node.enqueue(f.frame(),f.ids['right'])
        f.rounds(3)
        with f.node('left') as node:
            self.assertIn(ident,node.state['receipts'])
        report=f.servers['left'].tick()
        self.assertFalse(report['encrypted'])
        self.assertTrue(report['plaintext_selected_explicitly'])
        self.assertFalse(report['fallback_to_plaintext'])

    def test_actual_proxy_wire_is_tls_ciphertext_while_exact_packet_is_delivered(self):
        listener=socket.socket()
        listener.bind(('127.0.0.1',0))
        listener.listen(1)
        listener.settimeout(3)
        self.addCleanup(listener.close)
        recorded=[]
        errors=[]
        def proxy():
            try:
                incoming,_=listener.accept()
                outgoing=socket.create_connection(self.f.servers['proxima'].address,timeout=3)
                def pump(source,target):
                    try:
                        while True:
                            data=source.recv(65536)
                            if not data:
                                break
                            recorded.append(data)
                            if sum(map(len,recorded))>256*1024:
                                raise ValueError('test proxy capture bound')
                            target.sendall(data)
                    except OSError:
                        pass
                    finally:
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                with incoming,outgoing:
                    upstream=threading.Thread(target=pump,args=(incoming,outgoing))
                    downstream=threading.Thread(target=pump,args=(outgoing,incoming))
                    upstream.start()
                    downstream.start()
                    upstream.join(timeout=4)
                    downstream.join(timeout=4)
            except Exception as error:
                errors.append(error)
        thread=threading.Thread(target=proxy)
        thread.start()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.ids['proxima'])
        self.f.servers['earth'].peers[self.f.ids['proxima']]['port']=listener.getsockname()[1]
        result=self.f.servers['earth'].tick()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertFalse(result['errors'])
        captured=b''.join(recorded)
        self.assertGreater(len(captured),100)
        self.assertNotIn(b'"format":"RLD-CONTACT-MESH-V1"',captured)
        self.assertNotIn(b'"adapter":"RLD-CONTACT-TCP-V2"',captured)
        self.assertNotIn(b'"bundle":',captured)
        with self.f.node('proxima') as node:
            self.assertIn(ident,node.state['receipts'])
        with self.f.node('earth') as node:
            self.assertIn(ident,node.state['receipts'])




    def test_authenticated_refusal_hands_off_after_busy_original_input_slot_releases(self):
        from contextlib import contextmanager
        self.f.rounds()
        server=self.f.servers['proxima'];gate=threading.Event();held=None
        original=tcp.Server.mesh_node
        @contextmanager
        def pause_for_original_slot(runtime,deadline):
            if runtime is server and threading.current_thread() is runtime.input_thread:
                self.assertTrue(gate.wait(tcp.ATTEMPT_SECONDS),'input test owner exceeded budget')
            with original(runtime,deadline) as node:yield node
        try:
            with patch.object(tcp.Server,'mesh_node',pause_for_original_slot):
                held=self.f.node('proxima')
                with self.f.node('earth') as node:node.enqueue(self.f.frame(991),self.f.ids['proxima'])
                self.assertTrue(self.f.servers['earth'].tick()['errors'])
                self.await_condition(lambda:server.input_active is not None)
                before=server.input_received
                with self.f.node('earth') as node:
                    raw=self.f.frame(992);ident=node.enqueue(raw,self.f.ids['proxima'])
                self.assertTrue(self.f.servers['earth'].tick()['errors'])
                self.assertEqual(server.input_received,before)
                self.assertNotIn(ident,held.state['messages'])
                time.sleep(.04)
                held.close();held=None;gate.set()
                self.await_condition(lambda:server.input_received==before+1)
                self.await_condition(lambda:server.input_active is None and not server.input_pending)
            with self.f.node('proxima') as node:
                self.assertIn(ident,node.state['receipts'])
                self.assertEqual(mesh.transit_check(node.state['messages'][ident],NETWORK)[1],raw)
                self.assertFalse(node.status()['payment_authorized'])
        finally:
            if held is not None:held.close()
            gate.set()

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


class DeferredAdmissionTests(unittest.TestCase):
    def admission(self,release_at=None,deadline=3.0,stop_at=None,raise_on_wait=False,empty=False):
        server=object.__new__(tcp.Server)
        owner=threading.current_thread();job=('network','recipient','peer','pin','challenge',b'authenticated-input-model')
        server.guard=threading.Lock();server.workers={owner};server.input_pending=[]
        server.input_active=None if empty else ('older-input',)
        server.running=True;server.input_received=0;server.input_wake=threading.Event()
        clock=[0.0];occupancy=[]
        def release_deferred_slot_clock(seconds):
            self.assertIn(owner,server.workers)
            self.assertTrue(server.guard.acquire(False));server.guard.release()
            count=len(server.workers)+len(server.input_pending)+(server.input_active is not None)
            self.assertLessEqual(count,tcp.MAX_WORKERS);occupancy.append(count)
            if raise_on_wait:raise ValueError('injected admission wait failure')
            clock[0]+=seconds
            if release_at is not None and clock[0]>=release_at:server.input_active=None
            if stop_at is not None and clock[0]>=stop_at:server.running=False
        with patch.object(tcp.time,'monotonic',side_effect=lambda:clock[0]),patch.object(tcp.time,'sleep',side_effect=release_deferred_slot_clock):
            try:result=server._admit_deferred_input(job,deadline)
            finally:self.assertNotIn(owner,server.workers)
        return result,server,job,clock[0],occupancy

    def test_current_authenticated_input_waits_for_original_slot_release(self):
        result,server,job,waited,occupancy=self.admission(release_at=.115)
        self.assertEqual(result,(True,None));self.assertEqual(server.input_pending,[job])
        self.assertEqual(server.input_received,1);self.assertTrue(server.input_wake.is_set())
        self.assertGreaterEqual(waited,.115);self.assertLessEqual(waited,tcp.MAX_LOCAL_LOCK_WAIT_SECONDS)
        self.assertTrue(occupancy);self.assertTrue(all(n==tcp.MAX_WORKERS for n in occupancy))

    def test_busy_original_slot_refuses_at_original_local_wait_bound(self):
        result,server,job,waited,_=self.admission()
        self.assertEqual(result,(False,'input_slot_occupied'));self.assertEqual(server.input_pending,[])
        self.assertEqual(server.input_active,('older-input',));self.assertEqual(server.input_received,0)
        self.assertLessEqual(waited,tcp.MAX_LOCAL_LOCK_WAIT_SECONDS)

    def test_connection_deadline_and_runtime_stop_never_extend_admission(self):
        result,server,_,waited,_=self.admission(release_at=.115,deadline=.07)
        self.assertEqual(result,(False,'input_slot_occupied'));self.assertLessEqual(waited,.07)
        result,server,_,waited,_=self.admission(release_at=.115,stop_at=.04)
        self.assertEqual(result,(False,'runtime_stopping'));self.assertLessEqual(waited,.045)
        self.assertEqual(server.input_pending,[])

    def test_immediate_free_slot_retains_original_expired_reply_admission(self):
        result,server,job,waited,_=self.admission(deadline=0.0,empty=True)
        self.assertEqual(result,(True,None));self.assertEqual(server.input_pending,[job]);self.assertEqual(waited,0.0)

    def test_admission_wait_exception_releases_only_own_handler(self):
        with self.assertRaisesRegex(ValueError,'injected admission wait failure'):
            self.admission(raise_on_wait=True)


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

if __name__=='__main__':
    unittest.main()
