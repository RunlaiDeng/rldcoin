"""One-use adjacent preparation preserves pinned transport and durable custody."""
from contextlib import contextmanager
import errno
import gc
import os
from pathlib import Path
import tempfile
import threading
import unittest
import weakref
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace,TraceCursor
from test_interstellar_tcp import Fixture,NETWORK


class AdjacentPrepareTests(unittest.TestCase):
    def fixture(self,neighbors=2):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                    str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        parent.mkdir(parents=True,exist_ok=True)
        root=tempfile.mkdtemp(prefix='rld-adjacent-prepare-',dir=parent)
        names=['source']+[f'peer-{n}' for n in range(neighbors)]
        original=tcp.Server
        def observed(*args,**kwargs):
            trace=ContactTrace();server=original(*args,contact_trace=trace,**kwargs)
            trace.bind(server.network,server.id);return server
        with patch.object(tcp,'Server',side_effect=observed):
            fixture=Fixture(root,names=names,edges=[('source',n) for n in names[1:]])
        self.addCleanup(fixture.close)
        server=fixture.servers['source'];peers=sorted(server.peers)
        by_id={fixture.ids[n]:n for n in names}
        packets={}
        with fixture.node('source') as node:
            for n,peer in enumerate(peers):packets[peer]=node.enqueue(fixture.frame(n),peer)
        return fixture,server,peers,by_id,packets

    def run_pass(self,server):
        result=[];errors=[]
        def run():
            try:result.append(server.tick())
            except BaseException as error:errors.append(error)
        owner=threading.Thread(target=run)
        server.claim_outbound(owner)
        try:
            owner.start();owner.join(10)
            self.assertFalse(owner.is_alive(),'original bounded pass did not exit')
        finally:
            if not owner.is_alive():server.release_outbound(owner)
        if errors:raise errors[0]
        self.assertEqual(len(result),1)
        return result[0]

    def receipt(self,fixture,name,packet):
        with fixture.node(name) as node:
            self.assertIn(packet,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_actual_TLS_reuses_only_reply_lease_and_keeps_exact_prepared_bytes(self):
        fixture,server,peers,names,packets=self.fixture()
        original_prepare=tcp.outgoing;original_bind=tcp.bind_request
        prepared=[];bound=[];original_mesh=server.mesh_node;leases=[]
        @contextmanager
        def opened(deadline):
            with original_mesh(deadline) as node:
                leases.append(node);yield node
        def prepare(node,peer,*args):
            value=original_prepare(node,peer,*args)
            prepared.append((peer,node,wire.canonical(value)));return value
        def bind(key,network,requester,peer,nonce,value):
            self.assertIsNone(server.local_mesh_owner,'connect binds after lease close')
            bound.append((peer,wire.canonical(value)))
            return original_bind(key,network,requester,peer,nonce,value)
        with patch.object(server,'mesh_node',side_effect=opened), \
             patch.object(tcp,'outgoing',side_effect=prepare), \
             patch.object(tcp,'bind_request',side_effect=bind):
            report=self.run_pass(server)
        self.assertFalse(report['errors'])
        own=[x for x in prepared if x[1].id==server.id]
        self.assertEqual([x[0] for x in own],peers)
        self.assertEqual(len(leases),3)
        self.assertIs(own[0][1],leases[0]);self.assertIs(own[1][1],leases[1])
        self.assertEqual([(p,raw) for p,_,raw in own],bound)
        for peer in peers:self.receipt(fixture,names[peer],packets[peer])
        rows=TraceCursor(NETWORK,server.id).drain(server.contact_trace.snapshot())
        self.assertTrue(rows['this_interval_complete'])
        starts=[r['peer'] for r in rows['events'] if r['stage']=='outbound_peer_started']
        ends=[r['peer'] for r in rows['events'] if r['stage']=='outbound_peer_finished']
        self.assertEqual(starts,peers);self.assertEqual(ends,peers)

    def test_next_prepare_refusal_keeps_prior_custody_and_never_connects_next(self):
        fixture,server,peers,names,packets=self.fixture()
        original=tcp.outgoing;connect=tcp.client_connect
        connected=[]
        def refusing(node,peer,*args):
            if node.id==server.id and peer==peers[1]:
                raise BlockingIOError(errno.EAGAIN,'controlled adjacent preparation refusal')
            return original(node,peer,*args)
        def connecting(address,pin,network,peer,deadline):
            connected.append(peer);return connect(address,pin,network,peer,deadline)
        with patch.object(tcp,'outgoing',side_effect=refusing), \
             patch.object(tcp,'client_connect',side_effect=connecting):
            report=self.run_pass(server)
        self.assertEqual(connected,[peers[0]])
        self.assertEqual(len(report['errors']),1)
        self.assertTrue(server.observations[peers[0]]['outbound_last_attempt_succeeded'])
        self.assertFalse(server.observations[peers[1]]['outbound_last_attempt_succeeded'])
        self.receipt(fixture,names[peers[0]],packets[peers[0]])
        with fixture.node('source') as node:
            self.assertIn(packets[peers[0]],node.receipts())
            self.assertIn(packets[peers[1]],node.summaries())
            self.assertNotIn(packets[peers[1]],node.receipts())
        self.assertTrue(server.accepted_transits[peers[0]])
        self.assertNotIn(peers[1],server.accepted_transits)

    def test_failed_reply_close_discards_next_bytes_preserving_exact_retry(self):
        fixture,server,peers,names,packets=self.fixture()
        original_mesh=server.mesh_node;connect=tcp.client_connect;calls=0;connected=[]
        @contextmanager
        def closing(deadline):
            nonlocal calls
            calls+=1;operation=calls
            with original_mesh(deadline) as node:yield node
            if operation==2:raise OSError(errno.EIO,'controlled reply lease close refusal')
        def connecting(address,pin,network,peer,deadline):
            connected.append(peer);return connect(address,pin,network,peer,deadline)
        with patch.object(server,'mesh_node',side_effect=closing), \
             patch.object(tcp,'client_connect',side_effect=connecting):
            report=self.run_pass(server)
        self.assertEqual(connected,[peers[0]])
        self.assertEqual(len(report['errors']),2)
        self.assertEqual(server.accepted_transits,{})
        with fixture.node('source') as node:
            for peer in peers:self.assertIn(packets[peer],node.failed_carriage(peer))
            self.assertIn(packets[peers[0]],node.receipts())
            self.assertNotIn(packets[peers[1]],node.receipts())
        self.assertTrue(all(v==1 for v in server.peer_attempts.values()))

    def test_stop_after_adjacent_prepare_keeps_next_retry_and_no_next_socket(self):
        fixture,server,peers,names,packets=self.fixture()
        original=tcp.outgoing;connect=tcp.client_connect;connected=[]
        def stopping(node,peer,*args):
            value=original(node,peer,*args)
            if node.id==server.id and peer==peers[1]:server.running=False
            return value
        def connecting(address,pin,network,peer,deadline):
            connected.append(peer);return connect(address,pin,network,peer,deadline)
        with patch.object(tcp,'outgoing',side_effect=stopping), \
             patch.object(tcp,'client_connect',side_effect=connecting):
            report=self.run_pass(server)
        self.assertEqual(connected,[peers[0]])
        self.assertEqual(len(report['errors']),1)
        self.assertTrue(server.accepted_transits[peers[0]])
        with fixture.node('source') as node:
            self.assertIn(packets[peers[1]],node.failed_carriage(peers[1]))
            self.assertNotIn(packets[peers[1]],node.receipts())

    def test_prefetch_keeps_four_peer_slots_and_does_not_skip_unattempted_peer(self):
        fixture,server,peers,names,packets=self.fixture(5)
        report=self.run_pass(server)
        self.assertFalse(report['errors'])
        self.assertEqual(set(server.peer_attempts),set(peers[:tcp.MAX_OUTBOUND_PER_TICK]))
        self.assertEqual(server.mesh_costs.snapshot()['rows']['tcp-outbound']['open']['calls'],
                         tcp.MAX_OUTBOUND_PER_TICK+1)
        for peer in peers[:tcp.MAX_OUTBOUND_PER_TICK]:self.receipt(fixture,names[peer],packets[peer])
        with fixture.node(names[peers[-1]]) as node:self.assertNotIn(packets[peers[-1]],node.receipts())

    def test_second_peer_uses_current_pin_and_failure_reprepares_on_next_pass(self):
        fixture,server,peers,names,packets=self.fixture()
        original=tcp.outgoing;prepared=[]
        def replaced(node,peer,*args):
            value=original(node,peer,*args)
            if node.id==server.id:
                prepared.append(peer)
                if peer==peers[1]:server.peers[peer]['tls_cert_sha256']='0'*64
            return value
        with patch.object(tcp,'outgoing',side_effect=replaced):report=self.run_pass(server)
        self.assertEqual(len(report['errors']),1)
        self.assertIn('TLS certificate pin mismatch',report['errors'][0])
        with fixture.node(names[peers[1]]) as node:self.assertNotIn(packets[peers[1]],node.receipts())
        server.peers[peers[1]]['tls_cert_sha256']=fixture.pins[names[peers[1]]]
        report=self.run_pass(server);self.assertFalse(report['errors'])
        self.receipt(fixture,names[peers[1]],packets[peers[1]])
        self.assertEqual(prepared,peers)
        self.assertEqual(server.peer_attempts[peers[1]],2)

    def test_adjacent_refusal_retains_no_closed_Node_when_GC_is_disabled(self):
        fixture,server,peers,names,packets=self.fixture(4)
        original=tcp.outgoing;refs=[]
        def refusing(node,peer,*args):
            if node.id==server.id:
                refs.append(weakref.ref(node))
                if peer==peers[-1]:raise ValueError('controlled final adjacent refusal')
            return original(node,peer,*args)
        enabled=gc.isenabled();gc.disable()
        try:
            # A direct replacement avoids a mock retaining its Node arguments.
            with patch.object(tcp,'outgoing',new=refusing):report=self.run_pass(server)
            self.assertEqual(len(report['errors']),1)
            self.assertEqual(len(refs),4)
            self.assertTrue(all(ref() is None for ref in refs),
                            'a refused future attempt retained a complete closed Node')
        finally:
            if enabled:gc.enable()

    def test_removed_adjacent_peer_refuses_without_stealing_later_slot(self):
        fixture,server,peers,names,packets=self.fixture(3)
        original=tcp.outgoing
        def removed(node,peer,*args):
            value=original(node,peer,*args)
            if node.id==server.id and peer==peers[1]:server.peers.pop(peer)
            return value
        with patch.object(tcp,'outgoing',new=removed):report=self.run_pass(server)
        self.assertEqual(len(report['errors']),1)
        self.assertEqual(server.peer_attempts,{peer:1 for peer in peers})
        self.receipt(fixture,names[peers[2]],packets[peers[2]])
        with fixture.node(names[peers[1]]) as node:self.assertNotIn(packets[peers[1]],node.receipts())
        with fixture.node('source') as node:
            self.assertIn(packets[peers[1]],node.failed_carriage(peers[1]))


if __name__=='__main__':unittest.main()
