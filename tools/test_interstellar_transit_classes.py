"""Bounded fresh/historical carriage fairness, durable custody and pinned TLS."""
import copy
import tempfile
import time
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from regional_carriage_worker import Worker
from test_interstellar_receipt_scheduler import Fixture
from test_interstellar_tcp import Fixture as TcpFixture


class TransitClassTests(unittest.TestCase):
    def fixture(self, count=64):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        f=Fixture(temp.name)
        self.frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"synthetic":true}')
        with f.node(0) as node:
            for _ in range(count):node.enqueue(self.frame,f.ids[2])
        return f

    def ids(self, bundle):
        return [mesh.digest(t['packet']) for t in bundle['body']['transits']]

    def test_four_slots_serve_both_classes_and_cold_preparations_cover_whole_backlog(self):
        f=self.fixture(96);seen=set();peer=f.ids[1]
        with f.node(0) as node:
            pending=set(node.state['messages']);recent=set(node.state['recent_transits'])
            self.assertEqual(len(recent),32)
        for _ in range(32):
            with f.node(0) as node:
                selected=set(self.ids(tcp.outgoing(node,peer)))
                self.assertEqual(len(selected&recent),2)
                self.assertEqual(len(selected-recent),2)
                seen.update(selected)
                self.assertEqual(set(node.state['messages']),pending)
                self.assertFalse(node.receipts())
        self.assertEqual(seen,pending)

    def test_continuous_new_custody_keeps_historical_backlog_progressing(self):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            originals=set(node.state['messages'])-set(node.state['recent_transits'])
            retained=set(node.state['messages']);seen=set()
            for _ in range(40):
                added=node.enqueue_batch([(self.frame,f.ids[2])]*2);retained.update(added)
                current=set(node.state['recent_transits'])
                batch=set(self.ids(tcp.outgoing(node,peer)))
                self.assertEqual(len(batch&current),2)
                self.assertEqual(len(batch-current),2)
                seen.update(batch)
            self.assertTrue(originals<=seen)
            self.assertEqual(set(node.state['messages']),retained)
            self.assertEqual(len(node.state['recent_transits']),32)
            self.assertFalse(node.receipts())

    def test_verified_hop_suppression_cannot_starve_later_eligible_history(self):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            recent=set(node.state['recent_transits'])
            history=sorted(set(node.state['messages'])-recent)
            accepted=set()
            for ident in history[:-2]:
                transit=node.state['messages'][ident]
                hop=mesh.sign(node.key,'hop',dict(format=mesh.VERSION,network=node.network,
                    node_id=node.id,packet_id=ident,previous=ident,to=peer))
                accepted.add(mesh.digest(dict(packet=transit['packet'],routing=transit['routing'],hops=[hop])))
            before=copy.deepcopy(node.state['messages'])
            selected=set(self.ids(tcp.outgoing(node,peer,accepted)))
            self.assertEqual(selected-recent,set(history[-2:]))
            self.assertEqual(len(selected&recent),2)
            self.assertEqual(node.state['messages'],before);self.assertFalse(node.receipts())

    def test_single_packet_budget_alternates_classes_across_restart(self):
        f=self.fixture();peer=f.ids[1];classes=[];seen=set()
        with f.node(0) as node:
            bundle=node.exchange(peer);recent=set(node.state['recent_transits'])
            limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            pending=set(node.state['messages'])
        with patch.object(mesh,'MAX_BATCH',limit):
            for _ in range(64):
                with f.node(0) as node:
                    ids=self.ids(node.prepare_exchange(peer));self.assertEqual(len(ids),1)
                    seen.update(ids);classes.append(ids[0] in recent)
        self.assertEqual(classes,[True,False]*32);self.assertEqual(seen,pending)

    def test_cursors_are_peer_local_and_failed_publication_changes_no_metadata(self):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            before=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('cursor fsync refused')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),raw)
            other=node.exchange(f.ids[2]);node.prepare_exchange(peer)
            self.assertEqual(node.exchange(f.ids[2]),other)
            self.assertTrue(all(node.state[name][f.ids[2]] is None for name in
                                ('transit_cursors','recent_transit_cursors','history_transit_cursors')))
            self.assertEqual(node.state['transit_class_steps'][f.ids[2]],0)

    def test_authenticated_receive_labels_only_actual_new_packets_once(self):
        f=self.fixture(4)
        with f.node(0) as source:bundle=source.prepare_exchange(f.ids[1])
        with f.node(1) as carrier:
            carrier.receive(bundle,f.ids[0]);recent=list(carrier.state['recent_transits'])
            self.assertEqual(set(recent),set(self.ids(bundle)))
            carrier.enqueue(self.frame,f.ids[2]);expected=list(carrier.state['recent_transits'])
            carrier.receive(bundle,f.ids[0]);self.assertEqual(carrier.state['recent_transits'],expected)
            bad=copy.deepcopy(bundle);bad['body']['transits'][0]['packet']['signature']='0'*128
            bad=mesh.sign(source.key,'exchange',bad['body'])
            before=copy.deepcopy(carrier.state);raw=carrier.path.read_bytes()
            with self.assertRaises(ValueError):carrier.receive(bad,f.ids[0])
            self.assertEqual(carrier.state,before);self.assertEqual(carrier.path.read_bytes(),raw)

    def test_batch_failure_does_not_adopt_recent_labels_or_signed_packets(self):
        f=self.fixture()
        with f.node(0) as node:
            before=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('batch fsync refused')):
                with self.assertRaises(OSError):node.enqueue_batch([(self.frame,f.ids[2])]*4)
            self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),raw)

    def test_invalid_recent_metadata_and_old_v3_schema_refuse_without_rewrite(self):
        f=self.fixture()
        with f.node(0) as node:original=copy.deepcopy(node.state);path=node.path
        variants=[]
        for values in (['f'*64]*2,['g'*64],list(range(33)),list(original['messages'])[:33]):
            item=copy.deepcopy(original);item['recent_transits']=values;variants.append(item)
        for name,value in (('recent_transit_cursors',False),('history_transit_cursors','F'*64),
                           ('transit_class_steps',False),('transit_class_steps',2**63)):
            item=copy.deepcopy(original);item[name][f.ids[1]]=value;variants.append(item)
        item=copy.deepcopy(original);item['transit_scheduler']='RLD-CONTACT-TRANSIT-SCHEDULER-V3'
        for name in ('recent_transits','recent_transit_cursors','history_transit_cursors','transit_class_steps'):item.pop(name)
        variants.append(item)
        for item in variants:
            mesh.atomic(path,item);raw=path.read_bytes()
            with self.assertRaises(ValueError):f.node(0)
            self.assertEqual(path.read_bytes(),raw)

    def test_stale_syntactic_label_cannot_create_carriage_or_custody(self):
        f=self.fixture(5)
        with f.node(0) as node:
            pending=set(node.state['messages']);phantom='f'*64
            self.assertNotIn(phantom,pending)
            node.state['recent_transits']=[phantom];node.save()
        with f.node(0) as node:
            self.assertTrue(set(self.ids(node.prepare_exchange(f.ids[1])))<=pending)
            self.assertEqual(set(node.state['messages']),pending);self.assertFalse(node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_zero_wire_budget_rotates_classes_and_never_drops_evidence(self):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            pending=copy.deepcopy(node.state['messages']);classes=[]
            limit=len(wire.canonical(dict(node.exchange(peer)['body'],transits=[])))+512
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in range(4):
                    self.assertFalse(node.prepare_exchange(peer)['body']['transits'])
                    classes.append(node.state['transit_cursors'][peer] in node.state['recent_transits'])
            self.assertEqual(classes,[True,False,True,False])
            self.assertEqual(node.state['messages'],pending);self.assertFalse(node.receipts())

    def test_actual_tls_multihop_workers_carry_fresh_and_historical_packets(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        f=TcpFixture(temp.name);self.addCleanup(f.close)
        with f.node('earth') as node:
            ids=[node.enqueue(f.frame(i),f.ids['andromeda']) for i in range(36)]
        for server in f.servers.values():self.addCleanup(Worker(server,interval=0.1).close)
        deadline=time.monotonic()+20;received=set()
        while time.monotonic()<deadline:
            with f.node('earth') as node:received=set(node.receipts())
            if set(ids)<=received:break
            time.sleep(0.02)
        self.assertTrue(set(ids)<=received)
        with f.node('andromeda') as node:
            for ident in ids:mesh.receipt_matches(node.receipts()[ident],node.transit(ident))


if __name__=='__main__':unittest.main()
