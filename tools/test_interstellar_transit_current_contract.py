"""Current FIFO and historical carriage contract; legacy rank tests stay intact.

Only fresh synthetic transport evidence. No socket, Native ledger or value.
Arrival IDs below come from actual enqueue returns, never a selector's plan.
"""
import base64
import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_receipt_scheduler import Fixture


class CurrentTransitContractTests(unittest.TestCase):
    def fixture(self, count=25):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        f=Fixture(temp.name);f.frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"synthetic":true}')
        with f.node(0) as node:f.arrivals=[node.enqueue(f.frame,f.ids[2]) for _ in range(count)]
        return f

    def ids(self, bundle):
        ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        self.assertLessEqual(len(ids),4);self.assertEqual(len(ids),len(set(ids)))
        self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)
        return ids

    def positions(self,node,peer):
        return {k:copy.deepcopy(node.state[k][peer]) for k in ('first_carriage','transit_cursors',
                'recent_transit_cursors','history_transit_cursors','transit_class_steps')}

    def test_peer_isolation_readonly_exchange_and_actual_ordinary_cursor(self):
        f=self.fixture();peer,other=f.ids[1:3]
        with f.node(0) as node:
            original=node.exchange(other);raw=node.path.read_bytes();positions=self.positions(node,other)
            node.exchange(other);self.assertEqual(node.path.read_bytes(),raw)
            offered=set()
            for _ in range(13):
                waiting=[i for i in f.arrivals if i not in offered];batch=self.ids(node.prepare_exchange(peer))
                self.assertEqual(batch[:min(2,len(waiting))],waiting[:2])
                first=set(batch[:min(2,len(waiting))]);ordinary=[i for i in batch if i not in first]
                if ordinary:self.assertEqual(node.state['transit_cursors'][peer],ordinary[-1])
                offered.update(batch)
            self.assertEqual(offered,set(f.arrivals));self.assertEqual(self.positions(node,other),positions)
            node.state['cursor']=10**6;node.save()
            self.assertEqual(node.exchange(other)['body']['transits'],original['body']['transits'])
            self.assertEqual(self.positions(node,other),positions);self.assertFalse(node.receipts())

    def test_suppression_skips_exact_verified_hops_without_custody_or_other_peer_move(self):
        f=self.fixture(5);peer,other=f.ids[1:3]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);positions=self.positions(node,other)
            first=node.exchange(peer);suppressed={mesh.digest(t) for t in first['body']['transits']}
            ids=self.ids(node.prepare_exchange(peer,suppressed))
            self.assertEqual(set(ids),set(f.arrivals)-set(self.ids(first)))
            self.assertEqual(len(ids),1);self.assertIsNone(node.state['transit_cursors'][peer])
            self.assertEqual(set(node.state['first_carriage'][peer]['prepared']),set(ids))
            self.assertEqual(self.positions(node,other),positions)
            self.assertEqual(node.state['messages'],original);self.assertFalse(node.receipts())

    def one_frame_fifo(self, largest):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            if largest:
                node.state['transit_cursors'][peer]='f'*64;node.state['recent_transit_cursors'][peer]='f'*64;node.save()
            before=self.positions(node,peer);bundle=node.exchange(peer)
            limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            seen=[]
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in f.arrivals:
                    selected=node.prepare_exchange(peer);self.assertEqual(len(selected['body']['transits']),1)
                    self.assertLessEqual(len(wire.canonical(selected)),limit);seen.extend(self.ids(selected))
            self.assertEqual(seen,f.arrivals)
            for k in ('transit_cursors','recent_transit_cursors','history_transit_cursors','transit_class_steps'):
                self.assertEqual(node.state[k][peer],before[k])
            self.assertEqual(set(node.state['messages']),set(f.arrivals));self.assertFalse(node.receipts())
        with f.node(0) as node:self.assertEqual(set(node.state['first_carriage'][peer]['prepared']),set(f.arrivals))

    def test_wire_trim_carries_complete_fifo_and_does_not_advance_ordinary_on_first_only(self):self.one_frame_fifo(False)
    def test_largest_retained_cursor_cannot_override_first_fifo_or_prevent_complete_coverage(self):self.one_frame_fifo(True)

    def test_failed_spool_retains_signed_bytes_and_only_commits_actual_preparation(self):
        f=self.fixture(5);peer=f.ids[1];root=f.root/'links';prepared=[]
        f.configs[0]['contacts'][0]={'peer':peer,'inbox':str(root/'in'),'outbox':str(root/'out')}
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);others={p:self.positions(node,p) for p in f.ids[2:]}
            real_write=mesh.evidence.write_new;real_prepare=node.prepare_exchange
            def prepare(*args,**kwargs):
                value=real_prepare(*args,**kwargs);prepared.append(value);return value
            def write(path,raw):
                if path.parent==root/'out':raise OSError('injected spool failure')
                return real_write(path,raw)
            with patch.object(node,'prepare_exchange',side_effect=prepare),patch.object(mesh.evidence,'write_new',side_effect=write):result=node.tick()
            self.assertIn('injected spool failure',result['errors']);self.assertEqual(len(prepared),1)
            ids=self.ids(prepared[0]);self.assertEqual(ids[:2],f.arrivals[:2]);self.assertEqual(len(ids),4)
            self.assertEqual(node.state['transit_cursors'][peer],ids[-1])
            self.assertEqual(node.state['messages'],original);self.assertFalse(node.receipts())
            self.assertEqual({p:self.positions(node,p) for p in f.ids[2:]},others)
            positions=self.positions(node,peer)
        with f.node(0) as node:self.assertEqual(node.state['messages'],original);self.assertEqual(self.positions(node,peer),positions)

    def test_failed_sends_fill_four_distinct_slots_and_first_fifo_finishes_without_custody(self):
        f=self.fixture();peer=f.ids[1];offered=set();first_seen=[]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages'])
            for _ in range(13):
                waiting=[i for i in f.arrivals if i not in offered];ids=self.ids(node.prepare_exchange(peer))
                self.assertEqual(len(ids),4);self.assertEqual(ids[:min(2,len(waiting))],waiting[:2])
                first_seen.extend(ids[:min(2,len(waiting))]);offered.update(ids)
            self.assertEqual(offered,set(f.arrivals));self.assertEqual(len(first_seen),len(set(first_seen)))
            self.assertEqual(set(node.state['first_carriage'][peer]['prepared']),set(f.arrivals))
            self.assertEqual(node.state['messages'],original);self.assertFalse(node.receipts())

    def test_actual_archive_removal_preserves_uncompleted_fifo_and_complete_archived_evidence(self):
        f=self.fixture(32);peer=f.ids[2]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);first=node.prepare_exchange(peer);carried=self.ids(first)
            self.assertEqual(carried[:2],f.arrivals[:2]);self.assertEqual(len(carried),4)
        with f.node(2) as destination:destination.receive(first,f.ids[0]);reply=destination.exchange(f.ids[0])
        with f.node(0) as node:
            node.receive(reply,peer);self.assertEqual(node.archive_completed(),4)
            self.assertEqual(set(node.state['archives']),set(carried));remaining=[i for i in f.arrivals if i not in carried]
            next_ids=self.ids(node.prepare_exchange(peer));self.assertEqual(next_ids[:2],remaining[:2])
            self.assertFalse(set(next_ids)&set(carried));self.assertEqual(node.state['messages'],{i:original[i] for i in remaining})
            positions=self.positions(node,peer)
        with f.node(0) as node:
            self.assertEqual(self.positions(node,peer),positions)
            for i in carried:self.assertEqual(node.transit(i),original[i]);mesh.receipt_matches(node.receipts()[i],node.transit(i))
            self.assertEqual(node.state['messages'],{i:original[i] for i in remaining})

    def test_low_hash_insertion_cannot_skip_waiting_fifo_or_drop_original_evidence(self):
        f=self.fixture();peer=f.ids[2]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);carried=self.ids(node.prepare_exchange(peer));last=node.state['transit_cursors'][peer]
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"insertion":true}')
            for serial in range(1024):
                nonce=hashlib.sha256(str(serial).encode()).digest()
                packet=mesh.sign(node.key,'packet',dict(format=mesh.VERSION,network=node.network,node_id=node.id,destination=peer,
                    nonce=nonce.hex(),hop_limit=mesh.MAX_HOPS,frame=base64.b64encode(frame).decode()))
                if mesh.digest(packet)<last:break
            else:self.fail('no bounded low-hash insertion nonce')
            with patch.object(mesh.os,'urandom',return_value=nonce):added=node.enqueue(frame,peer)
            self.assertLess(added,last);waiting=[i for i in f.arrivals if i not in carried];next_ids=self.ids(node.prepare_exchange(peer))
            self.assertEqual(next_ids[:2],waiting[:2]);seen=set(carried+next_ids)
            for _ in range(13):seen.update(self.ids(node.prepare_exchange(peer)))
            self.assertTrue(set(f.arrivals+[added])<=seen)
            for i,v in original.items():self.assertEqual(node.state['messages'][i],v)
            self.assertFalse(node.receipts())

    def test_continuous_arrivals_keep_fifo_offers_and_bound_complete_old_history_coverage(self):
        f=self.fixture(96);peer=f.ids[1];seen=set();original=None
        for turn in range(64):
            with mesh._carriage_position_lock:mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with f.node(0) as node:
                if original is None:original=copy.deepcopy(node.state['messages'])
                previous=list(node.state['first_carriage'][peer]['pending'])
                node.enqueue_batch([(f.frame,f.ids[2])]*2)
                ids=self.ids(node.prepare_exchange(peer));seen.update(ids)
                if previous:self.assertEqual(ids[:min(2,len(previous))],previous[:2])
                for i,v in original.items():self.assertEqual(node.state['messages'][i],v)
                self.assertFalse(node.receipts());self.assertFalse(node.status()['payment_authorized'])
            if set(f.arrivals)<=seen:break
        self.assertTrue(set(f.arrivals)<=seen,'retained old history starved under continuous arrivals/cold hint misses')

    def test_publication_failure_retains_all_positions_and_full_retry_has_no_first_or_ordinary_advance(self):
        f=self.fixture();peer=f.ids[1]
        with f.node(0) as node:
            state=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('expected preparation publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)
            first=node.prepare_exchange(peer);ids=self.ids(first);positions=self.positions(node,peer)
            retry=node.prepare_exchange(peer,retry_packet_ids=tuple(ids))
            self.assertEqual(self.ids(retry),ids);self.assertEqual(self.positions(node,peer),positions)
            self.assertFalse(node.receipts());self.assertEqual(node.state['messages'],state['messages'])


if __name__=='__main__':unittest.main()
