"""Fresh no-value transport: FIFO first offers and retained ordinary history.

The eight historical sorted-rank expectations are superseded by the owner-
authorized V8/V10 contract. Their original sources and failures remain retained;
these tests keep the compatible custody, byte, peer and complete-coverage gates.
"""
import copy
import base64
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from test_interstellar_receipt_scheduler import Fixture


class TransitSchedulerTests(unittest.TestCase):
    def fixture(self,count=25):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);f=Fixture(temp.name)
        with f.node(0) as node:
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"synthetic":true}')
            f.arrivals=[node.enqueue(frame,f.ids[2]) for _ in range(count)]
        return f

    def ids(self,bundle):
        ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        self.assertLessEqual(len(ids),4);self.assertEqual(len(ids),len(set(ids)))
        self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)
        return ids

    def positions(self,node,peer):
        return {k:copy.deepcopy(node.state[k][peer]) for k in ('first_carriage','transit_cursors',
                'recent_transit_cursors','history_transit_cursors','transit_class_steps')}

    def test_actual_four_preparations_and_tick_cold_open_cover_every_peer_for_all_pool_sizes(self):
        for count in (5,15,25,64,256):
            with self.subTest(pending=count):
                f=self.fixture(count);seen={peer:set() for peer in f.ids[1:]}
                with f.node(0) as node:expected=set(node.state['messages'])
                for _ in range(count):
                    with f.node(0) as node:
                        for peer in f.ids[1:]:
                            body=tcp.outgoing(node,peer)['body'];self.assertLessEqual(len(body['transits']),4)
                            seen[peer].update(mesh.digest(t['packet']) for t in body['transits'])
                        cursors=dict(node.state['transit_cursors']);node.tick()
                        self.assertEqual(node.state['transit_cursors'],cursors)
                self.assertTrue(all(ids==expected for ids in seen.values()))
                with f.node(0) as node:
                    self.assertEqual(set(node.state['messages']),expected);self.assertFalse(node.state['receipts'])
                    self.assertFalse(node.status()['payment_authorized'])

    def test_peer_isolation_public_exchange_readonly_and_global_cursor_not_active_authority(self):
        f=self.fixture()
        with f.node(0) as node:
            original=node.exchange(f.ids[2])['body']['transits'];raw=node.path.read_bytes()
            node.exchange(f.ids[2]);self.assertEqual(node.path.read_bytes(),raw)
            other_before=self.positions(node,f.ids[2]);offered=set()
            for _ in range(8):
                waiting=[i for i in f.arrivals if i not in offered]
                ids=self.ids(tcp.outgoing(node,f.ids[1]));n=min(2,len(waiting))
                self.assertEqual(ids[:n],waiting[:n])
                if len(ids)>n:self.assertEqual(node.state['transit_cursors'][f.ids[1]],ids[-1])
                offered.update(ids)
            node.state['cursor']=10**6;node.save()
            self.assertEqual(node.exchange(f.ids[2])['body']['transits'],original)
            self.assertIsNone(node.state['transit_cursors'][f.ids[2]])
            self.assertEqual(self.positions(node,f.ids[2]),other_before)
            self.assertFalse(node.receipts());self.assertFalse(node.status()['payment_authorized'])

    def test_failed_preparation_publication_releases_neither_bundle_nor_cursor(self):
        f=self.fixture()
        with f.node(0) as node:
            state=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('injected cursor publication failure')):
                with self.assertRaises(OSError):tcp.outgoing(node,f.ids[1])
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)
        with f.node(0) as node:self.assertEqual(node.state,state)

    def test_old_identity_and_state_refuse_without_rewriting_pending_or_residue(self):
        for kind, marker in [(kind, marker) for kind in ('identity','state') for marker in
                             (None, 'RLD-CONTACT-TRANSIT-SCHEDULER-V1',
                              'RLD-CONTACT-TRANSIT-SCHEDULER-V2', 'RLD-CONTACT-TRANSIT-SCHEDULER-V3')]:
            with self.subTest(kind=kind,marker=marker):
                f=self.fixture(5)
                with f.node(0) as node:path=node.root/('identity.private.json' if kind=='identity' else 'mesh-state.json')
                state=mesh.load(path,mesh.MAX_STATE)
                if marker is None:state.pop('transit_scheduler')
                else:state['transit_scheduler']=marker
                mesh.atomic(path,state)
                raw=path.read_bytes();residue=path.parent/'.write-retained';residue.write_bytes(b'interrupted evidence')
                with self.assertRaises(ValueError):f.node(0)
                self.assertEqual(path.read_bytes(),raw);self.assertEqual(residue.read_bytes(),b'interrupted evidence')

    def test_invalid_marker_cursors_and_contact_bound_refuse_without_rewrite(self):
        f=self.fixture(5)
        with f.node(0) as node:original=copy.deepcopy(node.state);path=node.path
        variants=[]
        for value in (-1,0,2**63,False,'0','f'*63,'F'*64):
            state=copy.deepcopy(original);state['transit_cursors'][f.ids[1]]=value;variants.append(state)
        for value in ({f.ids[0]:0},{'not-an-id':0},{format(i,'064x'):0 for i in range(mesh.MAX_CONTACTS+1)}):
            state=copy.deepcopy(original);state['transit_cursors']=value;variants.append(state)
        state=copy.deepcopy(original);state['transit_scheduler']='UNKNOWN';variants.append(state)
        for state in variants:
            mesh.atomic(path,state);raw=path.read_bytes()
            with self.assertRaises(ValueError):f.node(0)
            self.assertEqual(path.read_bytes(),raw)

    def test_combined_original_byte_limit_refuses_preparation_without_advancing(self):
        f=self.fixture(5)
        with f.node(0) as node:
            state=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'MAX_STATE',len(raw)-1):
                with self.assertRaisesRegex(ValueError,'capacity'):tcp.outgoing(node,f.ids[1])
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)

    def test_removed_and_readded_contact_forgets_only_cursor_metadata(self):
        f=self.fixture(5)
        with f.node(0) as node:
            expected=copy.deepcopy(node.state['messages']);tcp.outgoing(node,f.ids[4])
        full=copy.deepcopy(f.configs[0]['contacts']);f.configs[0]['contacts']=[x for x in full if x['peer']!=f.ids[4]]
        with f.node(0) as node:
            self.assertNotIn(f.ids[4],node.state['transit_cursors']);self.assertEqual(node.state['messages'],expected)
        f.configs[0]['contacts']=full
        with f.node(0) as node:
            self.assertIsNone(node.state['transit_cursors'][f.ids[4]]);self.assertEqual(node.state['messages'],expected)

    def test_verified_hop_suppression_retains_evidence_and_only_advances_requested_peer(self):
        f=self.fixture(5)
        with f.node(0) as node:
            peer=f.ids[1];initial=node.exchange(peer);all_candidates={mesh.digest(t) for t in initial['body']['transits']}
            before=copy.deepcopy(node.state['messages']);other=self.positions(node,f.ids[2]);bundle=tcp.outgoing(node,peer,all_candidates)
            # The selected starting four are skipped and the fifth is eligible.
            self.assertEqual(len(bundle['body']['transits']),1)
            self.assertEqual(node.state['messages'],before);self.assertFalse(node.state['receipts'])
            self.assertEqual(set(self.ids(bundle)),set(f.arrivals)-set(self.ids(initial)))
            self.assertIsNone(node.state['transit_cursors'][peer])
            self.assertEqual(set(node.state['first_carriage'][peer]['prepared']),set(self.ids(bundle)))
            self.assertIsNone(node.state['transit_cursors'][f.ids[2]])
            self.assertEqual(self.positions(node,f.ids[2]),other)

    def test_wire_trim_keeps_one_position_step_and_eventually_covers_all_packets(self):
        f=self.fixture()
        with f.node(0) as node:
            peer=f.ids[1];bundle=node.exchange(peer);expected=set(node.state['messages']);seen=[];before=self.positions(node,peer)
            limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in range(25):
                    selected=node.prepare_exchange(peer);self.assertEqual(len(selected['body']['transits']),1)
                    self.assertLessEqual(len(wire.canonical(selected)),limit)
                    seen.extend(self.ids(selected))
            self.assertEqual(set(seen),expected);self.assertEqual(seen,f.arrivals)
            for k in ('transit_cursors','recent_transit_cursors','history_transit_cursors','transit_class_steps'):
                self.assertEqual(node.state[k][peer],before[k])
            self.assertEqual(set(node.state['messages']),expected);self.assertFalse(node.receipts())

    def test_single_frame_budget_covers_complete_pool_from_largest_retained_cursor(self):
        f=self.fixture(25)
        with f.node(0) as node:
            peer=f.ids[1];node.state['transit_cursors'][peer]='f'*64;node.state['recent_transit_cursors'][peer]='f'*64;node.save()
            bundle=node.exchange(peer);limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            seen=[];expected=set(node.state['messages']);before=self.positions(node,peer)
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in range(25):
                    selected=node.prepare_exchange(peer);self.assertEqual(len(selected['body']['transits']),1)
                    seen.extend(self.ids(selected))
            self.assertEqual(set(seen),expected);self.assertEqual(seen,f.arrivals)
            for k in ('transit_cursors','recent_transit_cursors','history_transit_cursors','transit_class_steps'):
                self.assertEqual(node.state[k][peer],before[k])
            self.assertFalse(node.state['receipts'])

    def test_failed_spool_write_still_rotates_only_that_peer_and_keeps_all_packets(self):
        f=self.fixture(5);peer=f.ids[1];root=f.root/'links'
        f.configs[0]['contacts'][0]={'peer':peer,'inbox':str(root/'in'),'outbox':str(root/'out')}
        with f.node(0) as node:
            expected=copy.deepcopy(node.state['messages']);real=mesh.evidence.write_new
            real_prepare=node.prepare_exchange;prepared=[];others={p:self.positions(node,p) for p in f.ids[2:]}
            def prepare(*args,**kwargs):
                bundle=real_prepare(*args,**kwargs);prepared.append(bundle);return bundle
            def fail_contact(path,raw):
                if path.parent==root/'out':raise OSError('injected spool failure')
                return real(path,raw)
            with patch.object(node,'prepare_exchange',side_effect=prepare),patch.object(mesh.evidence,'write_new',side_effect=fail_contact):result=node.tick()
            self.assertIn('injected spool failure',result['errors']);self.assertEqual(node.state['messages'],expected)
            self.assertEqual(len(prepared),1);ids=self.ids(prepared[0])
            self.assertEqual(ids[:2],f.arrivals[:2]);self.assertEqual(len(ids),4)
            self.assertEqual(node.state['transit_cursors'][peer],ids[-1])
            self.assertTrue(all(node.state['transit_cursors'][p] is None for p in f.ids[2:]))
            self.assertEqual({p:self.positions(node,p) for p in f.ids[2:]},others)
            positions=self.positions(node,peer);self.assertFalse(node.receipts())
        with f.node(0) as node:self.assertEqual(node.state['messages'],expected);self.assertEqual(self.positions(node,peer),positions)

    def test_failed_sends_spend_full_four_slots_on_distinct_pending_packets(self):
        f=self.fixture(25)
        with f.node(0) as node:
            seen=set();first_seen=[];original=copy.deepcopy(node.state['messages'])
            for _ in range(13):
                waiting=[i for i in f.arrivals if i not in seen];n=min(2,len(waiting))
                ids=self.ids(tcp.outgoing(node,f.ids[1]));self.assertEqual(len(ids),4)
                self.assertEqual(ids[:n],waiting[:n]);first_seen.extend(ids[:n]);seen.update(ids)
            self.assertEqual(len(first_seen),len(set(first_seen)))
            self.assertEqual(seen,set(f.arrivals));self.assertEqual(node.state['messages'],original)
            self.assertFalse(node.state['receipts']);self.assertFalse(node.status()['payment_authorized'])

    def test_empty_suppressed_batch_steps_one_from_absent_last_id(self):
        f=self.fixture(4)
        with f.node(0) as node:
            peer=f.ids[1];node.state['transit_cursors'][peer]='f'*64;node.state['recent_transit_cursors'][peer]='f'*64;node.save()
            complete={mesh.digest(t) for t in node.exchange(peer)['body']['transits']}
            expected=sorted(node.state['messages'])[0]
            bundle=tcp.outgoing(node,peer,complete)
            self.assertFalse(bundle['body']['transits']);self.assertEqual(node.state['transit_cursors'][peer],expected)
            self.assertEqual(len(node.state['messages']),4);self.assertFalse(node.state['receipts'])

    def test_absent_last_id_wrap_does_not_sign_new_evidence_or_grant_delivery(self):
        f=self.fixture(5)
        with f.node(0) as node:
            peer=f.ids[1];node.state['transit_cursors'][peer]='f'*64;node.state['recent_transit_cursors'][peer]='f'*64;node.save()
            before=copy.deepcopy(node.state['messages']);bundle=tcp.outgoing(node,peer)
            last=mesh.digest(bundle['body']['transits'][-1]['packet'])
            self.assertEqual(node.state['transit_cursors'][peer],last);self.assertEqual(node.state['messages'],before)
            self.assertFalse(node.state['receipts']);self.assertFalse(node.status()['payment_authorized'])

    def test_actual_completed_archive_removal_does_not_skip_next_waiting_batch(self):
        f=self.fixture(32);peer=f.ids[2]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);first=node.prepare_exchange(peer)
            carried=self.ids(first);self.assertEqual(len(carried),4);self.assertEqual(carried[:2],f.arrivals[:2])
        with f.node(2) as destination:
            destination.receive(first,f.ids[0])
            reply=destination.exchange(f.ids[0])
        with f.node(0) as node:
            node.receive(reply,peer)
            self.assertEqual(node.archive_completed(),4)
            self.assertEqual(set(node.state['archives']),set(carried))
            self.assertTrue(all(i not in node.state['messages'] for i in carried))
            self.assertTrue(all(i not in node.state['recent_transits'] for i in carried))
            remaining=[i for i in f.arrivals if i not in carried];actual=self.ids(node.prepare_exchange(peer))
            self.assertEqual(actual[:2],remaining[:2]);self.assertFalse(set(actual)&set(carried))
            self.assertEqual(node.state['messages'],{i:original[i] for i in remaining})
            for ident in carried:
                self.assertIsNotNone(node.transit(ident));mesh.receipt_matches(node.receipts()[ident],node.transit(ident))
                self.assertEqual(node.transit(ident),original[ident])
        with f.node(0) as node:
            self.assertEqual(node.state['transit_cursors'][peer],actual[-1])
            self.assertEqual(set(node.state['archives']),set(carried))
            for ident in carried:self.assertEqual(node.transit(ident),original[ident]);mesh.receipt_matches(node.receipts()[ident],node.transit(ident))

    def test_insertion_before_last_id_does_not_repeat_or_skip_original_successors(self):
        f=self.fixture(25);peer=f.ids[2]
        with f.node(0) as node:
            original=copy.deepcopy(node.state['messages']);carried=self.ids(node.prepare_exchange(peer));last=node.state['transit_cursors'][peer]
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"insertion":true}')
            # Insert below the ordinary hash position without losing the older
            # input-order FIFO offers or retained history under either class.
            for serial in range(1024):
                nonce=hashlib.sha256(str(serial).encode()).digest()
                packet=mesh.sign(node.key,'packet',dict(format=mesh.VERSION,network=node.network,
                    node_id=node.id,destination=peer,nonce=nonce.hex(),hop_limit=mesh.MAX_HOPS,
                    frame=base64.b64encode(frame).decode()))
                if mesh.digest(packet)<last:break
            else:self.fail('no insertion nonce found')
            with patch.object(mesh.os,'urandom',return_value=nonce):added=[node.enqueue(frame,peer)]
            self.assertLess(added[0],last)
            received=self.ids(node.prepare_exchange(peer));waiting=[i for i in f.arrivals if i not in carried]
            self.assertEqual(received[:2],waiting[:2]);seen=set(carried+received)
            for _ in range(13):seen.update(self.ids(node.prepare_exchange(peer)))
            self.assertEqual(seen,set(f.arrivals+added));self.assertEqual(set(node.state['messages']),set(f.arrivals+added))
            for ident,value in original.items():self.assertEqual(node.state['messages'][ident],value)
            self.assertFalse(node.receipts());self.assertFalse(node.status()['payment_authorized'])


if __name__=='__main__':unittest.main()
