"""Fresh synthetic ground transport only: no socket, native ledger or value."""
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
            for _ in range(count):node.enqueue(frame,f.ids[2])
        return f

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
            for _ in range(8):tcp.outgoing(node,f.ids[1])
            node.state['cursor']=10**6;node.save()
            self.assertEqual(node.exchange(f.ids[2])['body']['transits'],original)
            self.assertEqual(node.state['transit_cursors'][f.ids[1]],sorted(node.state['messages'])[(8*4-1)%25])
            self.assertIsNone(node.state['transit_cursors'][f.ids[2]])

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
            peer=f.ids[1];all_candidates={mesh.digest(t) for t in node.exchange(peer)['body']['transits']}
            before=copy.deepcopy(node.state['messages']);bundle=tcp.outgoing(node,peer,all_candidates)
            # The selected starting four are skipped and the fifth is eligible.
            self.assertEqual(len(bundle['body']['transits']),1)
            self.assertEqual(node.state['messages'],before);self.assertFalse(node.state['receipts'])
            self.assertEqual(node.state['transit_cursors'][peer],sorted(node.state['messages'])[-1])
            self.assertIsNone(node.state['transit_cursors'][f.ids[2]])

    def test_wire_trim_keeps_one_position_step_and_eventually_covers_all_packets(self):
        f=self.fixture()
        with f.node(0) as node:
            peer=f.ids[1];bundle=node.exchange(peer);expected=set(node.state['messages']);seen=set()
            limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in range(25):
                    selected=node.prepare_exchange(peer);self.assertEqual(len(selected['body']['transits']),1)
                    self.assertLessEqual(len(wire.canonical(selected)),limit)
                    seen.update(mesh.digest(t['packet']) for t in selected['body']['transits'])
            self.assertEqual(seen,expected);self.assertEqual(node.state['transit_cursors'][peer],sorted(node.state['messages'])[-1])

    def test_single_frame_budget_covers_complete_pool_from_largest_retained_cursor(self):
        f=self.fixture(25)
        with f.node(0) as node:
            peer=f.ids[1];node.state['transit_cursors'][peer]='f'*64;node.state['recent_transit_cursors'][peer]='f'*64;node.save()
            bundle=node.exchange(peer);limit=len(wire.canonical(dict(bundle['body'],transits=bundle['body']['transits'][:1])))+513
            seen=set();expected=set(node.state['messages'])
            with patch.object(mesh,'MAX_BATCH',limit):
                for _ in range(25):
                    selected=node.prepare_exchange(peer);self.assertEqual(len(selected['body']['transits']),1)
                    seen.update(mesh.digest(t['packet']) for t in selected['body']['transits'])
            self.assertEqual(seen,expected);self.assertEqual(node.state['transit_cursors'][peer],sorted(expected)[-1])
            self.assertFalse(node.state['receipts'])

    def test_failed_spool_write_still_rotates_only_that_peer_and_keeps_all_packets(self):
        f=self.fixture(5);peer=f.ids[1];root=f.root/'links'
        f.configs[0]['contacts'][0]={'peer':peer,'inbox':str(root/'in'),'outbox':str(root/'out')}
        with f.node(0) as node:
            expected=copy.deepcopy(node.state['messages']);real=mesh.evidence.write_new
            def fail_contact(path,raw):
                if path.parent==root/'out':raise OSError('injected spool failure')
                return real(path,raw)
            with patch.object(mesh.evidence,'write_new',side_effect=fail_contact):result=node.tick()
            self.assertIn('injected spool failure',result['errors']);self.assertEqual(node.state['messages'],expected)
            self.assertEqual(node.state['transit_cursors'][peer],sorted(expected)[3])
            self.assertTrue(all(node.state['transit_cursors'][p] is None for p in f.ids[2:]))
        with f.node(0) as node:self.assertEqual(node.state['messages'],expected)

    def test_failed_sends_spend_full_four_slots_on_distinct_pending_packets(self):
        f=self.fixture(25)
        with f.node(0) as node:
            seen=set()
            for _ in range(6):
                batch={mesh.digest(t['packet']) for t in tcp.outgoing(node,f.ids[1])['body']['transits']}
                self.assertEqual(len(batch),4);self.assertFalse(seen&batch);seen.update(batch)
            self.assertEqual(len(seen),24)
            batch={mesh.digest(t['packet']) for t in tcp.outgoing(node,f.ids[1])['body']['transits']}
            self.assertEqual(seen|batch,set(node.state['messages']));self.assertFalse(node.state['receipts'])

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
            ordered=sorted(node.state['messages']);first=node.prepare_exchange(peer)
            self.assertEqual([mesh.digest(t['packet']) for t in first['body']['transits']],ordered[:4])
        with f.node(2) as destination:
            destination.receive(first,f.ids[0])
            reply=destination.exchange(f.ids[0])
        with f.node(0) as node:
            node.receive(reply,peer)
            self.assertEqual(node.archive_completed(),4)
            self.assertEqual(set(node.state['archives']),set(ordered[:4]))
            self.assertTrue(all(i not in node.state['messages'] for i in ordered[:4]))
            self.assertTrue(all(i not in node.state['recent_transits'] for i in ordered[:4]))
            actual=[mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']]
            self.assertEqual(actual,ordered[4:8])
            # The previous rank of four would have selected original rows 8..11.
            self.assertEqual(sorted(node.state['messages'])[4:8],ordered[8:12])
            for ident in ordered[:4]:
                self.assertIsNotNone(node.transit(ident));mesh.receipt_matches(node.receipts()[ident],node.transit(ident))
        with f.node(0) as node:
            self.assertEqual(node.state['transit_cursors'][peer],ordered[7])
            self.assertEqual(set(node.state['archives']),set(ordered[:4]))

    def test_insertion_before_last_id_does_not_repeat_or_skip_original_successors(self):
        f=self.fixture(25);peer=f.ids[2]
        with f.node(0) as node:
            ordered=sorted(node.state['messages']);node.prepare_exchange(peer)
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"insertion":true}')
            # Search a nonce without mutating the pool: this regression isolates
            # the single-class identity successor from separate class fairness.
            for serial in range(1024):
                nonce=hashlib.sha256(str(serial).encode()).digest()
                packet=mesh.sign(node.key,'packet',dict(format=mesh.VERSION,network=node.network,
                    node_id=node.id,destination=peer,nonce=nonce.hex(),hop_limit=mesh.MAX_HOPS,
                    frame=base64.b64encode(frame).decode()))
                if mesh.digest(packet)<ordered[3]:break
            else:self.fail('no insertion nonce found')
            with patch.object(mesh.os,'urandom',return_value=nonce):added=[node.enqueue(frame,peer)]
            self.assertLess(added[0],ordered[3])
            received=[mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']]
            original_successors=[i for i in received if i in set(ordered)]
            self.assertEqual(original_successors,ordered[4:4+len(original_successors)])
            self.assertFalse(set(received)&set(ordered[:4]))
            self.assertEqual(set(node.state['messages']),set(ordered)|set(added))


if __name__=='__main__':unittest.main()
