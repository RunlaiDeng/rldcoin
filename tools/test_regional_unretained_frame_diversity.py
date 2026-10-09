"""Exact complete-frame scheduling only; no Native/value authentication."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages
from regional_contact_node import MAX_PER_TICK
import test_regional_receive_frame_diversity as retained_tests
from test_regional_contact_receive_ring import ident

class UnretainedFrameDiversityTests(unittest.TestCase):
    def fixture(self):
        s,node,rows,receipts,frames,envelope=retained_tests.FrameDiversityTests().fixture()
        s.bft.state['messages']=Messages()
        ids=[ident(n) for n in range(1,5)]
        for n in (2,3):
            e=copy.deepcopy(envelope);e['body']['Finalized']['statement']['height']=n+2
            content=mesh.digest(e);rows[ident(n)]['export_id']=content
            frames[ident(n)]=wire.make_frame('regional-bft',s.bft.region,s.bft.region,content,wire.canonical(e))
        for i in list(rows):
            if i not in ids:del rows[i];del receipts[i]
        return s,node,rows,receipts,frames,envelope

    def test_first_encounter_exact_copy_leaves_original_slot_for_late_submission(self):
        s,node,rows,receipts,frames,envelope=self.fixture();quota=dict(attempted=set(),novel=0,background=0)
        with patch.object(mesh,'transit_check',side_effect=lambda raw,network:({},raw,())),patch.object(mesh,'receipt_matches'):
            first=s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts))
            self.assertEqual(first,[ident(1),ident(2),ident(3)])
            e=copy.deepcopy(envelope);e['body']={'Submission':[]};content=mesh.digest(e);i=ident(5)
            rows[i]=dict(destination=ident(777),kind='regional-bft',export_id=content);receipts[i]=True
            frames[i]=wire.make_frame('regional-bft',s.bft.region,s.bft.region,content,wire.canonical(e))
            late=s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts))
            self.assertEqual(late,[i]);self.assertEqual(len(quota['attempted']),MAX_PER_TICK)
        self.assertEqual(s.bft_seen,set());self.assertIn(ident(4),receipts)

    def test_received_first_copy_still_matches_same_unit_literal_bytes(self):
        s,node,rows,receipts,frames,envelope=self.fixture();quota=dict(attempted=set(),novel=0,background=0)
        with patch.object(mesh,'transit_check',side_effect=lambda raw,network:({},raw,())),patch.object(mesh,'receipt_matches'):
            first=s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts,quota))
            s.bft.state['messages']=Messages().append(mesh.digest(envelope['body']),envelope,None,False)
            s.bft_seen.update(first)
            self.assertEqual(s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts,quota)),[])
            self.assertNotIn(ident(4),s.bft_seen)
            fresh=dict(attempted=set(),novel=0,background=0)
            self.assertEqual(s.receive_candidates(rows,receipts,ident(777),fresh,s.retained_frame_classifier(node,rows,receipts,fresh)),[ident(4)])

    def test_changed_proof_signature_and_region_are_never_literal_copies(self):
        for mode in ('proof','signature','region'):
            s,node,rows,receipts,frames,envelope=self.fixture();e=copy.deepcopy(envelope)
            if mode=='proof':e['evidence']['snapshots']=[{'changed':'complete proof'}]
            elif mode=='signature':e['body']['Finalized']['bad_signature']='00'*64
            else:e['region']=ident(702)
            content=mesh.digest(e);rows[ident(4)]['export_id']=content
            region=e['region'];frames[ident(4)]=wire.make_frame('regional-bft',region,region,content,wire.canonical(e))
            with patch.object(mesh,'transit_check',side_effect=lambda raw,network:({},raw,())),patch.object(mesh,'receipt_matches'):
                quota=dict(attempted=set(),novel=0,background=0)
                self.assertEqual(len(s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts,quota))),4)
            self.assertEqual(s.bft_seen,set())

    def test_transport_or_receipt_failure_retains_normal_reception_and_no_group(self):
        for mode in ('transit','receipt'):
            s,node,rows,receipts,frames,_=self.fixture()
            with patch.object(mesh,'transit_check',side_effect=ValueError('invalid transit') if mode=='transit' else lambda raw,network:({},raw,())),patch.object(mesh,'receipt_matches',side_effect=ValueError('invalid receipt') if mode=='receipt' else None):
                quota=dict(attempted=set(),novel=0,background=0)
                self.assertEqual(len(s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts,quota))),4)
                self.assertEqual(quota['frames'],set())
            self.assertEqual(s.bft_seen,set())

    def test_capacity_fallback_preserves_all_attempts_and_native_refusal(self):
        import regional_contact_node as contact
        s,node,rows,receipts,frames,_=self.fixture()
        with patch.object(mesh,'transit_check',side_effect=lambda raw,network:({},raw,())),patch.object(mesh,'receipt_matches'),patch.object(contact,'MAX_NATIVE_OUTPUT',1):
            quota=dict(attempted=set(),novel=0,background=0)
            chosen=s.receive_candidates(rows,receipts,ident(777),quota,s.retained_frame_classifier(node,rows,receipts,quota))
        self.assertEqual(len(chosen),4);self.assertEqual(quota['frames'],set())
        calls=[];s.contact_trace=None;s.bft_individual_retry=False
        def refuse(raws):calls.extend(raws);raise ValueError('Native complete authentication refused')
        s.bft.receive_many=refuse;errors=[];rejected=[];deferred=[]
        s.receive_bft_batch([(i,frames[i]) for i in chosen],errors,rejected,deferred)
        self.assertEqual(calls,[frames[i] for i in chosen]);self.assertEqual(len(rejected),4)
        self.assertEqual(s.bft_seen,set())

if __name__=='__main__':unittest.main()
