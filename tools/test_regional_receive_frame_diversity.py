"""Exact frame scheduling models; no Native authentication or value authority."""
from types import SimpleNamespace
import copy
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import ORIGIN_RUNTIME_FORMAT, FORMAT
from regional_bft_retention import Messages, ORIGIN_NETWORK
from regional_contact_node import Service
from test_regional_contact_receive_ring import ident


class FrameDiversityTests(unittest.TestCase):
    def fixture(self):
        envelope=dict(format=ORIGIN_NETWORK,currency=ident(700),region=ident(701),
            evidence={'snapshots':[]},origins=[],body={'Finalized':{'statement':{'height':2}}})
        record=mesh.digest(envelope['body']);content=mesh.digest(envelope)
        messages=Messages().append(record,envelope,None,True)
        runtime=SimpleNamespace(format=ORIGIN_RUNTIME_FORMAT,joint=None,
            _retained_native_authenticated=True,region=ident(701),state={'messages':messages})
        service=Service.__new__(Service);service.bft=runtime;service.bft_seen=set()
        service.receive_after={'novel':None,'background':None};service.progress={'cursor':0}
        raw=wire.make_frame('regional-bft',runtime.region,runtime.region,content,wire.canonical(envelope))
        frames={ident(n):raw for n in range(1,13)}
        summaries={i:dict(destination=ident(777),kind='regional-bft',export_id=content) for i in frames}
        receipts={i:True for i in frames};node=SimpleNamespace(network=ident(700),transit=lambda i:frames[i])
        return service,node,summaries,receipts,frames,envelope

    def classifier(self,service,node,summaries,receipts):
        return service.retained_frame_classifier(node,summaries,receipts)

    def patches(self):
        return (patch.object(mesh,'transit_check',side_effect=lambda raw,network:({},raw,())),
                patch.object(mesh,'receipt_matches'))

    def test_literal_complete_bytes_and_receipt_are_required_before_grouping(self):
        service,node,summaries,receipts,frames,envelope=self.fixture()
        a,b=self.patches()
        with a,b as receipt:
            classify=self.classifier(service,node,summaries,receipts)
            self.assertIsNotNone(classify(ident(1)));receipt.assert_called_once()
            changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'different':'proof'}]
            frames[ident(2)]=wire.make_frame('regional-bft',service.bft.region,service.bft.region,
                                           summaries[ident(2)]['export_id'],wire.canonical(changed))
            self.assertIsNone(classify(ident(2))) # even with a forged retained digest hint.
            frames[ident(3)]=wire.make_frame('regional-bft',ident(702),ident(702),
                                           summaries[ident(3)]['export_id'],wire.canonical(envelope))
            self.assertIsNone(classify(ident(3)))
            receipt.side_effect=ValueError('receipt mismatch')
            self.assertIsNone(classify(ident(1)))

    def test_changed_conflict_or_signature_bytes_keep_normal_selection_and_authentication(self):
        service,node,summaries,receipts,frames,envelope=self.fixture()
        changed=copy.deepcopy(envelope);changed['body']['Finalized']['statement']['height']=3
        frames[ident(2)]=wire.make_frame('regional-bft',service.bft.region,service.bft.region,
            summaries[ident(2)]['export_id'],wire.canonical(changed))
        corrupted=copy.deepcopy(envelope);corrupted['body']['Finalized']['bad_signature']='00'*64
        frames[ident(3)]=wire.make_frame('regional-bft',service.bft.region,service.bft.region,
            summaries[ident(3)]['export_id'],wire.canonical(corrupted))
        a,b=self.patches()
        with a,b:
            quota=dict(attempted=set(),novel=0,background=0)
            chosen=service.receive_candidates(summaries,receipts,ident(777),quota,
                self.classifier(service,node,summaries,receipts))
        self.assertEqual(chosen,[ident(1),ident(2),ident(3)])
        self.assertEqual(service.bft_seen,set())
        called=[];service.contact_trace=None;service.bft_individual_retry=False
        def receive(rows):called.extend(rows);raise ValueError('Native rejected conflict/forged envelope')
        service.bft.receive_many=receive
        errors=[];rejected=[];deferred=[]
        service.receive_bft_batch([(i,frames[i]) for i in chosen],errors,rejected,deferred)
        self.assertEqual(called,[frames[i] for i in chosen]);self.assertEqual(len(rejected),3)
        self.assertEqual(service.bft_seen,set())

    def test_deferred_exact_copies_rotate_and_restart_without_seen_authority(self):
        service,node,summaries,receipts,frames,envelope=self.fixture();seen=set()
        a,b=self.patches()
        with a,b:
            for _ in range(12):
                quota=dict(attempted=set(),novel=0,background=0)
                chosen=service.receive_candidates(summaries,receipts,ident(777),quota,
                    self.classifier(service,node,summaries,receipts))
                self.assertEqual(len(chosen),1);seen.update(chosen)
                self.assertEqual(len(quota['attempted']),1)
                self.assertEqual(len(quota['frames']),1)
        self.assertEqual(seen,set(frames));self.assertEqual(service.bft_seen,set())
        # A restart does not deserialize a frame witness or mark copies seen.
        service.receive_after={'novel':None,'background':None}
        a,b=self.patches()
        with a,b:
            self.assertEqual(service.receive_candidates(summaries,receipts,ident(777),
                dict(attempted=set(),novel=0,background=0),self.classifier(service,node,summaries,receipts)),[ident(1)])

    def test_distinct_groups_and_novel_class_share_the_original_four_inspections(self):
        service,node,summaries,receipts,frames,envelope=self.fixture()
        second=copy.deepcopy(envelope);second['body']['Finalized']['statement']['height']=1
        record=mesh.digest(second['body']);content=mesh.digest(second)
        service.bft.state['messages']=service.bft.state['messages'].append(record,second,None,True)
        frames[ident(2)]=wire.make_frame('regional-bft',service.bft.region,service.bft.region,
                                        content,wire.canonical(second))
        summaries[ident(2)]['export_id']=content
        for n in (20,21):
            frames[ident(n)]=b'not a retained frame'
            summaries[ident(n)]=dict(destination=ident(777),kind='regional-bft',export_id=ident(n+900))
            receipts[ident(n)]=True
        a,b=self.patches()
        with a as transport,b:
            quota=dict(attempted=set(),novel=0,background=0)
            chosen=service.receive_candidates(summaries,receipts,ident(777),quota,
                self.classifier(service,node,summaries,receipts))
        self.assertEqual(chosen,[ident(20),ident(21),ident(1),ident(2)])
        self.assertEqual((quota['novel'],quota['background']),(2,2))
        self.assertEqual(len(quota['frames']),2)
        self.assertEqual(transport.call_count,4) # complete transport checked even for unknown frames; Native still checks selected inputs.
        self.assertEqual(service.bft_seen,set())

    def test_without_native_retention_witness_or_outside_origin_profile_no_grouping(self):
        for mode in ('unverified','legacy','joint'):
            service,node,summaries,receipts,frames,envelope=self.fixture()
            if mode=='unverified':service.bft._retained_native_authenticated=False
            elif mode=='legacy':service.bft.format=FORMAT
            else:service.bft.joint=object()
            self.assertIsNone(self.classifier(service,node,summaries,receipts))
            self.assertEqual(service.receive_candidates(summaries,receipts,ident(777),
                dict(attempted=set(),novel=0,background=0)),[ident(1),ident(2),ident(3),ident(4)])


if __name__=='__main__':unittest.main()
