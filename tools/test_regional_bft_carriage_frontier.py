"""Changing pending-list scheduling; synthetic metadata grants no authority."""
import copy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import FORMAT,ORIGIN_RUNTIME_FORMAT,Runtime,carriage_batch,carriage_frontier
from regional_bft_retention import Messages,ORIGIN_NETWORK

CONTEXT=dict(currency='1'*64,region='2'*64,epoch='3'*64,previous='4'*64,
             parent_height=2,parent_block='5'*64,parent_state='6'*64)

class CarriageFrontierTests(unittest.TestCase):
    def fixture(self):
        def vote(parent,phase):
            return {'Signed':{'Vote':dict(context=dict(CONTEXT,parent_height=parent),
                round=0,phase=phase,value='model-value',approval={'key':'model-owner'})}}
        rows=[('650',vote(0,'Prepare'),None,True),('760',vote(1,'Commit'),None,True),
              ('ba6',vote(1,'Prepare'),None,True),('cac',vote(0,'Commit'),None,True),
              ('e9d',{'Signed':{'Proposal':dict(round=0,snapshot={'statement':
                    dict(CONTEXT,height=1)},leader={'key':'model-owner'})}},None,True),
              ('ac4',{'Finalized':{'statement':{'height':2}}},None,True)]
        prepare=('c02',vote(2,'Prepare'),'model-value',True)
        def timeout(ident,round_no):return (ident,{'Signed':{'Timeout':dict(context=CONTEXT,
            round=round_no,high=None,approval={'key':'model-owner'})}},None,True)
        arrivals=[None,prepare,timeout('56e',0),timeout('95c',1),timeout('902',2),None,timeout('fd0',3)]
        return rows,arrivals

    def simulate(self,stable):
        rows,arrivals=self.fixture();retained=set();cursor=0;position=(None,None);choices=[]
        original=copy.deepcopy(rows+list(filter(None,arrivals)))
        for incoming in arrivals:
            if incoming is not None:rows.append(incoming)
            messages=SimpleNamespace(bodies=lambda:iter(rows))
            pending=[(ident,ident,peer) for ident,_,_,_ in sorted(rows)
                     for peer in 'abc' if (ident,peer) not in retained]
            batch=carriage_batch(messages,pending,2,cursor,prepare_first=True,
                proposal_context=CONTEXT,class_position=position if stable else None)
            self.assertLessEqual(len(batch),4);self.assertEqual(len(batch),len(set(batch)))
            active={i for i,b,_,_ in rows if b.get('Finalized') or
                    b.get('Signed',{}).get('Vote',b.get('Signed',{}).get('Timeout',{})).get('context',{}).get('parent_height')==2}
            if any(p[1] in active for p in pending) and any(p[1] not in active for p in pending):
                self.assertGreaterEqual(sum(p[1] in active for p in batch),2)
                self.assertGreaterEqual(sum(p[1] not in active for p in batch),2)
            choices.append(batch);retained.update((ident,peer) for _,ident,peer in batch)
            if stable:position=carriage_frontier(messages,batch,2,position)
            if pending:cursor+=4
        self.assertEqual(rows,original[:6]+original[6:])
        return choices

    def test_growing_timeout_prefix_does_not_withhold_required_prepare(self):
        old=self.simulate(False);new=self.simulate(True);target=('c02','c02','c')
        self.assertFalse(any(target in batch for batch in old))
        self.assertIn(target,new[2])
        self.assertEqual(old[0],new[0])

    def test_insertion_before_seek_and_deletion_of_previous_pair_keep_progress(self):
        rows,_=self.fixture();messages=SimpleNamespace(bodies=lambda:iter(rows))
        pairs=[(ident,ident,peer) for ident in ('ac4','ba6','cac') for peer in 'abc']
        previous=(('ac4','b','ac4'),('ba6','b','ba6'))
        selected=carriage_batch(messages,pairs,2,0,class_position=previous)
        self.assertEqual(selected[:2],[('ac4','ac4','c'),('ac4','ac4','a')])
        without=[p for p in pairs if p!=('ac4','ac4','b') and p!=('ba6','ba6','b')]
        self.assertEqual(carriage_batch(messages,without,2,0,class_position=previous),selected)

    def test_empty_class_keeps_its_position_and_restarts_use_original_selection(self):
        rows,_=self.fixture();messages=SimpleNamespace(bodies=lambda:iter(rows))
        previous=(('ac4','b','ac4'),('ba6','b','ba6'))
        self.assertEqual(carriage_frontier(messages,[('ac4','ac4','c')],2,previous),
                         (('ac4','c','ac4'),previous[1]))
        pending=[('ac4','ac4',p) for p in 'abc']
        self.assertEqual(carriage_batch(messages,pending,2,4),
                         carriage_batch(messages,pending,2,4,class_position=None))

class RuntimeFrontierBoundaryTests(unittest.TestCase):
    """Model only publication boundaries; no Native key, ledger or authority."""
    def runtime(self):
        r=Runtime.__new__(Runtime)
        r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None;r.binding={'model':'no-value'}
        r.native=SimpleNamespace(authority='model-only',currency=CONTEXT['currency'],
                                 ledger=Path('/model-only/no-ledger'))
        r.region=CONTEXT['region'];r.node_id='0'*64;r.peers={'model-key':'a'*64}
        r.transport={'model':'no-connection'};r._retained_native_authenticated=True
        r._carriage_context=wire.canonical(CONTEXT);r._carriage_round=0
        body={'Signed':{'Timeout':dict(context=CONTEXT,round=0,high=None,
                                      approval={'key':'model-only'})}}
        envelope=dict(format=ORIGIN_NETWORK,currency=r.native.currency,region=r.region,
                      body=body,evidence={'snapshots':[]},origins=[])
        messages=Messages().append(mesh.digest(body),envelope,None,True)
        r.state=dict(messages=messages,height=2,cursor=0)
        r.failure=None;r.enqueues=0
        @contextmanager
        def carriage():
            if r.failure=='open':raise OSError('model open refusal')
            def enqueue(batch):
                if r.failure=='enqueue':raise OSError('model enqueue refusal')
                r.enqueues+=len(batch);return []
            node=SimpleNamespace(id=r.node_id,summaries=lambda:{},
                                 set_carriage_priority=lambda *_a,**_k:None,
                                 enqueue_batch=enqueue)
            yield node
            if r.failure=='close':raise OSError('model close refusal')
        r.carriage_node=carriage
        def save(state):
            if r.failure=='save':raise OSError('model save refusal')
            r.state=state
        r.save=save
        return r

    def broadcast(self,r):
        r._broadcast_quiet=None
        with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
             patch('regional_bft_node.carriage_batch',wraps=carriage_batch) as select:
            r.broadcast()
            return select.call_args.kwargs['class_position']

    def test_same_parent_round_change_retains_position_but_changed_trust_resets(self):
        r=self.runtime();self.assertEqual(self.broadcast(r),(None,None))
        prior=r._broadcast_class_position
        r._carriage_round+=1
        self.assertEqual(self.broadcast(r),prior[1])
        self.assertEqual(r._broadcast_class_position[0],prior[0])
        for change in (lambda:setattr(r,'transport',{'model':'changed-pinned-contact'}),
                       lambda:setattr(r,'binding',{'model':'changed-trust'}),
                       lambda:setattr(r,'_carriage_context',wire.canonical(dict(CONTEXT,parent_height=3))),
                       lambda:r.peers.update({'another-model-key':'b'*64})):
            change();self.assertEqual(self.broadcast(r),(None,None))

    def test_failed_publication_capacity_and_non_origin_paths_discard_position(self):
        for failure in ('open','enqueue','close','save'):
            r=self.runtime();self.broadcast(r);self.assertIsNotNone(r._broadcast_class_position)
            r.failure=failure
            with self.assertRaisesRegex(OSError,'model '+failure):self.broadcast(r)
            self.assertIsNone(r._broadcast_class_position)
            r.failure=None;self.assertEqual(self.broadcast(r),(None,None))
        r=self.runtime();self.broadcast(r)
        with patch('regional_bft_node.MAX_CARRIAGE_FRONTIER_BYTES',1):
            self.assertIsNone(self.broadcast(r));self.assertIsNone(r._broadcast_class_position)
        for configure in (lambda r:setattr(r,'format',FORMAT),
                          lambda r:setattr(r,'_retained_native_authenticated',False),
                          lambda r:setattr(r,'_carriage_context',None)):
            r=self.runtime();self.broadcast(r);configure(r)
            self.assertIsNone(self.broadcast(r));self.assertIsNone(r._broadcast_class_position)


if __name__=='__main__':unittest.main()
