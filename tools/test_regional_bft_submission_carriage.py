"""Finite no-value scheduling models, never Native authentication or authority.

Complete fixture metadata below includes deliberately empty snapshot blocks and
synthetic commands; these cannot authorize value or a Native vote. Tests isolate
immutable byte, role, queue, fairness and Runtime authorization boundaries.
"""
import copy
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
from regional_bft_retention import Messages
from regional_bft_node import (submission_carriage_pair,carriage_batch,carriage_frontier,
    _carriage_current,Runtime,ORIGIN_RUNTIME_FORMAT,FORMAT,ORIGIN_NETWORK)
from test_regional_bft_parent_carriage import fixture as parent_fixture
from test_regional_bft_carriage_frontier import RuntimeFrontierBoundaryTests


def fixture(commands=None,local=True):
    m,p,c,peers,parent,history,e=parent_fixture()
    if commands is None:commands=[{'synthetic_no_value':True}]
    e=dict(e,body={'Submission':commands},evidence={'snapshots':[]},origins=[])
    ident=mesh.digest(e['body']);m=m.append(ident,e,None,local)
    p=[(m.content(i),i,peer) for i in sorted(m) for peer in sorted(peers.values())]
    return m,p,c,peers,ident,parent,history,e


class SubmissionCarriageTests(unittest.TestCase):
    def choose(self,m,p,c,peers,cursor=0,position=(None,None),round_number=0,**kwargs):
        pair=submission_carriage_pair(m,p,c,peers,round_number)
        chosen=carriage_batch(m,p,c['parent_height'],cursor,prepare_first=True,
            proposal_context=c,class_position=position,submission_pair=pair,**kwargs)
        return chosen,pair

    def test_first_batch_replaces_only_first_history_place_and_preserves_frontier(self):
        m,p,c,peers,i,*_=fixture();priority=submission_carriage_pair(m,p,c,peers,0)
        current=_carriage_current(m,3)
        candidates=[n*4 for n in range(12) if priority not in carriage_batch(m,p,3,n*4)]
        self.assertTrue(candidates)
        for cursor in candidates:
            old=carriage_batch(m,p,3,cursor);selected,pair=self.choose(m,p,c,peers,cursor)
            places=[n for n,x in enumerate(old) if x[1] not in current]
            self.assertIn(pair,selected);self.assertEqual(selected[places[0]],pair)
            self.assertEqual(selected[places[-1]],old[places[-1]])
            self.assertEqual([x for x in selected if x[1] in current],[x for x in old if x[1] in current])
            self.assertEqual(carriage_frontier(m,selected,3),carriage_frontier(m,old,3))
            self.assertEqual(len(selected),len(set(selected)))

    def test_native_context_height_round_and_four_distinct_roles_determine_destination(self):
        m,p,c,peers,*_=fixture()
        for height in (1,3,9):
            for r in (0,1,7,31):
                pair=submission_carriage_pair(m,p,dict(c,parent_height=height),peers,r)
                self.assertEqual(pair[2],peers[sorted(peers)[(height+r)%4]])
        for context in (None,{},dict(c,extra='invalid'),dict(c,parent_height=True),dict(c,parent_height=0),dict(c,epoch='bad')):
            self.assertIsNone(submission_carriage_pair(m,p,context,peers,0))
        for r in (None,True,-1,32,'0'):
            self.assertIsNone(submission_carriage_pair(m,p,c,peers,r))
        for roles in ({},dict(list(peers.items())[:3]),dict.fromkeys(peers,'a'*64),{'bad':None,**dict(list(peers.items())[1:])}):
            self.assertIsNone(submission_carriage_pair(m,p,c,roles,0))

    def test_local_exact_domain_original_content_value_and_command_bounds(self):
        m,p,c,peers,i,_,_,e=fixture()
        for commands in ([],[{}]*5,None):
            changed=dict(e,body={'Submission':commands});j=mesh.digest(changed['body'])
            bad=Messages().append(j,changed,None,True)
            self.assertIsNone(submission_carriage_pair(bad,[(bad.content(j),j,x) for x in peers.values()],c,peers,0))
        for change in ('remote','value','currency','region','legacy','epoch'):
            changed=copy.deepcopy(e);local=True;value=None
            if change=='remote':local=False
            elif change=='value':value='a'*64
            elif change in ('currency','region'):changed[change]='a'*64
            elif change=='legacy':changed['format']='RLD-REGIONAL-BFT-NETWORK-V2';changed.pop('origins')
            else:changed['body']={'EpochSubmission':{'commands':[{}]}}
            j=mesh.digest(changed['body']);bad=Messages().append(j,changed,value,local)
            waiting=[(bad.content(j),j,x) for x in peers.values()]
            self.assertIsNone(submission_carriage_pair(bad,waiting,c,peers,0),change)
        with patch('regional_bft_node.MAX_BROADCAST_HINT_BYTES',1):
            self.assertIsNone(submission_carriage_pair(m,p,c,peers,0))
        wrong=[('0'*64,j,x) for _,j,x in p]
        self.assertIsNone(submission_carriage_pair(m,wrong,c,peers,0))

    def test_already_enqueued_pair_and_restart_use_original_complete_inventory(self):
        m,p,c,peers,i,*_=fixture();pair=submission_carriage_pair(m,p,c,peers,0)
        waiting=[x for x in p if x!=pair]
        self.assertIsNone(submission_carriage_pair(m,waiting,c,peers,0))
        records,snapshots=m.packed();cold=Messages.unpack(records,snapshots)
        self.assertEqual(submission_carriage_pair(cold,p,c,peers,0),pair)
        self.assertIsNone(submission_carriage_pair(cold,waiting,c,peers,0))
        self.assertIsNone(submission_carriage_pair(cold,p,c,peers,None))
        self.assertEqual({i:m.payload(i) for i in m},{i:cold.payload(i) for i in cold})

    def test_complete_payload_refusal_does_not_select_or_mutate_retained_bytes(self):
        m,p,c,peers,*_=fixture();before=m.packed()
        with patch.object(Messages,'payload',side_effect=ValueError('complete bytes refused')):
            with self.assertRaisesRegex(ValueError,'complete bytes refused'):
                submission_carriage_pair(m,p,c,peers,0)
        self.assertEqual(m.packed(),before)
        self.assertIsNotNone(submission_carriage_pair(m,p,c,peers,0))

    def test_history_only_and_new_submission_arrivals_leave_ordinary_history_progress(self):
        m,p,c,peers,i,_,history,e=fixture();waiting=[x for x in p if x[1] not in _carriage_current(m,3)]
        original=set(waiting);retained=set();position=(None,None);before={i:m.payload(i) for i in m}
        for step in range(8):
            remaining=[x for x in waiting if x not in retained]
            selected,_=self.choose(m,remaining,c,peers,step*4,position)
            self.assertLessEqual(len(selected),4);self.assertEqual(len(selected),len(set(selected)))
            retained.update(selected);position=carriage_frontier(m,selected,3,position)
        self.assertEqual(original,retained);self.assertEqual(before,{i:m.payload(i) for i in m})
        # Continuously admitted new local submissions cannot displace the last
        # ordinary history choice or its immutable class frontier.
        m,p,c,peers,*_=fixture();retained=set();position=(None,None);old=set(p)
        for step in range(24):
            extra=dict(e,body={'Submission':[{'synthetic_no_value':step}]});j=mesh.digest(extra['body'])
            if j not in m:m=m.append(j,extra,None,True)
            pending=[(m.content(k),k,x) for k in sorted(m) for x in sorted(peers.values())
                     if (m.content(k),k,x) not in retained]
            selected,_=self.choose(m,pending,c,peers,step*4,position)
            retained.update(selected);position=carriage_frontier(m,selected,3,position)
        self.assertTrue(old<=retained)

    def test_current_parent_and_same_peer_vote_dependencies_keep_their_places(self):
        m,p,c,peers,*_=fixture();parent_pair=next(x for x in p if x[1] in _carriage_current(m,3))
        old=carriage_batch(m,p,3,0,prepare_first=True,proposal_context=c,parent_pair=parent_pair)
        selected,_=self.choose(m,p,c,peers,parent_pair=parent_pair)
        self.assertEqual([x for x in old if x[1] in _carriage_current(m,3)],
                         [x for x in selected if x[1] in _carriage_current(m,3)])

    def test_fresh_three_recipient_proposal_or_prepare_keeps_only_history_place(self):
        m,p,c,peers,i,_,_,e=fixture();key=sorted(peers)[0];recipients=tuple(sorted(peers.values())[:3])
        for phase in ('Proposal','Prepare'):
            if phase=='Proposal':
                statement={k:c[k] for k in ('currency','region','epoch','previous')};statement['height']=4
                body={'Signed':{'Proposal':dict(round=0,snapshot={'statement':statement},leader={'key':key})}}
                option={'first_proposal':(0,key,recipients)}
            else:
                body={'Signed':{'Vote':dict(context=c,round=0,value='a'*64,phase='Prepare',approval={'key':key})}}
                option={'first_prepare':(0,key,recipients)}
            j=mesh.digest(body);extra=dict(e,body=body);messages=m.append(j,extra,'a'*64,True)
            pending=[(messages.content(k),k,x) for k in sorted(messages) for x in recipients]
            old=carriage_batch(messages,pending,3,0,prepare_first=True,proposal_context=c,**option)
            pair=submission_carriage_pair(messages,pending,c,peers,3) # configured peer in recipients
            chosen=carriage_batch(messages,pending,3,0,prepare_first=True,proposal_context=c,submission_pair=pair,**option)
            self.assertEqual(chosen,old);self.assertEqual(sum(x[1]==j for x in chosen),3)

    def test_legacy_disabled_or_nonwaiting_hint_has_no_selection_effect(self):
        m,p,c,peers,*_=fixture();pair=submission_carriage_pair(m,p,c,peers,0)
        for options in ({'submission_pair':pair},{'prepare_first':True,'submission_pair':('missing','missing','missing')}):
            reference=dict(options);reference.pop('submission_pair')
            self.assertEqual(carriage_batch(m,p,3,0,**options),carriage_batch(m,p,3,0,**reference))

    def test_runtime_authentication_profile_and_joint_boundary_is_before_hint(self):
        model=RuntimeFrontierBoundaryTests()
        for change in ('unauthenticated','legacy','joint'):
            r=model.runtime()
            if change=='unauthenticated':r._retained_native_authenticated=False
            elif change=='legacy':r.format=FORMAT
            else:r.joint=SimpleNamespace()
            with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
                 patch('regional_bft_node.submission_carriage_pair',side_effect=AssertionError('unchecked hint')):
                r.broadcast()

    def test_runtime_passes_exact_waiting_pair_only_after_native_retention_boundary(self):
        m,p,c,peers,i,*_=fixture();r=RuntimeFrontierBoundaryTests().runtime()
        r.peers=peers;r.node_id=peers[sorted(peers)[0]];r.region=c['region']
        r._carriage_context=__import__('interstellar_transfer').canonical(c)
        r.state=dict(messages=m,height=3,cursor=0);queued=[]
        @contextmanager
        def carriage():
            def enqueue(batch):queued.extend(batch);return []
            yield SimpleNamespace(id=r.node_id,summaries=lambda:{},
                set_carriage_priority=lambda *_a,**_k:None,enqueue_batch=enqueue)
        r.carriage_node=carriage
        with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
             patch('regional_bft_node.carriage_batch',wraps=carriage_batch) as select:
            r.broadcast()
        pair=select.call_args.kwargs['submission_pair']
        self.assertEqual(pair,(m.content(i),i,peers[sorted(peers)[3]]))
        self.assertLessEqual(len(queued),4)
        self.assertTrue(any(peer==pair[2] for _,peer in queued))
        self.assertEqual(r.state['messages'].payload(i),m.payload(i))

    def test_runtime_complete_close_and_save_failures_do_not_suppress_pending_submission(self):
        m,p,c,peers,*_=fixture();pair=submission_carriage_pair(m,p,c,peers,0)
        model=RuntimeFrontierBoundaryTests()
        for fail in ('open','enqueue','close','save'):
            r=model.runtime();r.failure=fail
            with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
                 patch('regional_bft_node.submission_carriage_pair',return_value=pair):
                with self.assertRaises(OSError):r.broadcast()
            self.assertEqual(submission_carriage_pair(m,p,c,peers,0),pair)


if __name__=='__main__':unittest.main()
