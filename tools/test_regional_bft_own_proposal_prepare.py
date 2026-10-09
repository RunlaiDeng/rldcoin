"""Exact Runtime scheduling boundaries; synthetic Native grants no authority."""
import copy
from contextlib import nullcontext
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from regional_bft_node import FORMAT,ORIGIN_RUNTIME_FORMAT,Runtime
from regional_bft_retention import Messages
import test_regional_contact_observation_scope as service_fixture
from test_regional_bft_finalization_eligibility import RecordingRuntime


class OwnProposalRuntime(RecordingRuntime):
    def __init__(self,refusal=None,phase_change=None):
        super().__init__(prepare_count=0,commit_count=0,active_prepared=False)
        self.format=ORIGIN_RUNTIME_FORMAT;self.key='b'
        self.active['proposed']=False;self.proposal=None
        self.slot=(mesh.digest(self.context),0);self.entered_at=time.monotonic()-2
        self.refusal=refusal;self.phase_change=phase_change
    def signed(self,context,round_number,kind,phase=None,value=None):
        if kind=='Proposal' and self.proposal is not None and round_number==self.proposal['round']:
            return [(self.proposal,self.value)]
        return []
    def candidate(self,context,high=None):
        self.events.append(('native-candidate',None))
        return {'model_complete_candidate':True}
    def sign(self,request):
        kind,payload=next(iter(request.items()));self.events.append(('native-sign',kind))
        if self.refusal==kind:raise ValueError('Native refused '+kind)
        if kind=='Propose':
            self.active.update(proposed=True,round=payload['round'])
            self.proposal=dict(copy.deepcopy(payload),leader={'key':self.key})
            self.events.append(('separate-caller-retained','Propose'))
            if self.refusal=='retain':raise OSError('complete envelope retention failed')
            self.events.append(('complete-envelope-retained','Propose'))
            if self.phase_change:self.active.update(self.phase_change)
        elif kind=='Prepare':
            self.assert_exact=copy.deepcopy(payload)
            self.active['prepared']=self.value
            self.events.append(('separate-caller-retained','Prepare'))
        else:raise AssertionError(kind)
    def _try_prepare(self,proposal):
        self.sign({'Prepare':proposal});return True


class OwnProposalPrepareTests(unittest.TestCase):
    def test_early_and_tail_carriage_share_one_attempt_even_after_failure_or_reobservation(self):
        r=Runtime.__new__(Runtime)
        r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None;r.node_id='own';r.peers={}
        r.state={'messages':Messages()};r.transport={};r._tick_operation=object()
        with patch.object(mesh,'Node',side_effect=OSError('mesh lock refused')) as opening:
            with self.assertRaisesRegex(OSError,'mesh lock'):r.broadcast()
            r._tick_operation=object()  # Native phase reobservation in the same unit
            r.broadcast()
            self.assertEqual(opening.call_count,1)
            r._tick=lambda:r.broadcast()
            with self.assertRaisesRegex(OSError,'mesh lock'):r.tick()
            self.assertEqual(opening.call_count,2)
            r.format=FORMAT
            for _ in range(2):
                with self.assertRaises(OSError):r.broadcast()
            self.assertEqual(opening.call_count,4)

    def test_service_moves_one_directory_batch_and_restores_hook_after_prepare_refusal(self):
        for refuse in (False,True):
            f=service_fixture.ObservationScopeTests(methodName='runTest');s=f.service()
            s.config={'contacts':[{'outbox':'modeled-spool'}]}
            s.bft.format=ORIGIN_RUNTIME_FORMAT;s.bft.joint=None
            s.receive_candidates=lambda *_:[]
            phases=[]
            node=SimpleNamespace(id='node',state={'adverts':{}},tick=lambda **_:dict(errors=[]),
                summaries=lambda:{},receipts=lambda:{},
                flush_spool_outgoing=lambda:phases.append('directory-batch') or [])
            s.selection_node=lambda:nullcontext(node)
            s.tcp.ordinary_mesh_node=lambda:nullcontext(node)
            s.wait_initial_proposal=lambda *_:False
            s.continue_after_finalization=lambda *_:False
            original=lambda:None;s.bft.after_local_proposal=original
            s.bft.broadcast=lambda:phases.append('enqueue')
            def tick():
                phases.append('complete-proposal-retained')
                s.bft.after_local_proposal()
                phases.append('own-prepare')
                if refuse:raise ValueError('Native Prepare refused')
                return {}
            s.bft.tick=tick
            f.tick(s)
            self.assertEqual(phases,['complete-proposal-retained','enqueue','directory-batch','own-prepare'])
            self.assertIs(s.bft.after_local_proposal,original)

    def test_service_can_publish_complete_proposal_before_fallible_own_prepare(self):
        r=OwnProposalRuntime(refusal='Prepare')
        r.after_local_proposal=lambda:r.events.append(('service-carriage',None))
        with self.assertRaisesRegex(ValueError,'Native refused Prepare'):r._tick()
        self.assertLess(r.events.index(('complete-envelope-retained','Propose')),
                        r.events.index(('service-carriage',None)))
        self.assertLess(r.events.index(('service-carriage',None)),
                        r.events.index(('native-sign','Prepare')))
        self.assertNotIn(('finalize',None),r.events)

    def test_proposal_sign_or_retention_refusal_never_releases_early_carriage(self):
        for refusal in ('Propose','retain'):
            r=OwnProposalRuntime(refusal=refusal)
            r.after_local_proposal=lambda:r.events.append(('service-carriage',None))
            with self.assertRaises((ValueError,OSError)):r._tick()
            self.assertNotIn(('service-carriage',None),r.events)

    def test_early_carriage_failure_preserves_proposal_and_prevents_next_first_sign(self):
        r=OwnProposalRuntime()
        def failed():raise OSError('carriage publication incomplete')
        r.after_local_proposal=failed
        with self.assertRaisesRegex(OSError,'publication incomplete'):r._tick()
        self.assertIn(('complete-envelope-retained','Propose'),r.events)
        self.assertNotIn(('native-sign','Prepare'),r.events)

    def test_own_proposal_is_fully_retained_before_native_prepare_this_unit(self):
        r=OwnProposalRuntime();r._tick()
        self.assertEqual([e for e in r.events if e[0]=='native-sign'],
                         [('native-sign','Propose'),('native-sign','Prepare')])
        self.assertLess(r.events.index(('complete-envelope-retained','Propose')),
                        r.events.index(('native-sign','Prepare')))
        self.assertEqual(r.assert_exact,r.proposal)
        self.assertEqual(r.events.count(('broadcast',None)),1)
        self.assertNotIn(('finalize',None),r.events)
    def test_failed_proposal_or_retention_never_prepare_or_broadcast(self):
        for refusal in ('Propose','retain'):
            r=OwnProposalRuntime(refusal=refusal)
            with self.assertRaises((ValueError,OSError)):r._tick()
            self.assertNotIn(('native-sign','Prepare'),r.events)
            self.assertNotIn(('broadcast',None),r.events)
    def test_native_prepare_refusal_preserves_proposal_without_retry(self):
        r=OwnProposalRuntime(refusal='Prepare')
        with self.assertRaisesRegex(ValueError,'Native refused Prepare'):r._tick()
        self.assertIn(('complete-envelope-retained','Propose'),r.events)
        self.assertEqual(r.events.count(('native-sign','Prepare')),1)
        self.assertNotIn(('finalize',None),r.events)
    def test_changed_phase_context_or_complete_candidate_cannot_continue(self):
        for change in ({'context':{'parent_height':99}},{'round':1},
                       {'proposed':False},{'prepared':'different'},{'committed':'different'}):
            r=OwnProposalRuntime(phase_change=change);r._tick()
            self.assertNotIn(('native-sign','Prepare'),r.events)
        r=OwnProposalRuntime()
        original=r.signed
        def altered(*args,**kw):
            rows=copy.deepcopy(original(*args,**kw))
            for p,_ in rows:p['snapshot']={'different_complete_candidate':True}
            return rows
        r.signed=altered;r._tick()
        self.assertNotIn(('native-sign','Prepare'),r.events)
    def test_existing_proposal_keyless_and_other_profiles_keep_original_path(self):
        r=OwnProposalRuntime();r.format=FORMAT;r._tick()
        self.assertEqual([e for e in r.events if e[0]=='native-sign'],[('native-sign','Propose')])
        r=OwnProposalRuntime();r.key_file=None;r._tick()
        self.assertFalse(any(e[0]=='native-sign' for e in r.events))
        r=OwnProposalRuntime();r.proposal={'round':0};r._tick()
        self.assertEqual([e for e in r.events if e[0]=='native-sign'],[('native-sign','Prepare')])
    def test_future_certified_leader_continues_only_the_exact_selected_round(self):
        r=OwnProposalRuntime();r.key='d'
        original=r.signed
        def signed(context,round_number,kind,*args):
            if kind=='Timeout' and round_number==1:
                return [(dict(context=context,round=1,high=None,approval={'key':key}),None)
                        for key in 'abc']
            return original(context,round_number,kind,*args)
        r.signed=signed
        original_json=r.with_json
        r.with_json=lambda action,body,*args:({'votes':body} if action=='bft-timeout-certificate'
                                             else original_json(action,body,*args))
        r._tick()
        self.assertEqual(r.assert_exact['round'],2)
        self.assertEqual(r.active['round'],2)
        self.assertEqual([e for e in r.events if e[0]=='native-sign'],
                         [('native-sign','Propose'),('native-sign','Prepare')])


if __name__=='__main__':unittest.main()
