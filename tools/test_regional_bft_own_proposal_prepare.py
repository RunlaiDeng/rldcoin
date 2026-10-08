"""Exact Runtime scheduling boundaries; synthetic Native grants no authority."""
import copy
import time
import unittest

import interstellar_mesh as mesh
from regional_bft_node import FORMAT,ORIGIN_RUNTIME_FORMAT
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
