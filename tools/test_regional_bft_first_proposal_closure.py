"""Bounded carriage scheduling models; none authenticates a Native envelope."""
import copy
from types import SimpleNamespace
import unittest

from regional_bft_node import carriage_batch, carriage_frontier
from test_regional_bft_proposal_carriage import CONTEXT
import test_regional_bft_proposal_carriage as proposal_fixture
from test_regional_bft_own_proposal_prepare import OwnProposalRuntime


class FirstProposalClosureTests(unittest.TestCase):
    def fixture(self, peers='abc'):
        messages, pending, rows=proposal_fixture.ProposalCarriageTests().fixture()
        rows.extend((f'h{i:03}', {'Finalized':{'statement':{'height':9}}}, 'history', True)
                    for i in range(40))
        pending=[(ident,ident,peer) for ident,_,_,_ in rows for peer in peers]
        return messages,pending,rows

    def choose(self,messages,pending,peers='abc',**kw):
        return carriage_batch(messages,pending,0,0,prepare_first=True,
            proposal_context=CONTEXT,first_proposal=(0,'own',tuple(peers)),**kw)

    def test_actual_two_two_counter_has_three_proposal_one_history_closure(self):
        messages,pending,_=self.fixture()
        # Match the observed first unit: fresh Proposal sorts before history.
        pending.sort(key=lambda p:(p[1]!='p',p))
        old=carriage_batch(messages,pending,0,0,prepare_first=True,proposal_context=CONTEXT)
        new=self.choose(messages,pending)
        self.assertEqual(sum(p[1]=='p' for p in old),2)
        self.assertEqual({p[2] for p in new if p[1]=='p'},set('abc'))
        self.assertEqual(sum(p[1].startswith('h') for p in new),1)
        self.assertEqual(len(new),4);self.assertEqual(len(set(new)),4)

    def test_one_two_three_and_more_recipients_preserve_capacity_and_history(self):
        for peers in ('a','ab','abc','abcd','abcdefghijklmnop'):
            messages,pending,_=self.fixture(peers)
            new=self.choose(messages,pending,peers)
            self.assertLessEqual(len(new),4);self.assertEqual(len(new),len(set(new)))
            self.assertTrue(any(p[1].startswith('h') for p in new))
            if len(peers)<=3:self.assertEqual({p[2] for p in new if p[1]=='p'},set(peers))
            else:self.assertEqual(new,carriage_batch(messages,pending,0,0,
                prepare_first=True,proposal_context=CONTEXT))

    def test_replay_reconnect_and_missing_recipient_use_ordinary_fair_frontier(self):
        messages,pending,_=self.fixture()
        first=self.choose(messages,pending)
        position=carriage_frontier(messages,first,0)
        retained={(p[0],p[2]) for p in first}
        for cursor in range(4,260,4):
            # A reconnect/restart has no first-publication hint. Original bytes
            # stay pending until actually enqueued, including historical pairs.
            waiting=[p for p in pending if (p[0],p[2]) not in retained]
            chosen=carriage_batch(messages,waiting,0,cursor,prepare_first=True,
                proposal_context=CONTEXT,class_position=position)
            self.assertLessEqual(len(chosen),4)
            retained.update((p[0],p[2]) for p in chosen)
            position=carriage_frontier(messages,chosen,0,position)
        self.assertEqual(retained,{(p[0],p[2]) for p in pending})
        partial=[p for p in pending if not(p[1]=='p' and p[2]=='b')]
        self.assertEqual(self.choose(messages,partial),carriage_batch(messages,partial,0,0,
            prepare_first=True,proposal_context=CONTEXT))

    def test_continuous_bounded_fresh_proposals_cannot_starve_original_history(self):
        messages,_,rows=self.fixture();retained=set();position=(None,None)
        initial={(i,peer) for i,_,_,_ in rows if i.startswith('h') for peer in 'abc'}
        for step in range(140):
            proposal=copy.deepcopy(rows[0][1]);proposal['Signed']['Proposal']['round']=step%32
            # Exact old proposals are not simultaneous candidates for the newly
            # released round: remove only this model's ephemeral current row.
            rows[:1]=[(f'p{step:03}',proposal,'native-modeled-value',True)]
            pending=[(i,i,peer) for i,_,_,_ in rows for peer in 'abc' if (i,peer) not in retained]
            chosen=carriage_batch(messages,pending,0,step*4,prepare_first=True,
                proposal_context=CONTEXT,class_position=position,
                first_proposal=(step%32,'own',tuple('abc')))
            if not initial<=retained:self.assertTrue(any(p[1].startswith('h') for p in chosen))
            self.assertLessEqual(len(chosen),4)
            retained.update((i,peer) for _,i,peer in chosen)
            position=carriage_frontier(messages,chosen,0,position)
        self.assertTrue(initial<=retained)

    def test_conflicting_metadata_wrong_round_key_context_and_no_native_value_fall_back(self):
        for change in ('ambiguous','round','key','context','value','remote','wrong-height'):
            messages,pending,rows=self.fixture();hint=(0,'own',tuple('abc'));context=CONTEXT
            if change=='ambiguous':
                rows.append(('q',copy.deepcopy(rows[0][1]),'different',True))
                pending.extend(('q','q',peer) for peer in 'abc')
            elif change=='round':hint=(1,'own',tuple('abc'))
            elif change=='key':hint=(0,'another',tuple('abc'))
            elif change=='context':context=None
            elif change=='wrong-height':context=dict(CONTEXT,parent_height=1)
            elif change=='value':rows[0]=(*rows[0][:2],None,True)
            else:rows[0]=(*rows[0][:3],False)
            original=copy.deepcopy(rows)
            self.assertEqual(carriage_batch(messages,pending,0,0,prepare_first=True,
                proposal_context=context,first_proposal=hint),carriage_batch(messages,pending,0,0,
                prepare_first=True,proposal_context=context),change)
            self.assertEqual(rows,original)

    def test_first_publication_hint_is_scoped_to_successful_propose_and_cleared_on_failure(self):
        for failure in (False,True):
            runtime=OwnProposalRuntime(refusal='Prepare' if not failure else None)
            seen=[]
            def publish():
                seen.append(runtime._first_proposal_carriage)
                if failure:raise OSError('publication refused')
            runtime.after_local_proposal=publish
            with self.assertRaises((ValueError,OSError)):runtime._tick()
            self.assertEqual(seen,[(0,runtime.key)])
            self.assertIsNone(runtime._first_proposal_carriage)
        for refusal in ('Propose','retain'):
            runtime=OwnProposalRuntime(refusal=refusal);runtime.after_local_proposal=lambda:None
            with self.assertRaises((ValueError,OSError)):runtime._tick()
            self.assertIsNone(getattr(runtime,'_first_proposal_carriage',None))

    def test_invalid_hint_and_disabled_dependency_path_do_not_change_selection(self):
        messages,pending,_=self.fixture()
        old=carriage_batch(messages,pending,0,0,prepare_first=True,proposal_context=CONTEXT)
        for hint in (None,[],(True,'own',tuple('abc')),(-1,'own',tuple('abc')),
                     (32,'own',tuple('abc')),(0,'own',('a','a','c')),
                     (0,'own',('a','b','other')),(0,'own',['a','b','c'])):
            self.assertEqual(carriage_batch(messages,pending,0,0,prepare_first=True,
                proposal_context=CONTEXT,first_proposal=hint),old)
        self.assertEqual(carriage_batch(messages,pending,0,0,proposal_context=CONTEXT,
            first_proposal=(0,'own',tuple('abc'))),carriage_batch(messages,pending,0,0))


if __name__=='__main__':unittest.main()
