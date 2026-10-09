"""Finite first-Prepare carriage models; no Native envelope authority."""
import copy
from types import SimpleNamespace
import unittest

from regional_bft_node import FORMAT, ORIGIN_RUNTIME_FORMAT, Runtime, carriage_batch, carriage_frontier
import test_regional_bft_proposal_carriage as proposal_fixture
import test_regional_bft_carriage_frontier as frontier_fixture

CONTEXT=proposal_fixture.CONTEXT


class FirstPrepareClosureTests(unittest.TestCase):
    def fixture(self,peers='abc',own_proposal=False):
        _,_,rows=proposal_fixture.ProposalCarriageTests().fixture()
        if not own_proposal:rows[0]=(*rows[0][:3],False)
        rows.append(('a',{'Finalized':{'statement':{'height':0}}},'parent',True))
        rows.extend((f'h{i:03}',{'Finalized':{'statement':{'height':9}}},'history',True)
                    for i in range(40))
        messages=SimpleNamespace(bodies=lambda:iter(rows))
        pending=[(i,i,peer) for i,_,_,local in sorted(rows) if local for peer in peers]
        return messages,pending,rows

    def choose(self,messages,pending,peers='abc',**kw):
        return carriage_batch(messages,pending,0,0,prepare_first=True,
            proposal_context=CONTEXT,first_prepare=(0,'own',tuple(peers)),**kw)

    def test_exact_first_batch_omission_becomes_three_prepares_and_one_history(self):
        messages,pending,_=self.fixture()
        old=carriage_batch(messages,pending,0,0,prepare_first=True,proposal_context=CONTEXT)
        self.assertNotIn(('v','v','c'),old)
        new=self.choose(messages,pending)
        self.assertEqual({p[2] for p in new if p[1]=='v'},set('abc'))
        self.assertEqual(sum(p[1].startswith('h') for p in new),1)
        self.assertEqual(len(new),4);self.assertEqual(len(new),len(set(new)))

    def test_one_two_three_and_unsupported_recipient_counts_preserve_bounds(self):
        for peers in ('a','ab','abc','abcd','abcdefghijklmnop'):
            messages,pending,_=self.fixture(peers);new=self.choose(messages,pending,peers)
            self.assertLessEqual(len(new),4);self.assertEqual(len(new),len(set(new)))
            self.assertTrue(any(p[1].startswith('h') for p in new))
            if len(peers)<=3:self.assertEqual({p[2] for p in new if p[1]=='v'},set(peers))
            else:self.assertEqual(new,carriage_batch(messages,pending,0,0,
                prepare_first=True,proposal_context=CONTEXT))

    def test_wrong_metadata_missing_copies_and_ambiguous_candidates_fall_back(self):
        for change in ('context','round','key','value','remote','ambiguous','missing','phase'):
            messages,pending,rows=self.fixture();vote=rows[1][1]['Signed']['Vote']
            if change=='context':vote['context']['parent_block']='another'
            elif change=='round':vote['round']=1
            elif change=='key':vote['approval']['key']='another'
            elif change=='value':rows[1]=(*rows[1][:2],None,True)
            elif change=='remote':rows[1]=(*rows[1][:3],False)
            elif change=='ambiguous':
                rows.append(('x',copy.deepcopy(rows[1][1]),rows[1][2],True))
                pending.extend(('x','x',peer) for peer in 'abc')
            elif change=='missing':pending.remove(('v','v','c'))
            else:vote['phase']='Commit'
            before=copy.deepcopy(rows)
            self.assertEqual(self.choose(messages,pending),carriage_batch(messages,pending,0,0,
                prepare_first=True,proposal_context=CONTEXT),change)
            self.assertEqual(rows,before)

    def test_same_peer_proposal_dependencies_and_fresh_propose_take_precedence(self):
        messages,pending,_=self.fixture(own_proposal=True)
        selected=self.choose(messages,pending)
        self.assertEqual({p[2] for p in selected if p[1]=='p'},set('abc'))
        self.assertEqual(sum(p[1].startswith('h') for p in selected),1)
        self.assertEqual(len(selected),4)
        self.assertEqual(self.choose(messages,pending,first_proposal=(0,'own',tuple('abc'))),
            carriage_batch(messages,pending,0,0,prepare_first=True,
                proposal_context=CONTEXT,first_proposal=(0,'own',tuple('abc'))))

    def test_retained_bounded_new_votes_replay_and_restart_do_not_starve_history(self):
        messages,_,rows=self.fixture();retained=set();position=(None,None)
        initial={(i,peer) for i,_,_,_ in rows if i.startswith('h') for peer in 'abc'}
        for step in range(160):
            if 0<step<32:
                body=copy.deepcopy(rows[1][1]);body['Signed']['Vote']['round']=step
                rows.append((f'w{step:03}',body,'native-modeled-value',True))
            pending=[(i,i,peer) for i,_,_,local in sorted(rows) if local for peer in 'abc'
                     if (i,peer) not in retained]
            # Only a new bounded modeled signature supplies a release hint;
            # later/replayed/cold batches have no hint. No retained row is pruned.
            selected=carriage_batch(messages,pending,0,step*4,prepare_first=True,
                proposal_context=CONTEXT,class_position=position,
                first_prepare=(step,'own',tuple('abc')) if step<32 else None)
            self.assertLessEqual(len(selected),4)
            if not initial<=retained:self.assertTrue(any(p[1].startswith('h') for p in selected))
            retained.update((i,peer) for _,i,peer in selected)
            position=carriage_frontier(messages,selected,0,position)
        self.assertTrue(initial<=retained)
        self.assertEqual(len(rows),74)

    def test_native_sign_success_is_required_to_install_the_small_hint(self):
        def runtime():
            r=Runtime.__new__(Runtime);r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None
            r._retained_native_authenticated=True;r.key='modeled-own';r.sign=lambda _:None
            return r
        r=runtime();self.assertTrue(r._try_prepare({'round':0}))
        self.assertEqual(r._first_prepare_carriage,(0,'modeled-own'))
        for configure in (lambda r:setattr(r,'format',FORMAT),
                          lambda r:setattr(r,'_retained_native_authenticated',False)):
            r=runtime();configure(r);self.assertTrue(r._try_prepare({'round':0}))
            self.assertIsNone(getattr(r,'_first_prepare_carriage',None))
        r=runtime()
        def reject(_):raise OSError('original Native refused')
        r.sign=reject
        with self.assertRaises(OSError):r._try_prepare({'round':0})
        self.assertIsNone(getattr(r,'_first_prepare_carriage',None))

    def test_failed_attempts_clear_hint_but_consumed_propose_unit_cannot_add_another_batch(self):
        fixture=frontier_fixture.RuntimeFrontierBoundaryTests()
        for failure in ('open','enqueue','close','save'):
            r=fixture.runtime();r._first_prepare_carriage=(0,'modeled-own');r.failure=failure
            with self.assertRaises(OSError):fixture.broadcast(r)
            self.assertIsNone(r._first_prepare_carriage)
        r=fixture.runtime();r._tick_operation=object();r._broadcast_unit_done=True
        r._first_prepare_carriage=(0,'modeled-own');r.broadcast()
        self.assertEqual(r.enqueues,0);self.assertEqual(r._first_prepare_carriage,(0,'modeled-own'))
        r._broadcast_unit_done=False;fixture.broadcast(r)
        self.assertIsNone(r._first_prepare_carriage)
        self.assertIsNone(getattr(fixture.runtime(),'_first_prepare_carriage',None))


if __name__=='__main__':unittest.main()
