"""Native-checked metadata selection only; models grant no ledger authority."""
import copy
import itertools
from types import SimpleNamespace
import unittest
from regional_bft_node import carriage_batch

CONTEXT=dict(currency='fixture',region='ground',epoch='era',previous='checkpoint',
             parent_height=0,parent_block='genesis',parent_state='empty')

class ProposalCarriageTests(unittest.TestCase):
    def fixture(self,chain=False):
        statement={k:CONTEXT[k] for k in ('currency','region','epoch','previous')}
        statement['height']=1
        proposal={'Signed':{'Proposal':dict(round=0,snapshot={'statement':statement},leader={'key':'own'})}}
        def vote(phase):return {'Signed':{'Vote':dict(context=copy.deepcopy(CONTEXT),round=0,
            value='native-modeled-value',phase=phase,approval={'key':'own'})}}
        rows=[('p',proposal,'native-modeled-value',True),('v',vote('Prepare'),'native-modeled-value',True)]
        order=['v','p']
        if chain:rows.append(('c',vote('Commit'),'native-modeled-value',True));order=['c','v','p']
        messages=SimpleNamespace(bodies=lambda:iter(rows))
        pending=[(ident,ident,peer) for ident in order for peer in 'abc']
        return messages,pending,rows
    def choose(self,messages,pending,height=0,cursor=0,context=CONTEXT):
        return carriage_batch(messages,pending,height,cursor,prepare_first=True,proposal_context=context)
    def test_three_own_prepares_cannot_displace_two_waiting_proposal_copies(self):
        m,p,_=self.fixture();selected=self.choose(m,p)
        self.assertEqual(len(selected),4);self.assertEqual(len(set(selected)),4)
        self.assertEqual({peer for _,ident,peer in selected if ident=='p'},set('abc'))
        self.assertEqual(sum(ident=='v' for _,ident,_ in selected),1)
    def test_own_commit_prepare_proposal_frontier_never_consumes_fifth_slot(self):
        m,p,_=self.fixture(chain=True)
        for cursor in (0,4,8,12):
            selected=self.choose(m,p,cursor=cursor)
            self.assertEqual(len(selected),4);self.assertEqual(len(set(selected)),4)
            for _,ident,peer in selected:
                if ident in ('v','c'):self.assertIn(('p','p',peer),selected)
                if ident=='c':self.assertIn(('v','v',peer),selected)
    def test_history_slots_and_default_selection_are_unchanged(self):
        m,p,rows=self.fixture();rows.append(('h',{'Finalized':{'statement':{'height':9}}},'history',True))
        p.extend([('h','h',peer) for peer in 'abc'])
        original=carriage_batch(m,p,0,0,prepare_first=True);selected=self.choose(m,p)
        self.assertEqual([pair for pair in selected if pair[1]=='h'],[pair for pair in original if pair[1]=='h'])
        self.assertEqual(carriage_batch(m,p,0,0),original)
    def test_complete_native_context_value_round_and_signer_must_match(self):
        for change in ('context','value','round','signer','proposal-value','proposal-parent'):
            m,p,rows=self.fixture();vote=rows[1][1]['Signed']['Vote'];proposal=rows[0][1]['Signed']['Proposal']
            if change=='context':vote['context']['parent_block']='different'
            elif change=='value':vote['value']='different'
            elif change=='round':vote['round']=1
            elif change=='signer':vote['approval']['key']='another'
            elif change=='proposal-value':rows[0]=(*rows[0][:2],'different',rows[0][3])
            else:proposal['snapshot']['statement']['previous']='different'
            self.assertEqual(self.choose(m,p),carriage_batch(m,p,0,0,prepare_first=True),change)
    def test_already_queued_or_other_peer_proposals_do_not_suppress_votes(self):
        m,p,_=self.fixture()
        for pending in ([x for x in p if x[1]!='p'],[x for x in p if x[1]!='p' or x[2]=='a']):
            selected=self.choose(m,pending)
            self.assertEqual(selected,carriage_batch(m,pending,0,0,prepare_first=True))
    def test_all_two_peer_dependency_orders_preserve_unique_closed_frontier(self):
        m,p,rows=self.fixture(chain=True);p=[pair for pair in p if pair[2]!='c']
        before=copy.deepcopy(rows)
        for order in itertools.permutations(p):
            for cursor in (0,4,8):
                selected=self.choose(m,list(order),cursor=cursor)
                self.assertEqual(len(selected),4);self.assertEqual(len(set(selected)),4)
                for _,ident,peer in selected:
                    if ident in ('v','c'):self.assertIn(('p','p',peer),selected)
                    if ident=='c':self.assertIn(('v','v',peer),selected)
        self.assertEqual(rows,before)
    def test_absent_incomplete_or_wrong_height_context_uses_original_selection(self):
        m,p,_=self.fixture()
        for context in (None,{},dict(CONTEXT,parent_height=1)):
            self.assertEqual(self.choose(m,p,context=context),carriage_batch(m,p,0,0,prepare_first=True))
        self.assertEqual(carriage_batch(m,p,0,0,proposal_context=CONTEXT),carriage_batch(m,p,0,0))

if __name__=='__main__':unittest.main()
