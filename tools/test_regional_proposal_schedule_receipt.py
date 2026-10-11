"""Scheduling response binding models only; no native or signing authority."""
import copy
from types import SimpleNamespace
import unittest

from regional_bft_proposal_schedule import opportunity,FORMAT

class ProposalReceiptTests(unittest.TestCase):
    def test_context_heads_round_shape_and_authority_substitution_refuse(self):
        context=dict(currency='1'*64,region='2'*64)
        value=dict(format=FORMAT,context=context,round=0,key='key',caller_head='3'*64,
            archive_sha256='4'*64,authenticated_messages=0,current_proposals=False,
            future_proposals=False,proposed_round=0,leader='key',timeout=None,high=None,
            can_propose=True,ledger_changed=False,signing_authority=False,independent_freshness_qualified=False)
        runtime=SimpleNamespace(signer='fixture',root='fixture',key='key',format='fixture',
            head=dict(head='3'*64),_archive_head='4'*64,state=dict(messages={}),peers={'key':None})
        runtime.with_json=lambda *args:value
        self.assertEqual(opportunity(runtime,context,0),value)
        for field,changed in [('format','wrong'),('context',{}),('key','wrong'),('caller_head','0'*64),
            ('archive_sha256','0'*64),('round',True),('proposed_round',False),('proposed_round',32),
            ('authenticated_messages',True),('authenticated_messages',1),('leader','foreign'),
            ('current_proposals',1),('future_proposals',None),('can_propose',1),('timeout',[]),
            ('high','0'*64),('ledger_changed',True),('signing_authority',True),
            ('independent_freshness_qualified',True),('unknown',False)]:
            bad=copy.deepcopy(value);bad[field]=changed;runtime.with_json=lambda *args:bad
            with self.subTest(field=field),self.assertRaises(ValueError):opportunity(runtime,context,0)

if __name__=='__main__':unittest.main()
