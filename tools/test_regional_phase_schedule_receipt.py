"""Phase bridge response refusal models; no Native or signing authority."""
import copy,hashlib
from types import SimpleNamespace
import unittest
import interstellar_transfer as wire
from regional_bft_phase_schedule import action,FORMAT

class PhaseReceiptTests(unittest.TestCase):
    def test_request_order_heads_modes_types_and_authority_substitution_refuse(self):
        context=dict(currency='1'*64,region='2'*64)
        runtime=SimpleNamespace(signer='fixture',root='fixture',key='key',format='fixture',
            head=dict(head='3'*64,pending=None,outbox=None),_archive_head='4'*64,state=dict(messages={}))
        request=dict(context=context,order=[])
        value=dict(format=FORMAT,context=context,round=0,key='key',caller_head='3'*64,
            archive_sha256='4'*64,mode='start',authenticated_messages=0,
            request_sha256=hashlib.sha256(wire.canonical(request)).hexdigest(),action='Idle',
            ledger_changed=False,signing_authority=False,independent_freshness_qualified=False)
        runtime.with_json=lambda *args:value;self.assertEqual(action(runtime,context,0,'start'),'Idle')
        for field,changed in [('format','wrong'),('context',{}),('round',True),('mode','commit'),
            ('key','wrong'),('caller_head','0'*64),('archive_sha256','0'*64),('request_sha256','0'*64),
            ('authenticated_messages',True),('authenticated_messages',1),('action','Timeout'),
            ('action',{'Prepare':{}}),('action',{'Finalize':{'snapshot':True}}),
            ('ledger_changed',True),('signing_authority',True),('independent_freshness_qualified',True),('unknown',True)]:
            bad=copy.deepcopy(value);bad[field]=changed;runtime.with_json=lambda *args:bad
            with self.subTest(field=field),self.assertRaises(ValueError):action(runtime,context,0,'start')

if __name__=='__main__':unittest.main()
