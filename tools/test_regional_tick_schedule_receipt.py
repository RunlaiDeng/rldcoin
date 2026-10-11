"""Binding refusal models, not Native custody or consensus qualification."""
import copy
import hashlib
from types import SimpleNamespace
import unittest
import interstellar_transfer as wire
from regional_bft_tick_schedule import FORMAT,plan,request

class TickReceiptTests(unittest.TestCase):
    def test_clock_action_head_request_and_authority_substitution_refuse(self):
        context=dict(currency='1'*64,region='2'*64)
        runtime=SimpleNamespace(signer='fixture',root='fixture',key='key',format='fixture',
            head=dict(head='3'*64,pending=None,outbox=None),_archive_head='4'*64,state=dict(messages={}),
            entered_at=2.,block_interval=1.,round_timeout=20.)
        value=dict(format=FORMAT,context=context,round=0,key='key',caller_head='3'*64,
            archive_sha256='4'*64,authenticated_messages=0,monotonic_now=2.5,
            request_sha256=hashlib.sha256(wire.canonical(request(runtime,context,'begin',False,None))).hexdigest(),
            action={'Phase':'Idle'},ledger_changed=False,signing_authority=False,independent_freshness_qualified=False)
        runtime.with_json=lambda *args:value;self.assertEqual(plan(runtime,context,0,'begin'),{'Phase':'Idle'})
        changes=[('format','wrong'),('context',{}),('round',True),('key','wrong'),('caller_head','0'*64),
            ('archive_sha256','0'*64),('request_sha256','0'*64),('authenticated_messages',True),
            ('monotonic_now',True),('monotonic_now',float('nan')),('monotonic_now',1.),
            ('action','Idle'),('action',{'WaitInitial':{'deadline':4.}}),('action',{'Propose':{'round':True,'timeout':None,'high':None}}),
            ('action',{'Timeout':{'context':context,'round':True}}),('action',{'Phase':{'Prepare':{}}}),
            ('ledger_changed',True),('signing_authority',True),('independent_freshness_qualified',True),('unknown',True)]
        for field,changed in changes:
            bad=copy.deepcopy(value);bad[field]=changed;runtime.with_json=lambda *args:bad
            with self.subTest(field=field),self.assertRaises(ValueError):plan(runtime,context,0,'begin')

if __name__=='__main__':unittest.main()
