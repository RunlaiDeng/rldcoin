"""Actual local outbox orchestration only; fake results grant no Native rights."""
import copy
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_transfer as wire
import regional_bft_node as bft


class LocalEnvelopeTests(unittest.TestCase):
    def runtime(self):
        runtime=bft.Runtime.__new__(bft.Runtime)
        runtime.format=bft.FORMAT;runtime.joint=None;runtime.region='2'*64
        runtime.head={'head':'3'*64,'pending':None,'outbox':{'Vote':{'synthetic':'no-signature'}}}
        runtime.native=SimpleNamespace(currency='1'*64)
        self.actions=[];self.retained=[]
        def call(action,*args):
            self.actions.append(action);self.assertEqual(action,'proof')
            return {'snapshots':[]}
        runtime.native.call=call
        def with_json(action,value,*args):
            self.actions.append(action)
            if action=='bft-network-local-envelope':
                return self.response(runtime,value)
            if action=='bft-network-pack':return value
            if action=='bft-network-check':return {'evidence':{'snapshots':[]},'value':None}
            self.fail('unexpected Native action '+action)
        runtime.with_json=with_json
        runtime._retain_checked=lambda envelope,checked,sync,local:self.retained.append((envelope,checked,sync,local))
        runtime.save_head=lambda head:setattr(runtime,'head',head)
        return runtime

    def response(self,runtime,body):
        return {'format':'RLD-BFT-LOCAL-ENVELOPE-V1','currency':runtime.native.currency,
                'region':runtime.region,'request_sha256':hashlib.sha256(wire.canonical(body)).hexdigest(),
                'envelope':{'format':bft.NETWORK,'currency':runtime.native.currency,'region':runtime.region,
                            'evidence':{'snapshots':[]},'body':copy.deepcopy(body)},
                'checked':{'message_id':'4'*64,'value':None,'evidence':{'snapshots':[]},'epochs':[]},
                'verified':True,'ledger_changed':False,'signing_authority':False}

    def test_original_signed_outbox_uses_one_fully_checking_native_read(self):
        runtime=self.runtime();original=copy.deepcopy(runtime.head['outbox']);runtime.flush_outbox()
        self.assertEqual(self.actions,['bft-network-local-envelope'])
        self.assertEqual(self.retained[0][0]['body'],{'Signed':original})
        self.assertEqual(self.retained[0][2:],(False,True))
        self.assertIsNone(runtime.head['outbox'])

    def test_native_or_retention_failure_keeps_exact_original_outbox(self):
        for fail in ('native','retain','save'):
            with self.subTest(fail=fail):
                runtime=self.runtime();before=copy.deepcopy(runtime.head)
                if fail=='native':runtime.with_json=lambda *args:(_ for _ in ()).throw(ValueError('Native refused full proof'))
                if fail=='retain':runtime._retain_checked=lambda *args,**kwargs:(_ for _ in ()).throw(OSError('durable retention failed'))
                if fail=='save':runtime.save_head=lambda head:(_ for _ in ()).throw(OSError('head publication failed'))
                with self.assertRaises((ValueError,OSError)):runtime.flush_outbox()
                self.assertEqual(runtime.head,before)

    def test_response_binding_and_mutated_complete_body_never_clear_outbox(self):
        for change in ('format','currency','region','request_sha256','verified','ledger_changed','signing_authority','body','checked','count'):
            with self.subTest(change=change):
                runtime=self.runtime();before=copy.deepcopy(runtime.head)
                def call(action,body):
                    value=self.response(runtime,body)
                    if change in ('format','currency','region','request_sha256'):value[change]='wrong'
                    elif change=='verified':value[change]=False
                    elif change in ('ledger_changed','signing_authority'):value[change]=True
                    elif change=='body':value['envelope']['body']={'Signed':{'Vote':{'changed':True}}}
                    elif change=='checked':value['checked']['message_id']='bad'
                    else:value['checked']['evidence']['snapshots']=[{}]*65
                    return value
                runtime.with_json=call
                with self.assertRaises(ValueError):runtime.flush_outbox()
                self.assertEqual(runtime.head,before);self.assertEqual(self.retained,[])

    def test_joint_or_other_profile_uses_original_independent_path(self):
        runtime=self.runtime();runtime.format='explicit-other-profile';runtime.flush_outbox()
        self.assertEqual(self.actions,['proof','bft-network-pack','bft-network-check'])
        self.assertIsNone(runtime.head['outbox'])

    def test_read_only_payload_and_expanded_response_limits_preserve_outbox(self):
        import regional_bft_local_envelope as local
        for bound in ('body','response'):
            runtime=self.runtime();before=copy.deepcopy(runtime.head)
            with patch.object(wire,'MAX_PAYLOAD',1) if bound=='body' else patch.object(local,'MAX_BYTES',1):
                with self.assertRaises(ValueError):runtime.flush_outbox()
            self.assertEqual(runtime.head,before);self.assertEqual(self.retained,[])


if __name__=='__main__':unittest.main()
