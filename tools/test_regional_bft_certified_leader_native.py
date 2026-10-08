"""Real Native two-handoff future-TC signing; fixture/controller setup, no full-cycle claim."""
import copy
import time
from pathlib import Path
import unittest
from unittest.mock import patch
import test_regional_bft_second_role_receive as second_role

class CertifiedNativeLeaderTests(unittest.TestCase):
    setUp=second_role.SecondRoleReceiveTests.setUp
    tearDown=second_role.SecondRoleReceiveTests.tearDown
    open=second_role.SecondRoleReceiveTests.open
    close=second_role.SecondRoleReceiveTests.close
    slot=second_role.SecondRoleReceiveTests.slot
    activation=second_role.SecondRoleReceiveTests.activation
    checkpoint_current=second_role.SecondRoleReceiveTests.checkpoint_current
    second_activation=second_role.SecondRoleReceiveTests.second_activation
    caller_inventory=second_role.SecondRoleReceiveTests.caller_inventory

    def future_certificate(self):
        self.second_activation()
        reference=self.runtimes[2].native.call('bft-context');context=reference['context'];keys=reference['keys']
        voters={r.key:r for r in self.runtimes.values() if r.key is not None}
        local=voters[keys[(context['parent_height']+2)%4]]
        self.assertNotEqual(local.key,keys[context['parent_height']%4])
        self.assertEqual(local.signer_status()['records'],0)
        for key in keys:
            if key==local.key:continue
            source=voters[key]
            for number in (0,1):source.sign({'Timeout':dict(context=context,round=number)})
            message=source.native.call('bft-retained-messages','--signer-dir',source.signer)[-1]
            local.retain(source.envelope({'Signed':message}),sync=False)
        return local,self.caller_inventory(),local.native.call('status')

    def test_real_two_handoff_future_leader_first_proposes_from_exact_three_timeout_votes(self):
        local,heads,ledger=self.future_certificate()
        status=local.tick()
        self.assertEqual(status['round'],0)
        self.assertEqual(local.signer_status()['records'],0)
        # The first ordinary tick starts the unchanged local block interval.
        time.sleep(local.block_interval+0.05)
        status=local.tick()
        self.assertEqual(status['round'],2)
        signer=local.signer_status()
        self.assertEqual(signer['records'],1)
        self.assertEqual(signer['state']['round'],2)
        self.assertTrue(signer['state']['proposed'])
        self.assertEqual(local.head['head'],signer['head'])
        self.assertIsNone(local.head['pending']);self.assertIsNone(local.head['outbox'])
        retained=local.native.call('bft-retained-messages','--signer-dir',local.signer)
        proposal=retained[-1]['Proposal']
        self.assertEqual(proposal['round'],2)
        self.assertEqual(proposal['timeout']['round'],1)
        self.assertEqual(len({v['approval']['key'] for v in proposal['timeout']['votes']}),3)
        self.assertEqual(local.native.call('status'),ledger)
        after=self.caller_inventory()
        self.assertEqual({p:v for p,v in heads.items() if p!=str(local.head_path)},
                         {p:v for p,v in after.items() if p!=str(local.head_path)})
        local.tick();self.assertEqual(local.signer_status()['records'],2)
        local.tick();self.assertEqual(local.signer_status()['records'],2)
        messages=local.native.call('bft-retained-messages','--signer-dir',local.signer)
        self.assertEqual(sum('Proposal' in message for message in messages),1)

    def test_real_native_refuses_altered_future_timeout_before_any_local_signature_or_head_change(self):
        local,heads,ledger=self.future_certificate()
        state_bytes=local.state_path.read_bytes()
        native=local.with_json
        def corrupt(action,value,*args):
            if action=='bft-timeout-certificate':
                value=copy.deepcopy(value);signature=value[0]['approval']['signature']
                value[0]['approval']['signature']=('0' if signature[0]!='0' else '1')+signature[1:]
            return native(action,value,*args)
        with patch.object(local,'with_json',side_effect=corrupt):
            with self.assertRaises(ValueError):local.tick()
        self.assertEqual(local.signer_status()['records'],0)
        self.assertEqual(self.caller_inventory(),heads)
        self.assertEqual(local.state_path.read_bytes(),state_bytes)
        self.assertEqual(local.native.call('status'),ledger)
        self.assertIsNone(local.head['pending']);self.assertIsNone(local.head['outbox'])
