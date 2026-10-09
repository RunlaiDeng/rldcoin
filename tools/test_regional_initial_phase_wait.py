"""Exact scheduling models only; no Native, signing or custody authority."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bft_tick_fixture as baseline
import regional_contact_node as contact
import regional_bft_node as bft
import test_regional_context_phase_timer as timer


class InitialPhaseWaitTests(unittest.TestCase):
    def runtime(self):
        helper=timer.ContextPhaseTimerTests()
        runtime=helper.runtime();runtime.key='key-2'
        helper.observe(runtime,1.);baseline.clock.now=1.5
        return runtime

    def test_due_wait_reobserves_both_heads_before_request_without_renewing_interval(self):
        runtime=self.runtime();reads=[];waits=[];original=runtime.loop_observation
        def read():
            if reads:
                self.assertIsNone(runtime._composed_phase_observation)
                self.assertIsNone(runtime._sign_native_head)
            else:
                runtime._composed_phase_observation=('old-operation','old-head')
                runtime._sign_native_head='old-native-head'
            reads.append(True);return original()
        def wait(due):
            waits.append(due);self.assertEqual(runtime.entered_at,1.)
            baseline.clock.now=due+0.01;return True
        runtime.loop_observation=read;runtime.before_initial_proposal=wait
        runtime.tick()
        self.assertEqual(waits,[2.]);self.assertEqual(len(reads),2)
        self.assertEqual(runtime._phase_context_started[1],1.)
        self.assertEqual(runtime.requests,[dict(kind='Propose',round=0)])

    def test_changed_native_round_or_refused_fresh_head_cannot_first_sign_old_round(self):
        for mode in ('advanced-round','refused-head'):
            with self.subTest(mode=mode):
                runtime=self.runtime();original=runtime.loop_observation
                def wait(due):
                    baseline.clock.now=due+0.01
                    if mode=='advanced-round':runtime.native_state['round']=1
                    else:runtime.loop_observation=lambda:(_ for _ in ()).throw(ValueError('changed caller head'))
                    return True
                runtime.before_initial_proposal=wait
                if mode=='refused-head':
                    with self.assertRaisesRegex(ValueError,'changed caller head'):runtime.tick()
                else:runtime.tick()
                self.assertEqual(runtime.requests,[])
                self.assertIsNone(runtime._tick_operation)
                self.assertIsNone(runtime.head['pending'])

    def test_wait_decline_follower_legacy_and_current_proposal_keep_original_phase_priority(self):
        for mode in ('declined','follower','legacy','proposal'):
            with self.subTest(mode=mode):
                runtime=self.runtime();waits=[]
                runtime.before_initial_proposal=lambda due:waits.append(due) or False
                if mode=='follower':runtime.key='key-3'
                elif mode=='legacy':runtime.format=bft.FORMAT
                elif mode=='proposal':runtime.proposal(0)
                runtime.tick()
                self.assertEqual(waits,[2.] if mode=='declined' else [])
                self.assertEqual(runtime.requests,[dict(kind='Prepare',round=0)] if mode=='proposal' else [])

    def test_service_wait_is_bounded_uses_remaining_time_and_stops_before_release(self):
        service=contact.Service.__new__(contact.Service);service.tcp=SimpleNamespace(running=True)
        now=[5.];sleeps=[]
        def sleep(seconds):sleeps.append(seconds);now[0]+=seconds
        with patch.object(contact.time,'monotonic',side_effect=lambda:now[0]),patch.object(contact.time,'sleep',side_effect=sleep):
            self.assertFalse(service.wait_initial_proposal(6.1));self.assertEqual(sleeps,[])
            self.assertFalse(service.wait_initial_proposal(float('nan')))
            self.assertTrue(service.wait_initial_proposal(5.25))
            self.assertAlmostEqual(sum(sleeps),.25)
            self.assertTrue(all(0<s<=.1 for s in sleeps))
            service.tcp.running=False
            with self.assertRaises(contact.tcp.MeshRuntimeStopping):service.wait_initial_proposal(5.3)


if __name__=='__main__':unittest.main()
