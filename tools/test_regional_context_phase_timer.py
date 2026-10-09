"""Exact Runtime scheduling models; no Native/signature/custody authority."""
import copy
import unittest
from unittest.mock import patch

import bft_tick_fixture as baseline
import regional_bft_node as bft
from test_regional_bft_certified_leader import Fixture


class ContextPhaseTimerTests(unittest.TestCase):
    def runtime(self, round_number=0):
        runtime=Fixture(round_number=round_number)
        runtime.format=bft.ORIGIN_RUNTIME_FORMAT
        runtime.joint=None
        runtime.state['tip']=baseline.CONTEXT['parent_block']
        runtime.head['outbox']=None
        runtime.save=lambda state:setattr(runtime,'state',state)
        runtime.loop_observation=lambda:(copy.deepcopy(baseline.CONTEXT),
            dict(state=copy.deepcopy(runtime.native_state),records=runtime.native_records))
        runtime.slot=None
        return runtime

    def observe(self, runtime, at, context=None):
        with patch.object(bft.time,'monotonic',return_value=at):
            return bft.Runtime._observe_context(runtime,copy.deepcopy(context or baseline.CONTEXT))

    def test_first_native_parent_observation_survives_later_tick_and_duplicate_evidence(self):
        runtime=self.runtime()
        runtime.key='key-2'  # parent height ten selects this initial leader.
        self.observe(runtime,1.)
        self.observe(runtime,2.25)
        baseline.clock.now=2.5
        runtime.tick()
        self.assertEqual(runtime.requests,[dict(kind='Propose',round=0)])
        self.assertEqual(runtime._phase_context_started[1],1.)

    def test_follower_timeout_is_not_renewed_by_repeated_native_context(self):
        runtime=self.runtime();runtime.key='key-3';runtime.round_timeout=2
        self.observe(runtime,1.)
        self.observe(runtime,3.1)
        baseline.clock.now=3.1
        runtime.tick()
        self.assertEqual(runtime.requests,[dict(kind='Timeout',round=0)])
        self.assertEqual(runtime.native_state['round'],1)

    def test_later_native_round_and_legacy_profile_keep_original_entry_time(self):
        for mode in ('later-round','legacy'):
            with self.subTest(mode=mode):
                runtime=self.runtime(1 if mode=='later-round' else 0)
                runtime.key='key-3';runtime.key_file=None
                self.observe(runtime,1.)
                if mode=='legacy':runtime.format=bft.FORMAT
                baseline.clock.now=4.
                runtime.tick()
                self.assertEqual(runtime.entered_at,4.)
                self.assertEqual(runtime.requests,[])

    def test_native_rollback_and_failed_persistence_cannot_publish_a_timestamp(self):
        for mode in ('rollback','conflicting-tip','persistence'):
            with self.subTest(mode=mode):
                runtime=self.runtime();self.observe(runtime,1.)
                previous=runtime._phase_context_started
                changed=copy.deepcopy(baseline.CONTEXT)
                if mode=='rollback':changed['parent_height']-=1
                elif mode=='conflicting-tip':changed['parent_block']='wrong-tip'
                else:
                    changed['parent_height']+=1;changed['parent_block']='next-tip'
                    runtime.save=lambda state:(_ for _ in ()).throw(OSError('durable write failed'))
                with self.assertRaises((ValueError,OSError)):self.observe(runtime,5.,changed)
                self.assertEqual(runtime._phase_context_started,previous)


if __name__=='__main__':unittest.main()
