"""Exact Runtime scheduling models; native responses intercepted, no authority."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_bft_node import Runtime
from bft_tick_fixture import Fixture, CONTEXT


class LoopObservationTests(unittest.TestCase):
    def runtime(self):
        r = Runtime.__new__(Runtime)
        r.head = dict(head='1'*64, pending=None, outbox=None)
        r.signing_binding = dict(currency='fixture', region='earth', key='fake-validator')
        r.signer = Path('/intentionally-absent-signer')
        r.state = dict(height=10, tip=CONTEXT['parent_block'])
        value = dict(format='RLD-BFT-LOOP-OBSERVATION-V1',
                     native=dict(context=copy.deepcopy(CONTEXT)),
                     signer=dict(binding=copy.deepcopy(r.signing_binding), head=r.head['head'], state=None),
                     signing_authority=False, independent_freshness_qualified=False)
        calls = []
        def call(*args):
            calls.append(args)
            return copy.deepcopy(value)
        r.native = SimpleNamespace(call=call)
        r.save = lambda state: setattr(r, 'state', state)
        return r, value, calls

    def test_exact_head_single_observation_each_call_and_no_mutable_cache(self):
        r, value, calls = self.runtime()
        context, status = r.loop_observation()
        status['head'] = 'changed'; context['parent_height'] = 99
        self.assertEqual(r.loop_observation()[0]['parent_height'],10)
        self.assertEqual(r.loop_observation()[1]['head'],r.head['head'])
        self.assertEqual(calls, [('bft-loop-status','--signer-dir',r.signer,
                                 '--expected-head',r.head['head'])]*3)

    def test_bad_head_or_binding_refuses_before_retained_height_changes(self):
        for field in ('head','binding'):
            r, value, _ = self.runtime()
            value['native']['context']['parent_height']=11
            value['signer'][field]='wrong'
            with self.assertRaises(ValueError):r.loop_observation()
            self.assertEqual(r.state['height'],10)

    def test_wrong_domain_or_authority_flag_refuses(self):
        for field, bad in [('format','other'),('signing_authority',True),
                           ('independent_freshness_qualified',True),('extra',0)]:
            r, value, _ = self.runtime(); value[field]=bad
            with self.assertRaises(ValueError):r.loop_observation()

    def test_native_refusal_has_no_cached_fallback(self):
        r, _, _ = self.runtime(); r.loop_observation()
        r.native.call=lambda *args: (_ for _ in ()).throw(ValueError('actual refused'))
        with self.assertRaisesRegex(ValueError,'actual refused'):r.loop_observation()

    def test_pending_or_outbox_prevents_native_read(self):
        for field in ('pending','outbox'):
            r, _, calls = self.runtime(); r.head[field]={'retained':True}
            with self.assertRaises(ValueError):r.loop_observation()
            self.assertEqual(calls,[])

    def test_native_rollback_or_conflicting_tip_refuses(self):
        for field, bad in [('parent_height',9),('parent_block','other')]:
            r, value, _ = self.runtime();value['native']['context'][field]=bad
            with self.assertRaisesRegex(ValueError,'rolled back'):r.loop_observation()
            self.assertEqual(r.state['height'],10)

    def test_ordinary_tick_uses_combined_observation_but_joint_keeps_old_path(self):
        for joint in (False,True):
            f=Fixture();f.key_file=None
            if not joint:f.joint=None
            def combined():
                f.counts['bft-loop-status']+=1
                return copy.deepcopy(CONTEXT),dict(state=copy.deepcopy(f.native_state),records=0)
            f.loop_observation=combined
            result=f.tick()
            self.assertEqual(f.counts['bft-loop-status'],0 if joint else 1)
            self.assertEqual(f.counts['bft-context'],1 if joint else 0)
            self.assertEqual(f.counts['bft-status'],1 if joint else 0)
            self.assertEqual(f.requests,[]);self.assertEqual(result['height'],10)

    def test_ordinary_combined_path_keeps_prepare_commit_before_future_round(self):
        f=Fixture();f.joint=None
        f.proposal(0);f.votes(0,'Prepare',3);f.proposal(4)
        def combined():
            f.counts['bft-loop-status']+=1
            return copy.deepcopy(CONTEXT),dict(state=copy.deepcopy(f.native_state),records=f.native_records)
        f.loop_observation=combined
        result=f.tick()
        self.assertEqual(f.counts['bft-loop-status'],1)
        self.assertEqual(f.counts['bft-context'],0)
        # Fresh post-Prepare and post-phase observations still occur.
        self.assertEqual(f.counts['bft-status'],2)
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Commit',round=0)])
        self.assertEqual(result['native_records'],2)

    def test_combined_observation_cannot_skip_actual_pre_sign_status(self):
        r, _, _ = self.runtime()
        r.key_file=Path('/intercepted-fake-key');events=[]
        r.signer_status=lambda: events.append('fresh-status') or (_ for _ in ()).throw(ValueError('changed head'))
        r._sign_stage=Runtime._sign_stage.__get__(r)
        r.loop_observation()
        with patch('regional_bft_node.private',return_value=r.key_file):
            with self.assertRaisesRegex(ValueError,'changed head'):r._sign({'Timeout':{}})
        self.assertEqual(events,['fresh-status']);self.assertIsNone(r.head['pending'])


if __name__=='__main__':unittest.main()
