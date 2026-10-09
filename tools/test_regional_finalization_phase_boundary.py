"""Actual boundary orchestration with refusal models, never Native authority."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from regional_bft_node import Runtime, FORMAT, ORIGIN_RUNTIME_FORMAT
from regional_contact_node import Service
import regional_contact_node as contact


class BoundaryRuntime(Runtime):
    def __init__(self):
        self.events=[];self.format=ORIGIN_RUNTIME_FORMAT;self.joint=None
        self.failed=False;self.key='d';self.peers=dict.fromkeys('abcd')
        self.key_file=Path(__file__);self.stop_height=6
        self.head=dict(head='original-caller',pending=None,outbox=None)
        self.state=dict(height=2);self.fresh=dict(parent_height=3)
        self._tick_operation=object();self._composed_phase_observation='old'
        self._sign_native_head='old';self._finalization_phase_used=False
        self.after_local_finalization=lambda:self.events.append('service-ready') or True
        self.refuse=None

    def with_json(self,action,value):
        self.events.append(action)
        if self.refuse==action:raise ValueError(action)
        self.state['height']=3

    def retain_local_body(self,body):
        self.events.append('retain-durable')
        if self.refuse=='retain':raise ValueError('retain')

    def observe(self):
        self.events.append('observe-native')
        if self.refuse=='observe':raise ValueError('observe')
        return self.fresh

    def _tick(self):
        self.events.append('fresh-native-tick')
        assert self._composed_phase_observation is None
        assert self._sign_native_head is None
        if self.refuse=='fresh-head':raise ValueError('fresh-head')
        return 'fresh-native-result'

    def broadcast(self):self.events.append('broadcast')
    def report(self,*args,**kwargs):self.events.append('report');return 'old-result'


class FinalizationPhaseBoundaryTests(unittest.TestCase):
    def finish(self,runtime):
        return runtime._finish_local_finalization({},dict(parent_height=2),0,{})

    def test_native_install_retention_observation_precede_one_fresh_successor_tick(self):
        runtime=BoundaryRuntime();old=runtime._tick_operation
        self.assertEqual(self.finish(runtime),'fresh-native-result')
        self.assertEqual(runtime.events,['finalize','retain-durable','observe-native',
                                        'service-ready','fresh-native-tick'])
        self.assertIsNot(runtime._tick_operation,old)
        runtime.events=[]
        self.assertEqual(self.finish(runtime),'old-result')
        self.assertEqual(runtime.events,['finalize','retain-durable','observe-native','broadcast','report'])

    def test_every_durability_and_fresh_head_refusal_prevents_successor_release(self):
        for refusal in ('finalize','retain','observe','fresh-head'):
            with self.subTest(refusal=refusal):
                runtime=BoundaryRuntime();runtime.refuse=refusal
                with self.assertRaisesRegex(ValueError,refusal):self.finish(runtime)
                self.assertNotIn('broadcast',runtime.events)
                if refusal!='fresh-head':self.assertNotIn('fresh-native-tick',runtime.events)
                self.assertEqual(runtime.head,dict(head='original-caller',pending=None,outbox=None))

    def test_duplicate_parent_follower_stopped_keyless_legacy_or_pending_keeps_original_exit(self):
        for mode in ('duplicate','follower','stop-height','keyless','legacy','pending','outbox','no-service','declined'):
            with self.subTest(mode=mode):
                runtime=BoundaryRuntime()
                if mode=='duplicate':runtime.fresh=dict(parent_height=2)
                elif mode=='follower':runtime.key='a'
                elif mode=='stop-height':runtime.stop_height=3
                elif mode=='keyless':runtime.key_file=None
                elif mode=='legacy':runtime.format=FORMAT
                elif mode=='pending':runtime.head['pending']={'retained':'request'}
                elif mode=='outbox':runtime.head['outbox']={'retained':'response'}
                elif mode=='no-service':runtime.after_local_finalization=None
                elif mode=='declined':runtime.after_local_finalization=lambda:False
                self.assertEqual(self.finish(runtime),'old-result')
                self.assertNotIn('fresh-native-tick',runtime.events)
                self.assertEqual(runtime.events[-2:],['broadcast','report'])

    def test_service_stop_after_durable_finalization_never_starts_successor(self):
        service=Service.__new__(Service);service.tcp=SimpleNamespace(running=False)
        runtime=BoundaryRuntime();runtime.after_local_finalization=service.continue_after_finalization
        with self.assertRaises(contact.tcp.MeshRuntimeStopping):self.finish(runtime)
        self.assertEqual(runtime.events,['finalize','retain-durable','observe-native'])
        self.assertEqual(runtime.head['head'],'original-caller')


if __name__=='__main__':unittest.main()
