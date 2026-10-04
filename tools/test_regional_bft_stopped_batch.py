"""Mechanical stopped inspection boundaries; actual Native checks are separate."""
from pathlib import Path
import tempfile
import unittest

import interstellar_mesh as mesh
from regional_bft_retention import Messages, pack_state
from verify_regional_bft_stopped_batch import verify_stopped_state
from test_regional_bft_cold_batch import FakeNative


class StoppedBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.directory=self.root/'retained';self.directory.mkdir(mode=0o700)
        self.native=FakeNative();self.config=dict(state=str(self.directory),format='RLD-REGIONAL-BFT-NODE-V1',key='3'*64)
        self.current=dict(region='2'*64,height=10,tip='4'*64)
        messages=Messages()
        for n in range(10):
            envelope=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency='1'*64,region='2'*64,body={'test':n},evidence={'snapshots':[]})
            messages=messages.append(mesh.digest(envelope['body']),envelope,None,False)
        self.state=dict(format=self.config['format'],binding=dict(currency='1'*64,region='2'*64,key='3'*64),messages=messages,height=10,tip='4'*64,snapshot_cache=[],cursor=0)
        self.write()
    def write(self):mesh.atomic(self.directory/'state.json',pack_state(self.state))
    def test_all_complete_messages_batched_with_private_source_unchanged(self):
        p=self.directory/'state.json';before=(p.read_bytes(),p.stat().st_mode)
        result=verify_stopped_state(self.native,self.config,self.current,self.root)
        self.assertEqual(result['messages_authenticated'],10);self.assertTrue(result['full_native_authentication'])
        self.assertEqual(len(self.native.requests),3)
        self.assertEqual((p.read_bytes(),p.stat().st_mode),before)
        self.assertEqual(list(self.directory.iterdir()),[p])
    def test_wrong_binding_or_ahead_state_refuses_before_native(self):
        for field,value in [('height',11),('tip','5'*64),('binding',dict(currency='f'*64,region='2'*64,key='3'*64))]:
            old=self.state[field];self.state[field]=value;self.write()
            with self.assertRaises(ValueError):verify_stopped_state(self.native,self.config,self.current,self.root)
            self.state[field]=old
        self.assertEqual(self.native.requests,[])
    def test_native_later_refusal_is_not_partial_success(self):
        def fail(response):
            if len(self.native.requests)==2:raise ValueError('later complete envelope rejected')
            return response
        self.native.change=fail
        with self.assertRaisesRegex(ValueError,'later complete envelope'):verify_stopped_state(self.native,self.config,self.current,self.root)
        self.assertEqual(len(self.native.requests),2)
    def test_batch_response_cannot_grant_signing_authority(self):
        self.native.change=lambda response:{**response,'signing_authority':True}
        with self.assertRaises(ValueError):verify_stopped_state(self.native,self.config,self.current,self.root)
    def test_source_symlink_refuses_before_native(self):
        p=self.directory/'state.json';saved=p.with_name('saved.json');p.rename(saved);p.symlink_to(saved)
        with self.assertRaises(ValueError):verify_stopped_state(self.native,self.config,self.current,self.root)
        self.assertEqual(self.native.requests,[])


if __name__=='__main__':unittest.main()
