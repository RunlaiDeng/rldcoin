"""Explicit startup pins: refusal before recovery; no adoption authority."""
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import regional_bft_node as bft
from regional_paged_fault_scope import inventory


class StartupPinConfigTests(unittest.TestCase):
    def test_invalid_head_and_nonbase_profiles_refuse_before_native_or_custody(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();path=root/'config.json'
            config=dict(format=bft.FORMAT,state=str(root/'state'),signer_dir=str(root/'signer'),
                head_file=str(root/'caller/head.json'),key_file=str(root/'absent/key.json'),
                key='1'*64,miner='2'*64,validators=[],block_interval=1,round_timeout=60,stop_height=24)
            native=SimpleNamespace(currency='3'*64,ledger=root/'native')
            for head in (None,'0'*64,'1'*63,True):
                mesh.atomic(path,dict(config,startup_native_history_head=head))
                with self.subTest(head=head),self.assertRaises(ValueError):bft.Runtime(native,{},path)
                self.assertEqual(set(root.iterdir()),{path})
            for profile in (bft.JOINT_FORMAT,bft.ROLE_FORMAT):
                mesh.atomic(path,dict(config,format=profile,startup_native_history_head='4'*64))
                with self.subTest(profile=profile),self.assertRaises(ValueError):bft.Runtime(native,{},path)
                self.assertEqual(set(root.iterdir()),{path})


class NativeStartupPinTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('RLD_STARTUP_PIN_FIXTURE') and os.environ.get('RLD_CONTACT_BINARY'),
                         'requires explicitly fresh retained fixture and bound Native binary')
    def test_actual_complete_plan_precedes_recovery_and_wrong_head_refuses_unchanged(self):
        from regional_bft_network_campaign import Campaign
        from regional_contact_node import Native
        from regional_contact_campaign import public
        root=Path(os.environ['RLD_STARTUP_PIN_FIXTURE']).resolve()
        self.assertFalse(root.exists());root.mkdir(mode=0o700)
        binary=Path(os.environ['RLD_CONTACT_BINARY']).resolve()
        campaign=Campaign(binary,root/'fixture');runtime=None;commands=[]
        class Recorded(Native):
            def call(self,*args,**kw):
                commands.append(args[0]);return super().call(*args,**kw)
        try:
            for _ in range(2):campaign.checkpoint('earth',online=(0,1,2,3))
            original=campaign.root/'bft-config-1.json';config=mesh.load(original,65536)
            caller=Path(config['head_file']);value=mesh.load(caller,8192)
            mesh.atomic(caller,dict(value,head=campaign.heads['earth',1]))
            absent=campaign.root/'absent';absent.mkdir(mode=0o700)
            config=dict(config,key_file=str(absent/'missing.json'))
            mesh.atomic(original,config);original_bytes=original.read_bytes()
            native=Recorded(binary,campaign.node('earth',1),public(1),campaign.currency)
            transport=mesh.load(campaign.root/'mesh-config-1.json',65536)
            runtime=bft.Runtime(native,transport,original)
            self.assertGreater(len(runtime.state['messages']),4)
            payloads={i:runtime.state['messages'].payload(i) for i in runtime.state['messages']}
            runtime.close();runtime=None
            pin=native.call('history-head')['history_head']
            pinned=campaign.root/'pinned-config.json';mesh.atomic(pinned,dict(config,startup_native_history_head=pin))
            before={str(p):inventory(p) for p in (native.ledger,Path(config['signer_dir']),caller.parent,Path(config['state']))}
            commands.clear()
            with patch.object(bft,'check_cold_retained',side_effect=AssertionError('no fallback after explicit pin')):
                runtime=bft.Runtime(native,transport,pinned)
            self.assertTrue(runtime._retained_native_authenticated)
            self.assertEqual({i:runtime.state['messages'].payload(i) for i in runtime.state['messages']},payloads)
            self.assertEqual(commands.count('bft-network-check-plan'),1)
            self.assertNotIn('history-head',commands);self.assertNotIn('bft-network-check-batch',commands)
            self.assertFalse(any(c in ('bft-sign','bft-submit','bft-recover') for c in commands))
            plan_index=commands.index('bft-network-check-plan')
            self.assertTrue(all(commands.index(c)>plan_index for c in ('bft-status','bft-retained-messages','proof')))
            runtime.close();runtime=None
            self.assertEqual({str(p):inventory(p) for p in map(Path,before)},before)
            self.assertEqual(original.read_bytes(),original_bytes)
            wrong=campaign.root/'wrong-pin-config.json'
            mesh.atomic(wrong,dict(config,startup_native_history_head='f'*64 if pin!='f'*64 else 'e'*64))
            commands.clear()
            with self.assertRaises(ValueError),patch.object(bft,'check_cold_retained',side_effect=AssertionError('no fallback')):
                bft.Runtime(native,transport,wrong)
            self.assertEqual(commands,['bft-context','bft-network-check-plan'])
            self.assertEqual({str(p):inventory(p) for p in map(Path,before)},before)
            self.assertEqual(original.read_bytes(),original_bytes)
            self.assertFalse(Path(config['key_file']).exists())
        finally:
            if runtime is not None:runtime.close()
            campaign.cleanup()


if __name__=='__main__':unittest.main()
