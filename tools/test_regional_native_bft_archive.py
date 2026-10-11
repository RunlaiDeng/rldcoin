"""Actual no-value native companion archive boundaries and independent Python codec.

A structural archive receipt never qualifies its unauthenticated codec bodies.
"""
import copy
import hashlib
from pathlib import Path
import os
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import Runtime
from regional_bft_retention import Messages, pack_state
from regional_bft_native_archive import arguments
from test_regional_bft_retention import NativeRetentionTests


class NativeArchiveTests(unittest.TestCase):
    setUp = NativeRetentionTests.setUp
    tearDown = NativeRetentionTests.tearDown
    open = NativeRetentionTests.open
    request = NativeRetentionTests.request

    def test_native_disk_bytes_match_python_reference_and_refuse_stale_or_forged_envelope(self):
        runtime=self.open();runtime.sign(self.request(0))
        packed=pack_state(runtime.state);raw=wire.canonical(packed)
        reference=self.c.root/'independent-python-archive.json';mesh.atomic(reference,packed)
        self.assertEqual(runtime.state_path.read_bytes(),reference.read_bytes())
        before=(runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records'])
        args=arguments(runtime)
        with self.assertRaises(ValueError):runtime.with_json('bft-runtime-archive-store',packed,*args,'--expected-state-sha256','0'*64)
        changed=copy.deepcopy(packed)
        old=next(iter(changed['runtime']['messages'].values()));new=copy.deepcopy(old)
        message=new['body']['Signed']['Timeout'];message['round']=1;message['approval']['signature']='00'*64
        ident=mesh.digest(new['body'])
        envelope=dict(new['header'],body=new['body'],evidence={'snapshots':[]})
        new['size_bytes']=len(wire.canonical(envelope));new['sha256']=hashlib.sha256(wire.canonical(envelope)).hexdigest()
        changed['runtime']['messages'][ident]=new
        with self.assertRaises(ValueError):runtime.with_json('bft-runtime-archive-store',changed,*args,'--expected-state-sha256',runtime._archive_head)
        self.assertEqual((runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records']),before)
        damaged=copy.deepcopy(packed);damaged['snapshots'][hashlib.sha256(b'{}').hexdigest()]={}
        with self.assertRaises(ValueError):runtime.with_json('bft-runtime-archive-store',damaged,*args,'--expected-state-sha256',runtime._archive_head)
        self.assertEqual(runtime.state_path.read_bytes(),before[0])

    def test_actual_native_write_refusal_preserves_archive_and_signer(self):
        runtime=self.open();runtime.sign(self.request(0));before=runtime.state_path.read_bytes()
        head=runtime.head_path.read_bytes();records=runtime.signer_status()['records']
        packed=pack_state(dict(runtime.state,cursor=runtime.state['cursor']+1))
        proposal=self.c.root/'outside-runtime-native-proposal.json';mesh.atomic(proposal,packed)
        runtime.root.chmod(0o500)
        try:
            with self.assertRaises(ValueError):
                runtime.native.call('bft-runtime-archive-store','--file',proposal,*arguments(runtime),
                                    '--expected-state-sha256',runtime._archive_head)
        finally:runtime.root.chmod(0o700)
        self.assertEqual(runtime.state_path.read_bytes(),before)
        self.assertEqual(runtime.head_path.read_bytes(),head)
        self.assertEqual(runtime.signer_status()['records'],records)

    def test_native_companion_reader_above_8mib_does_not_grant_cold_authority(self):
        runtime=self.open();base=dict(runtime.state);root=runtime.root;path=runtime.state_path
        caller=runtime.head_path.read_bytes();runtime.close();self.runtime=None
        messages=Messages()
        for n in range(9):
            envelope=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency=self.native.currency,region=runtime.region,
                          evidence=dict(snapshots=[dict(codec_only=n,padding='x'*(1024*1024))]),body=dict(codec_only=n))
            messages=messages.append(mesh.digest(envelope['body']),envelope,None,False)
        packed=pack_state(dict(base,messages=messages));raw=wire.canonical(packed)
        self.assertGreater(len(raw),8*1024*1024);self.assertLess(len(raw),32*1024*1024)
        mesh.atomic(path,packed)
        receipt=self.native.call('bft-runtime-archive-read',*arguments(runtime))
        self.assertEqual(receipt['state_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt['state_bytes'],len(raw));self.assertTrue(receipt['full_cold_authentication_required'])
        self.assertFalse(receipt['ledger_changed']);self.assertFalse(receipt['signing_authority'])
        # Complete Native authentication still rejects every modeled codec proof;
        # this successful byte read cannot initialize a ledger or release a vote.
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(path.read_bytes(),raw)
        self.assertEqual(runtime.head_path.read_bytes(),caller)
        self.assertEqual(self.native.call('bft-status','--signer-dir',runtime.signer)['records'],0)

    def test_retained_residue_object_and_byte_capacity_refuse_without_pruning(self):
        runtime=self.open();before=runtime.state_path.read_bytes();head=runtime.head_path.read_bytes()
        # Known no-value sparse residue tests the complete retained byte inventory.
        residue=runtime.root/'retained-failed-publication'
        fd=os.open(residue,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:os.ftruncate(fd,256*1024*1024)
        finally:os.close(fd)
        with self.assertRaisesRegex(ValueError,'capacity'):runtime.save(dict(runtime.state,cursor=1))
        self.assertEqual(runtime.state_path.read_bytes(),before);self.assertEqual(runtime.head_path.read_bytes(),head)
        self.assertEqual(residue.stat().st_size,256*1024*1024)
        # Keep the failed oversized root; use a new independent fixture for count.
        runtime.close();self.runtime=None
        from regional_bft_network_campaign import Campaign
        from regional_contact_node import Native
        from regional_contact_campaign import public
        from test_regional_bft_retention import BINARY
        count_root=self.c.root/'fresh-count-fixture'
        campaign=Campaign(BINARY,count_root)
        native=Native(BINARY,campaign.node('earth',0),public(1),campaign.currency)
        transport=mesh.load(campaign.root/'mesh-config-0.json',65536)
        count_runtime=Runtime(native,transport,campaign.root/'bft-config-0.json')
        try:
            retained=count_runtime.state_path.read_bytes();caller=count_runtime.head_path.read_bytes()
            for n in range(4096):
                fd=os.open(count_runtime.root/('retained-residue-'+str(n)),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
            with self.assertRaisesRegex(ValueError,'capacity'):count_runtime.save(dict(count_runtime.state,cursor=1))
            self.assertEqual(count_runtime.state_path.read_bytes(),retained)
            self.assertEqual(count_runtime.head_path.read_bytes(),caller)
            self.assertGreater(len(list(count_runtime.root.iterdir())),4096)
        finally:count_runtime.close();campaign.cleanup()

if __name__=='__main__':unittest.main()
