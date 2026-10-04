"""Fresh no-value transport storage; complete signatures still checked by Node."""
import copy
import hashlib
import tempfile
import os
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

import interstellar_active_state as codec
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture


class ActiveStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.f=Fixture(self.tmp.name)
        with self.f.node('earth') as node:
            for _ in range(3):node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.path=node.path;self.original=copy.deepcopy(node.state)
        self.raw=self.path.read_bytes();self.image=wire.decode_json(self.raw)

    def unpack(self,image):
        return mesh.unpack_state_storage(image,self.original['network'],self.original['node_id'])

    def write(self,image):self.path.write_bytes(wire.canonical(image))

    def test_exact_complete_roundtrip_and_immutable_shared_string_on_cold_restart(self):
        self.assertEqual(len(self.image['frames']),1)
        self.assertEqual(self.unpack(self.image),self.original)
        values=list(self.unpack(self.image)['messages'].values())
        self.assertIs(values[0]['packet']['body']['frame'],values[1]['packet']['body']['frame'])
        with self.f.node('earth') as node:self.assertEqual(node.state,self.original)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_distinct_frames_are_kept_exact_and_not_payload_only_deduplicated(self):
        with self.f.node('earth') as node:
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"distinct":true}')
            node.enqueue(frame,self.f.identities['andromeda']['node_id'])
            state=copy.deepcopy(node.state)
        image=wire.decode_json(self.path.read_bytes())
        self.assertEqual(len(image['frames']),2);self.assertEqual(self.unpack(image),state)

    def test_original_state_limit_charges_pool_and_metadata_and_refuses_before_write(self):
        size=len(self.raw)
        with patch.object(mesh,'MAX_STATE',size-1):
            with self.assertRaisesRegex(ValueError,'capacity'):mesh.atomic(self.path,self.original)
        self.assertEqual(self.path.read_bytes(),self.raw)
        with patch.object(mesh,'MAX_STATE',size):mesh.atomic(self.path,self.original)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_full_original_transit_size_bound_checked_before_reconstruction(self):
        for declared in (False,0,mesh.MAX_BATCH+1,1):
            image=copy.deepcopy(self.image);entry=next(iter(image['state']['messages'].values()))
            entry['expanded_size_bytes']=declared
            with self.subTest(size=declared),self.assertRaisesRegex(ValueError,'expanded'):self.unpack(image)

    def test_pool_and_message_count_limits_do_not_drop_pending_evidence(self):
        with patch.object(mesh,'MAX_MESSAGES',2):
            with self.assertRaisesRegex(ValueError,'capacity'):self.unpack(self.image)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_frame_corruption_missing_and_unreferenced_pool_refuse(self):
        ref=next(iter(self.image['frames']))
        for mode in ('corrupt','missing','orphan'):
            image=copy.deepcopy(self.image)
            if mode=='corrupt':image['frames'][ref]['frame']='AAAA'
            elif mode=='missing':del image['frames'][ref]
            else:
                obj=dict(image['frames'][ref],frame='AAAA');image['frames'][codec.digest(obj)]=obj
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.unpack(image)

    def test_external_image_metadata_and_frame_ownership_each_refuse(self):
        for location in ('image','state','object'):
            image=copy.deepcopy(self.image)
            target=image if location=='image' else image['state'] if location=='state' else next(iter(image['frames'].values()))
            target['network']='f'*64
            with self.subTest(location=location),self.assertRaises(ValueError):self.unpack(image)

    def test_complete_transit_digest_detects_changed_routing_or_hops(self):
        for field in ('routing','hops'):
            image=copy.deepcopy(self.image);entry=next(iter(image['state']['messages'].values()))
            if field=='routing':entry['transit'][field]['signature']='0'*128
            else:entry['transit'][field]=[{}]
            with self.subTest(field=field),self.assertRaises(ValueError):self.unpack(image)

    def test_storage_hashes_do_not_replace_native_packet_signature_or_routing_checks(self):
        state=copy.deepcopy(self.original);old=next(iter(state['messages']));transit=state['messages'].pop(old)
        transit['packet']['body']['nonce']='f'*64
        state['messages'][mesh.digest(transit['packet'])]=transit
        self.write(mesh.pack_state_storage(state))
        retained=self.path.read_bytes()
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(self.path.read_bytes(),retained)

    def test_legacy_inline_state_refuses_even_with_current_marker_without_rewrite(self):
        self.path.write_bytes(wire.canonical(self.original));retained=self.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'legacy'):self.f.node('earth')
        self.assertEqual(self.path.read_bytes(),retained)

    def test_legacy_identity_refuses_without_conversion(self):
        path=self.path.parent/'identity.private.json';identity=mesh.load(path,8192);identity.pop('active_storage')
        mesh.atomic(path,identity);retained=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'identity'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),retained);self.assertEqual(self.path.read_bytes(),self.raw)

    def test_failed_atomic_publication_retains_previous_pending_state(self):
        state=copy.deepcopy(self.original);state['cursor']+=1
        with patch.object(mesh.os,'replace',side_effect=OSError('injected publication failure')):
            with self.assertRaises(OSError):mesh.atomic(self.path,state)
        self.assertEqual(self.path.read_bytes(),self.raw)
        with self.f.node('earth') as node:self.assertEqual(node.state,self.original)

    def test_pending_shared_transits_survive_cold_multihop_and_destination_receipt(self):
        expected=set(self.original['messages']);self.f.rounds(8)
        with self.f.node('earth') as node:
            self.assertTrue(expected<=set(node.state['receipts'])|set(node.state['archives']))
            for ident in expected:self.assertEqual(node.transit(ident),self.original['messages'][ident])
        with self.f.node('andromeda') as node:self.assertTrue(expected<=set(node.state['receipts'])|set(node.state['archives']))

    def test_actual_process_sigkill_before_and_after_replace_retains_exact_authentic_state(self):
        for boundary in ('before','after'):
            self.path.write_bytes(self.raw)
            code="""
import os,signal,sys
from pathlib import Path
import interstellar_mesh as mesh
path=Path(sys.argv[1]);state=mesh.load(path,mesh.MAX_STATE);state['cursor']+=1
boundary=sys.argv[2]
if boundary=='before':
 original=mesh.evidence.write_new
 def die(path,raw):
  original(path,raw);os.kill(os.getpid(),signal.SIGKILL)
 mesh.evidence.write_new=die
else:
 original=mesh.os.replace
 def die(a,b):
  original(a,b);os.kill(os.getpid(),signal.SIGKILL)
 mesh.os.replace=die
mesh.atomic(path,state)
raise AssertionError('unreachable acknowledgment')
"""
            result=subprocess.run([sys.executable,'-B','-c',code,str(self.path),boundary],
                                  env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(result.returncode,-signal.SIGKILL)
            with self.f.node('earth') as node:
                expected=dict(self.original,cursor=self.original['cursor']+(boundary=='after'))
                self.assertEqual(node.state,expected)
            self.assertEqual(set(mesh.load(self.path,mesh.MAX_STATE)['messages']),set(self.original['messages']))
        self.assertTrue(list(self.path.parent.glob('.write-*')))

    def test_canonical_raw_decoder_refuses_duplicate_fields_and_noncanonical_bytes(self):
        for raw in (b'{"format":1,"format":2}',self.raw+b'\n'):
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):self.f.node('earth')
            self.assertEqual(self.path.read_bytes(),raw)


if __name__=='__main__':unittest.main()
