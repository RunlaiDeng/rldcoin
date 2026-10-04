"""Actual transport authentication and exact shared-object custody boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture


class SharedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-shared-archive-')
        self.f=Fixture(self.temp.name)

    def tearDown(self):self.temp.cleanup()

    def complete(self,count=1):
        with self.f.node('earth') as node:
            ids=[node.enqueue(self.f.frame(),node.id) for _ in range(count)]
            original={i:copy.deepcopy(node.state['messages'][i]) for i in ids}
        return ids,original

    def archive(self,count=1):
        ids,original=self.complete(count)
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertEqual(node.archive_completed(),count)
            entries=copy.deepcopy(node.state['archives'])
        return ids,original,entries

    def test_same_exact_frame_shares_one_object_without_changing_complete_transits(self):
        ids,original,entries=self.archive(3)
        refs={v['body']['frame_object']['file_id'] for v in entries.values()}
        self.assertEqual(len(refs),1)
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('earth') as node:
            inventory,_=node.archive_inventory()
            self.assertEqual(len(inventory),4)
            for ident in ids:
                self.assertEqual(node.transit(ident),original[ident])
                blob=node.archived(ident)
                self.assertEqual(mesh.digest(blob),entries[ident]['body']['expanded_sha256'])
            self.assertFalse(node.status()['payment_authorized'])

    def test_shared_frame_corruption_and_missing_file_refuse_with_warm_index(self):
        ids,_,entries=self.archive(2)
        with self.f.node('earth') as node:
            path=node.archive_root/(entries[ids[0]]['body']['frame_object']['file_id']+'.json')
            original=path.read_bytes();value=wire.decode_json(original);frame=value['frame']
            value['frame']=('A' if frame[0]!='A' else 'B')+frame[1:]
            bad=wire.canonical(value);self.assertEqual(len(bad),len(original));path.write_bytes(bad)
            retained=node.path.read_bytes()
            for ident in ids:
                with self.assertRaisesRegex(ValueError,'frame bytes differ'):node.archived(ident)
            self.assertEqual(node.path.read_bytes(),retained)
        path.unlink()
        with self.assertRaisesRegex(ValueError,'frame missing'):self.f.node('earth')
        self.assertEqual((self.f.root/'earth/mesh-state.json').read_bytes(),retained)

    def rewrite(self,node,ident,change):
        entry=copy.deepcopy(node.state['archives'][ident]['body'])
        old=node.archive_root/(entry['file_id']+'.json');wrapper=wire.decode_json(old.read_bytes())
        change(entry,wrapper)
        raw=wire.canonical(wrapper);entry.update(file_id=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
        wire.write_new(node.archive_root/(entry['file_id']+'.json'),raw)
        node.state['archives'][ident]=mesh.sign(node.key,'archive',entry);node.save()

    def test_owner_signed_changed_expansion_commitment_still_refuses(self):
        ids,_,_=self.archive()
        with self.f.node('earth') as node:
            def change(entry,wrapper):
                entry['expanded_sha256']=wrapper['expanded_sha256']='f'*64
            self.rewrite(node,ids[0],change);retained=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'expanded archive bytes differ'):node.archived(ids[0])
            self.assertEqual(node.path.read_bytes(),retained)

    def test_owner_signed_foreign_frame_object_does_not_supply_trusted_bytes(self):
        ids,_,entries=self.archive()
        with self.f.node('earth') as node:
            ref=entries[ids[0]]['body']['frame_object'];payload=wire.decode_json((node.archive_root/(ref['file_id']+'.json')).read_bytes())
            payload['node_id']='f'*64;raw=wire.canonical(payload);foreign=dict(file_id=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
            wire.write_new(node.archive_root/(foreign['file_id']+'.json'),raw)
            def change(entry,wrapper):entry['frame_object']=wrapper['frame_object']=foreign
            self.rewrite(node,ids[0],change);retained=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'frame domain/schema'):node.archived(ids[0])
            self.assertEqual(node.path.read_bytes(),retained)

    def test_valid_storage_digests_do_not_replace_original_packet_signature(self):
        ids,_,entries=self.archive()
        with self.f.node('earth') as node:
            complete=node.archived(ids[0]);ref=entries[ids[0]]['body']['frame_object']
            payload=wire.decode_json((node.archive_root/(ref['file_id']+'.json')).read_bytes())
            old=payload['frame'];payload['frame']=('A' if old[0]!='A' else 'B')+old[1:]
            raw=wire.canonical(payload);changed=dict(file_id=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
            wire.write_new(node.archive_root/(changed['file_id']+'.json'),raw)
            complete['transit']['packet']['body']['frame']=payload['frame']
            expanded=wire.canonical(complete)
            def change(entry,wrapper):
                entry['frame_object']=wrapper['frame_object']=changed
                entry['expanded_sha256']=wrapper['expanded_sha256']=hashlib.sha256(expanded).hexdigest()
                entry['expanded_size_bytes']=wrapper['expanded_size_bytes']=len(expanded)
            self.rewrite(node,ids[0],change);retained=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'signature'):node.archived(ids[0])
            self.assertEqual(node.path.read_bytes(),retained)

    def test_expansion_refuses_before_authentication_if_complete_bytes_exceed_bound(self):
        self.f.frame=lambda:wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"fixture":"'+b'x'*16384+b'"}')
        ids,_,entries=self.archive()
        with self.f.node('earth') as node:
            entry=entries[ids[0]]['body'];limit=max(entry['size_bytes'],entry['frame_object']['size_bytes'])+1024
            self.assertGreater(entry['expanded_size_bytes'],limit)
            def change(entry,wrapper):entry['expanded_size_bytes']=wrapper['expanded_size_bytes']=limit
            self.rewrite(node,ids[0],change);retained=node.path.read_bytes()
            with patch.object(mesh,'MAX_STATE',limit),patch.object(mesh,'transit_check',side_effect=AssertionError('unchecked expansion reached authentication')):
                with self.assertRaisesRegex(ValueError,'expanded archive capacity/size'):node.archived(ids[0])
            self.assertEqual(node.path.read_bytes(),retained)

    def test_pair_admission_counts_both_objects_before_writing_or_moving_active_evidence(self):
        ids,_=self.complete()
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'MAX_ARCHIVE_FILES',1),self.assertRaisesRegex(ValueError,'capacity'):
                node.archive_completed()
            self.assertEqual(list(node.archive_root.iterdir()),[])
            self.assertEqual(node.path.read_bytes(),before)
            self.assertIn(ids[0],node.state['messages'])

    def test_final_two_file_limit_refuses_before_temporary_third_directory_entry(self):
        self.complete()
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'MAX_ARCHIVE_FILES',2),patch.object(mesh,'archive_write',side_effect=AssertionError('unreserved staging reached write')):
                with self.assertRaisesRegex(ValueError,'archive capacity'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual(list(node.archive_root.iterdir()),[])

    def test_actual_link_peak_stays_within_three_reserved_file_slots(self):
        self.complete();link=mesh.os.link;peaks=[]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            def measure(source,target):
                link(source,target);peaks.append(len(list(node.archive_root.iterdir())))
            with patch.object(mesh,'MAX_ARCHIVE_FILES',3),patch.object(mesh.os,'link',side_effect=measure):
                self.assertEqual(node.archive_completed(),1)
            self.assertEqual(peaks,[2,3])
            self.assertEqual(len(list(node.archive_root.iterdir())),2)

    def test_sigkill_at_wrapper_link_preserves_bounded_residue_and_cold_authentication(self):
        ids,original=self.complete()
        state_path=self.f.root/'earth/mesh-state.json';before=state_path.read_bytes()
        worker="""
import json,os,signal,sys
import interstellar_mesh as mesh
mesh.MAX_ARCHIVE_FILES=3;mesh.ARCHIVE_HIGH_WATER=1
with mesh.Node(json.loads(sys.argv[1])) as node:
    link=mesh.os.link
    def interrupted(source,target):
        link(source,target)
        if mesh.load(target,mesh.MAX_STATE)['format']==mesh.ARCHIVE_STORAGE:
            os.kill(os.getpid(),signal.SIGKILL)
    mesh.os.link=interrupted
    node.archive_completed()
raise RuntimeError('hard-link interruption not reached')
"""
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(Path(mesh.__file__).parent))
        result=subprocess.run([sys.executable,'-B','-c',worker,json.dumps(self.f.configs['earth'])],
                              env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr.decode())
        root=self.f.root/'earth/archive'
        kept={p:(p.read_bytes(),p.stat().st_ino) for p in root.iterdir()}
        self.assertEqual(len(kept),3)
        self.assertEqual(sum(p.name.startswith('.archive-write-') for p in kept),1)
        self.assertEqual(state_path.read_bytes(),before)
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with patch.object(mesh,'MAX_ARCHIVE_FILES',3),patch.object(mesh,'ARCHIVE_HIGH_WATER',1),self.f.node('earth') as node:
            self.assertEqual(len(node.archive_inventory()[0]),3)
            self.assertEqual(node.state['archives'],{})
            self.assertEqual(node.archive_completed(),1)
            self.assertEqual(node.transit(ids[0]),original[ids[0]])
            self.assertFalse(node.status()['payment_authorized'])
        self.assertEqual({p:(p.read_bytes(),p.stat().st_ino) for p in root.iterdir()},kept)

    def test_existing_orphan_plus_final_wrapper_bytes_do_not_reserve_staging_peak(self):
        self.complete();write=mesh.archive_write;recorded=[]
        def fail(path,raw):
            recorded.append(raw)
            if len(recorded)==2:raise OSError('injected wrapper failure')
            write(path,raw)
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            with patch.object(mesh,'archive_write',side_effect=fail),self.assertRaisesRegex(OSError,'wrapper failure'):
                node.archive_completed()
            before=node.path.read_bytes();objects={p:p.read_bytes() for p in node.archive_root.iterdir()}
            final_bytes=sum(len(raw) for raw in recorded)
            with patch.object(mesh,'MAX_ARCHIVE_BYTES',final_bytes),patch.object(mesh,'archive_write',side_effect=AssertionError('unreserved staging bytes reached write')):
                with self.assertRaisesRegex(ValueError,'archive capacity'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual({p:p.read_bytes() for p in objects},objects)

    def test_wrapper_write_failure_retains_exact_payload_orphan_and_original_active_state(self):
        ids,original=self.complete();write=mesh.archive_write;calls=[]
        def fail(path,raw):
            calls.append(wire.decode_json(raw)['format'])
            if len(calls)==2:raise OSError('injected wrapper durability failure')
            write(path,raw)
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'archive_write',side_effect=fail),self.assertRaisesRegex(OSError,'wrapper durability'):
                node.archive_completed()
            self.assertEqual(calls,[mesh.ARCHIVE_FRAME,mesh.ARCHIVE_STORAGE])
            self.assertEqual(node.path.read_bytes(),before)
            files=list(node.archive_root.glob('*.json'));self.assertEqual(len(files),1);kept=files[0].read_bytes()
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertEqual(node.archive_completed(),1)
            self.assertEqual(files[0].read_bytes(),kept)
            self.assertEqual(node.transit(ids[0]),original[ids[0]])

    def test_legacy_private_state_refuses_without_rewrite_or_conversion(self):
        self.archive()
        path=self.f.root/'earth/mesh-state.json';state=mesh.load(path,mesh.MAX_STATE);state.pop('archive_storage');mesh.atomic(path,state)
        before={p:p.read_bytes() for p in (self.f.root/'earth').rglob('*') if p.is_file()}
        with self.assertRaisesRegex(ValueError,'corrupt state identity'):self.f.node('earth')
        self.assertEqual({p:p.read_bytes() for p in before},before)

    def test_legacy_private_identity_cannot_initialize_an_empty_new_store(self):
        root=(self.f.root/'legacy-identity').resolve();identity=mesh.initialize(root,'a'*64,'1'*64,'legacy')
        path=root/'identity.private.json';value=mesh.load(path,8192);value.pop('archive_storage');mesh.atomic(path,value)
        retained=path.read_bytes()
        config=dict(format=mesh.VERSION,state=str(root),network=identity['network'],contacts=[])
        with self.assertRaisesRegex(ValueError,'identity network/storage'):mesh.Node(config)
        self.assertEqual(path.read_bytes(),retained)
        self.assertFalse((root/'mesh-state.json').exists())
        self.assertFalse((root/'archive').exists())

    def test_duplicate_custody_syncs_payload_then_wrapper_and_refuses_failed_fsync(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['proxima']['node_id'])
            bundle=node.exchange(self.f.identities['proxima']['node_id']);peer=node.id
        with self.f.node('proxima') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.receive(bundle,peer);node.archive_completed();body=node.state['archives'][ident]['body']
            expected=[body['frame_object']['file_id']+'.json',body['file_id']+'.json'];synced=[];sync=mesh.sync_retained
            def observe(path):synced.append(path.name);sync(path)
            sync_many=mesh.sync_retained_many
            def observe_many(paths):synced.extend(path.name for path in paths);sync_many(paths)
            with patch.object(mesh,'sync_retained',side_effect=observe),patch.object(mesh,'sync_retained_many',side_effect=observe_many):node.receive(bundle,peer)
            self.assertEqual(synced,expected+['mesh-state.json'])
            before=node.path.read_bytes()
            with patch.object(mesh,'sync_retained_many',side_effect=OSError('injected fsync failure')),self.assertRaisesRegex(OSError,'fsync failure'):
                node.receive(bundle,peer)
            self.assertEqual(node.path.read_bytes(),before)


if __name__=='__main__':unittest.main()
