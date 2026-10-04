"""Operation-scoped real fsync; no Native, sockets or original private stores."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_receipt_scheduler import Fixture


class CustodySyncTests(unittest.TestCase):
    def test_unique_files_and_parent_are_actually_synced_once_per_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);paths=[root/'a',root/'b']
            for path in paths:path.write_bytes(b'complete retained bytes')
            actual=os.fsync;seen=[]
            def synced(fd):
                info=os.fstat(fd);seen.append((info.st_ino,stat.S_ISDIR(info.st_mode)));actual(fd)
            with patch.object(os,'fsync',side_effect=synced):
                mesh.sync_retained_many([paths[0],paths[1],paths[0]])
                self.assertEqual(len(seen),3)
                self.assertEqual(sum(directory for _,directory in seen),1)
                mesh.sync_retained_many(paths)
                self.assertEqual(len(seen),6)  # no cross-call witness

    def test_directory_failure_propagates_after_real_file_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a';path.write_bytes(b'retained');actual=os.fsync
            def failure(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('retained directory fsync failed')
                actual(fd)
            with patch.object(os,'fsync',side_effect=failure):
                with self.assertRaisesRegex(OSError,'directory fsync'):mesh.sync_retained_many([path])

    def test_symlink_file_and_original_capacity_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/'a';original.write_bytes(b'retained')
            link=root/'link';link.symlink_to(original)
            with self.assertRaises(OSError):mesh.sync_retained_many([link])
            with patch.object(os,'open',side_effect=AssertionError('capacity must precede opening')):
                with self.assertRaisesRegex(ValueError,'capacity'):
                    mesh.sync_retained_many([root/str(i) for i in range(2*(mesh.MAX_MESSAGES+mesh.MAX_PACKET_BATCH)+1)])

    def fixture(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        return Fixture(temporary.name,peer_count=2)

    def archived_shared_frame(self,f):
        source=f.node(1);destination=f.node(2)
        self.addCleanup(source.close);self.addCleanup(destination.close)
        frame=wire.make_frame('source-finality','b'*64,'d'*64,'c'*64,b'{"no_value_fixture":true}')
        source.enqueue_batch([(frame,destination.id),(frame,destination.id)])
        bundle=source.exchange(destination.id);destination.receive(bundle,source.id)
        with patch.object(mesh,'ARCHIVE_HIGH_WATER',1):self.assertEqual(destination.archive_completed(),2)
        return source,destination,bundle

    def test_complete_shared_archives_authenticate_before_one_batch_sync(self):
        source,destination,bundle=self.archived_shared_frame(self.fixture())
        read=destination.archived;actual=mesh.sync_retained_many;seen=[]
        def synced(paths):seen.append(tuple(paths));return actual(paths)
        with patch.object(destination,'archived',side_effect=read) as verified,patch.object(mesh,'sync_retained_many',side_effect=synced):
            destination.receive(bundle,source.id)
            self.assertEqual(verified.call_count,2)
            self.assertEqual(len(seen),1);self.assertEqual(len(seen[0]),3)
            self.assertEqual(len({p.parent for p in seen[0]}),1)
            frame_file=next(iter(destination.state['archives'].values()))['body']['frame_object']['file_id']+'.json'
            self.assertEqual(seen[0][0].name,frame_file)
            destination.receive(bundle,source.id)
            self.assertEqual(verified.call_count,4);self.assertEqual(len(seen),2)
        self.assertIsNone(destination._archive_sync_paths)

    def test_sync_failure_never_publishes_or_retains_a_batch_and_retry_rechecks(self):
        source,destination,bundle=self.archived_shared_frame(self.fixture())
        before=destination.path.read_bytes()
        with patch.object(mesh,'sync_retained_many',side_effect=OSError('retained custody fsync failure')):
            with self.assertRaisesRegex(OSError,'custody fsync'):destination.receive(bundle,source.id)
        self.assertEqual(destination.path.read_bytes(),before)
        self.assertIsNone(destination._archive_sync_paths)
        with patch.object(destination,'archived',wraps=destination.archived) as verified:
            destination.receive(bundle,source.id);self.assertEqual(verified.call_count,2)

    def test_later_invalid_transit_refuses_without_sync_publication_or_batch_reuse(self):
        source,destination,bundle=self.archived_shared_frame(self.fixture())
        body=copy.deepcopy(bundle['body']);body['transits'][-1]['packet']['signature']='0'*128
        hostile=mesh.sign(source.key,'exchange',body);before=destination.path.read_bytes()
        with patch.object(mesh,'sync_retained_many',side_effect=AssertionError('invalid exchange cannot sync')):
            with self.assertRaisesRegex(ValueError,'signature'):destination.receive(hostile,source.id)
        self.assertEqual(destination.path.read_bytes(),before)
        self.assertIsNone(destination._archive_sync_paths)
        destination.receive(bundle,source.id)


if __name__=='__main__':unittest.main()
