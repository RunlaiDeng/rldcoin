"""Actual native spool IO against the independent Python syscall oracle."""
import hashlib
import errno
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_spool_codec as codec
import interstellar_spool_native as native
import interstellar_spool_reference as reference
from interstellar_crypto import backend

class NativeSpoolTests(unittest.TestCase):
    def fixture(self):
        t=tempfile.TemporaryDirectory(prefix='rld-native-spool-');self.addCleanup(t.cleanup)
        root=Path(t.name);raw=b'{"exact":"'+b'original bytes '*2000+b'"}'
        return root,root/(hashlib.sha256(raw).hexdigest()+'.json'),raw,codec.encode(raw,limit=mesh.MAX_BATCH)

    def test_exact_bytes_inventory_duplicate_inode_and_collision_match_python(self):
        for adapter in (None,codec.FORMAT):
            root,target,raw,encoded=self.fixture();encoded=raw if adapter is None else encoded
            other,oracle,_,_=self.fixture()
            oracle=other/target.name
            native.publish_spool(target,encoded,raw,adapter);reference.publish_spool(oracle,encoded,raw,adapter)
            self.assertEqual(target.read_bytes(),oracle.read_bytes())
            actual=native.spool_inventory(root,adapter);expected=reference.spool_inventory(other,adapter)
            self.assertEqual(([p.name for p in actual[0]],*actual[1:]),([p.name for p in expected[0]],*expected[1:]))

    def test_real_native_inventory_and_io_use_no_python_filesystem_calls(self):
        root,target,raw,encoded=self.fixture();backend()
        with patch.object(os,'open',side_effect=AssertionError('Python open')), \
             patch.object(os,'link',side_effect=AssertionError('Python link')), \
             patch.object(os,'fsync',side_effect=AssertionError('Python sync')), \
             patch.object(Path,'iterdir',side_effect=AssertionError('Python inventory')):
            mesh.publish_spool(target,encoded,raw,codec.FORMAT)
            self.assertEqual(mesh.spool_inventory(root,codec.FORMAT),([target],len(raw),1))
        before=target.stat().st_ino
        native.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(target.stat().st_ino,before)
        wrong=b'other complete data'
        with self.assertRaisesRegex(ValueError,'collision'):
            native.publish_spool(target,codec.encode(wrong,limit=mesh.MAX_BATCH),wrong,codec.FORMAT)
        self.assertEqual(target.read_bytes(),encoded)

    def test_bad_compression_complete_digest_and_payload_binding_never_publish(self):
        root,target,raw,encoded=self.fixture()
        bad=bytearray(encoded);bad[len(codec.MAGIC)+8]^=1
        for data in (encoded[:-1],encoded+b'trailing',bytes(bad),b'',encoded+encoded):
            with self.subTest(size=len(data)),self.assertRaises(ValueError):native.publish_spool(target,data,raw,codec.FORMAT)
            self.assertEqual(list(root.iterdir()),[])
        with self.assertRaises(ValueError):native.publish_spool(target,encoded,b'wrong',codec.FORMAT)
        with self.assertRaisesRegex(ValueError,'payload binding'):
            native._invoke({'Publish':dict(path=str(target),adapter=codec.FORMAT,limits=native.limits(),encoded_size=len(encoded),encoded_sha256='0'*64,data_size=len(raw),data_sha256=hashlib.sha256(raw).hexdigest())},encoded,raw)
        self.assertEqual(list(root.iterdir()),[])

    def test_pending_full_reservation_headroom_limits_and_symlink_refuse(self):
        root,target,raw,encoded=self.fixture();pending=root/f'.rld-spool-pending-v1-{target.stem}-{len(raw)}-{"1"*32}.tmp'
        pending.write_bytes(b'partial')
        self.assertEqual(native.spool_inventory(root,codec.FORMAT),([],len(raw),1))
        for name,value in (('MAX_SPOOL_FILES',2),('MAX_SPOOL_BYTES',3*len(raw)-1)):
            with patch.object(mesh,name,value),self.assertRaisesRegex(ValueError,'capacity'):
                native.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(pending.read_bytes(),b'partial');pending.unlink();pending.symlink_to(target)
        with self.assertRaises(ValueError):native.spool_inventory(root,codec.FORMAT)
        pending.unlink();target.symlink_to(root/'absent')
        with self.assertRaises(OSError) as refused:native.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(refused.exception.errno,errno.ELOOP)
        self.assertTrue(target.is_symlink())

    def test_lost_result_preserves_complete_bytes_without_ack_and_rechecks(self):
        root,target,raw,encoded=self.fixture();engine=backend();invoke=engine.invoke
        def lose(operation,request,*args):
            result=invoke(operation,request,*args)
            if type(request) is dict and 'Publish' in request:raise ValueError('lost spool result')
            return result
        with patch.object(engine,'invoke',side_effect=lose),self.assertRaisesRegex(ValueError,'lost spool result'):
            native.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(target.read_bytes(),encoded)
        self.assertEqual(codec.decode(target.read_bytes(),limit=mesh.MAX_BATCH),raw)
        native.publish_spool(target,encoded,raw,codec.FORMAT)

    def test_header_digest_agreement_cannot_hide_different_complete_decoded_bytes(self):
        root,target,raw,encoded=self.fixture()
        wrong=bytes([raw[0]^1])+raw[1:]
        forged=bytearray(codec.encode(wrong,limit=mesh.MAX_BATCH))
        forged[len(codec.MAGIC)+8:codec.HEADER_SIZE]=hashlib.sha256(raw).digest()
        target.write_bytes(forged)
        with self.assertRaisesRegex(ValueError,'collision'):
            native.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(target.read_bytes(),forged)

    def test_actual_native_sigkill_boundaries_keep_residue_and_cold_admission(self):
        binary=os.environ.get('RLD_CONTACT_SPOOL_TEST_BINARY')
        self.assertTrue(binary,'requires bound current native test executable')
        raw=b'complete original bytes'
        for point in ('zero','partial','file','pending-dir','public','public-dir','cleanup'):
            root,target,_,_=self.fixture()
            result=subprocess.run([binary,'--exact','contact_spool::tests::crash_child','--nocapture'],
                env=dict(os.environ,RLD_SPOOL_CRASH_TARGET=str(target),RLD_SPOOL_CRASH_POINT=point),capture_output=True,timeout=10)
            self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr.decode())
            expected=point in ('public','public-dir','cleanup')
            self.assertEqual(native.spool_inventory(root),([target] if expected else [],len(raw)*(2 if expected and point!='cleanup' else 1),1 if point=='cleanup' or not expected else 2))
            before={p.name:p.read_bytes() for p in root.iterdir()}
            native.publish_spool(target,raw,raw)
            for name,data in before.items():self.assertEqual((root/name).read_bytes(),data)
            self.assertEqual(target.read_bytes(),raw)

if __name__=='__main__':unittest.main()
