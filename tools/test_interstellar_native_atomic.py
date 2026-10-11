"""Native mutable-state file publication and the independent Python byte oracle."""
import hashlib
import os
import copy
import signal
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_storage as native
import interstellar_storage_reference as reference
import interstellar_transfer as wire
from interstellar_crypto import backend

class NativeAtomicTests(unittest.TestCase):
    def root(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-atomic-')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_complete_bytes_match_independent_existing_file_replacement(self):
        root=self.root();a=root/'old-reference';b=root/'native'
        for raw in (wire.canonical({'signed_index':['original',17]}),wire.canonical({'signed_index':['new',18]})):
            reference.atomic_bytes(a,raw);native.atomic_write(b,raw)
            self.assertEqual(a.read_bytes(),b.read_bytes())
            self.assertEqual(b.stat().st_mode&0o777,0o600)
        self.assertEqual(len(list(root.iterdir())),2)

    def test_mutable_publication_uses_no_python_filesystem_syscalls(self):
        root=self.root();path=root/'state';path.write_bytes(b'old');backend()
        with patch.object(os,'open',side_effect=AssertionError('Python open')),\
             patch.object(os,'replace',side_effect=AssertionError('Python replace')),\
             patch.object(os,'fsync',side_effect=AssertionError('Python sync')):
            native.atomic_write(path,b'new complete bytes')
            mesh.atomic(path,{'fixture_only':True,'no_value':True})
        self.assertEqual(path.read_bytes(),wire.canonical({'fixture_only':True,'no_value':True}))

    def test_original_state_capacity_checked_before_native_publication(self):
        root=self.root();path=root/'state';path.write_bytes(b'old')
        with patch.object(mesh,'MAX_STATE',2):
            with self.assertRaisesRegex(ValueError,'capacity'):native.atomic_write(path,b'new')
        self.assertEqual(path.read_bytes(),b'old')
        with patch.object(mesh,'MAX_STATE',3):native.atomic_write(path,b'new')
        self.assertEqual(path.read_bytes(),b'new')
        with self.assertRaisesRegex(ValueError,'capacity'):
            native._invoke({'AtomicWrite':dict(path=str(path),size_bytes=3,sha256=hashlib.sha256(b'new').hexdigest(),limit=2)},b'new')
        self.assertEqual(path.read_bytes(),b'new')

    def test_failed_actual_replace_keeps_old_directory_and_cleans_owned_staging(self):
        root=self.root();path=root/'directory';path.mkdir();retained=path/'retained';retained.write_bytes(b'old')
        with self.assertRaises(OSError):native.atomic_write(path,b'new')
        self.assertEqual(retained.read_bytes(),b'old');self.assertEqual(list(root.iterdir()),[path])

    def test_lost_replace_response_preserves_new_bytes_and_never_rolls_back(self):
        root=self.root();path=root/'state';native.atomic_write(path,b'old');engine=backend();actual=engine.invoke
        def lose(operation,request,*args):
            value=actual(operation,request,*args)
            if type(request) is dict and 'AtomicWrite' in request:raise ValueError('lost atomic publication response')
            return value
        with patch.object(engine,'invoke',side_effect=lose):
            with self.assertRaisesRegex(ValueError,'lost atomic'):native.atomic_write(path,b'new')
        self.assertEqual(path.read_bytes(),b'new')
        native.atomic_write(path,b'new');self.assertEqual(path.read_bytes(),b'new')

    def test_atomic_directory_entry_replacement_never_writes_through_final_symlink(self):
        root=self.root();original=root/'original';original.write_bytes(b'untouched')
        link=root/'link';link.symlink_to(original)
        native.atomic_write(link,b'new')
        self.assertFalse(link.is_symlink());self.assertEqual(link.read_bytes(),b'new')
        self.assertEqual(original.read_bytes(),b'untouched')

    def test_native_sigkill_retains_complete_authenticated_shared_state(self):
        from test_interstellar_mesh import Fixture
        binary=os.environ.get('RLD_CONTACT_STORAGE_TEST_BINARY')
        if not binary:self.skipTest('requires separately compiled and source-bound native storage test executable')
        for boundary in ('state-prepared','state-replaced'):
            with self.subTest(boundary=boundary):
                root=self.root();fixture=Fixture(root)
                with fixture.node('earth') as node:
                    node.enqueue(fixture.frame(),fixture.identities['andromeda']['node_id'])
                    original=copy.deepcopy(node.state);path=node.path
                old=path.read_bytes();new=copy.deepcopy(original);new['cursor']+=1
                payload=root/'complete-new-state.json';payload.write_bytes(wire.canonical(mesh.pack_state_storage(new)));payload.chmod(0o600)
                result=subprocess.run([binary,'--exact','contact_storage::tests::atomic_crash_child','--nocapture'],
                    env=dict(os.environ,RLD_ATOMIC_CRASH_TARGET=str(path),RLD_ATOMIC_CRASH_POINT=boundary,
                             RLD_ATOMIC_CRASH_PAYLOAD=str(payload)),capture_output=True,timeout=10)
                self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr.decode())
                self.assertEqual(path.read_bytes(),old if boundary=='state-prepared' else payload.read_bytes())
                before={p:p.read_bytes() for p in path.parent.glob('.write-*')}
                self.assertEqual(len(before),int(boundary=='state-prepared'))
                with fixture.node('earth') as node:
                    self.assertEqual(node.state,original if boundary=='state-prepared' else new)
                    self.assertEqual(node.state['messages'],original['messages'])
                self.assertEqual({p:p.read_bytes() for p in before},before)

if __name__=='__main__':unittest.main()
