"""Real native file operations against the retained independent Python oracle."""
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import interstellar_storage as native
import interstellar_storage_reference as reference
import interstellar_transfer as wire
from interstellar_crypto import backend

class NativeStorageTests(unittest.TestCase):
    def root(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-storage-')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_independent_existing_bytes_and_inode_are_preserved(self):
        root=self.root();raw=wire.canonical({'complete':['ordered',17],'signature':'public fixture only'})
        old=root/'python.json';new=root/'native.json'
        reference.archive_write(old,raw);native.archive_write(new,raw)
        inode=old.stat().st_ino
        native.archive_write(old,raw)
        self.assertEqual(old.read_bytes(),new.read_bytes());self.assertEqual(old.stat().st_ino,inode)
        with self.assertRaisesRegex(ValueError,'existing archive differs'):native.archive_write(old,raw+b'x')
        self.assertEqual(old.read_bytes(),raw);self.assertEqual(len(list(root.iterdir())),2)
        reference.sync_retained_many([old,new,old]);native.sync_retained_many([old,new,old])

    def test_default_native_operations_use_no_python_file_syscalls(self):
        root=self.root();path=root/'a';backend()
        with patch.object(os,'open',side_effect=AssertionError('Python file open')),\
             patch.object(os,'link',side_effect=AssertionError('Python publication')),\
             patch.object(os,'fsync',side_effect=AssertionError('Python sync')):
            native.archive_write(path,b'complete bytes');native.sync_retained_many([path,path])
        self.assertEqual(path.read_bytes(),b'complete bytes')

    def test_symlink_and_missing_file_refuse_without_replacing_evidence(self):
        root=self.root();old=root/'old';old.write_bytes(b'old');link=root/'link';link.symlink_to(old)
        with self.assertRaises(OSError):native.archive_write(link,b'old')
        with self.assertRaises(OSError):native.sync_retained(link)
        with self.assertRaises(OSError):native.sync_retained(root/'missing')
        self.assertEqual(old.read_bytes(),b'old');self.assertTrue(link.is_symlink())

    def test_new_parent_retains_private_directory_and_file_permissions(self):
        root=self.root();path=root/'new-private-parent'/'file'
        previous=os.umask(0o022)
        try:native.archive_write(path,b'complete bytes')
        finally:os.umask(previous)
        self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
        self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_abi_payload_commitment_and_original_bounds_refuse(self):
        root=self.root();path=root/'a'
        with self.assertRaisesRegex(ValueError,'binding'):
            native._invoke({'ArchiveWrite':dict(path=str(path),sha256=hashlib.sha256(b'expected').hexdigest(),size_bytes=5)},b'wrong')
        self.assertFalse(path.exists())
        with self.assertRaisesRegex(ValueError,'capacity'):
            native.sync_retained_many([root/str(i) for i in range(native.MAX_PATHS+1)])
        # A declared oversized pointer is rejected before any payload access.
        engine=backend();one=(ctypes.c_ubyte*1)(0)
        with self.assertRaisesRegex(ValueError,'ABI input invalid'):
            engine.invoke(engine.library.rld_contact_storage,'Info',one,native.MAX_FILE+1)

    def test_actual_maximum_payload_has_no_json_expansion_or_new_file_limit(self):
        root=self.root();raw=b'x'*native.MAX_FILE;path=root/'maximum'
        native.archive_write(path,raw);self.assertEqual(path.stat().st_size,native.MAX_FILE)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),hashlib.sha256(raw).digest())
        with self.assertRaisesRegex(ValueError,'capacity'):native.archive_write(root/'over',raw+b'x')
        self.assertFalse((root/'over').exists())

    def test_response_loss_never_substitutes_for_successful_custody_observation(self):
        root=self.root();path=root/'a';engine=backend();native.sync_retained_many([])
        actual=engine.invoke
        def lose(operation,request,*args):
            value=actual(operation,request,*args)
            if type(request) is dict and 'ArchiveWrite' in request:raise ValueError('lost native publication observation')
            return value
        with patch.object(engine,'invoke',side_effect=lose):
            with self.assertRaisesRegex(ValueError,'lost native'):native.archive_write(path,b'exact')
        self.assertEqual(path.read_bytes(),b'exact');inode=path.stat().st_ino
        native.archive_write(path,b'exact');self.assertEqual(path.stat().st_ino,inode)

    def test_wrong_return_shape_or_authority_refuses(self):
        root=self.root();path=root/'a';native.archive_write(path,b'bytes');engine=backend()
        with patch.object(engine,'invoke',return_value={'ledger_authority':True}):
            with self.assertRaisesRegex(ValueError,'response differs'):native.sync_retained(path)
        self.assertEqual(path.read_bytes(),b'bytes')

if __name__=='__main__':unittest.main()
