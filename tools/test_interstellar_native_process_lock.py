"""Actual OS owners, handle failures and independent Python lock interoperability."""
import errno
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import interstellar_process_lock as native
import interstellar_process_lock_reference as reference
from interstellar_crypto import backend
import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture

class ProcessLockTests(unittest.TestCase):
    def root(self):
        tmp=tempfile.TemporaryDirectory(prefix='rld-native-process-lock-');self.addCleanup(tmp.cleanup);return Path(tmp.name)
    def test_same_named_os_lock_interoperates_and_regular_file_is_retained(self):
        root=self.root()
        for role in native.ROLES:
            with native.Lock.acquire(root,role,True):
                with self.assertRaises(BlockingIOError):reference.Lock.acquire(root,role,True)
            path=root/reference.NAMES[role];inode=path.stat().st_ino
            with reference.Lock.acquire(root,role,True):
                with self.assertRaises(BlockingIOError):native.Lock.acquire(root,role,True)
            self.assertEqual(path.stat().st_ino,inode)
            with native.Lock.acquire(root,role,True):pass
    def test_blocking_pending_does_not_hold_registry_and_cannot_be_released_as_owned(self):
        root=self.root();held=native.Lock.acquire(root,'Mesh',True);self.addCleanup(held.close)
        token='1'*32;result=[];errors=[]
        def wait():
            try:result.append(native._invoke({'Acquire':dict(token=token,path=str(root),role='Mesh',nonblocking=False)}))
            except BaseException as error:errors.append(error)
        before=native.usage();thread=threading.Thread(target=wait);thread.start()
        try:
            deadline=time.monotonic()+3
            while native.usage()!=before+1 and time.monotonic()<deadline:time.sleep(.005)
            self.assertEqual(native.usage(),before+1);self.assertTrue(thread.is_alive())
            with self.assertRaisesRegex(ValueError,'acquisition pending'):
                native._invoke({'Release':dict(token=token,path=str(root),role='Mesh')})
            with native.Lock.acquire(root,'Service',True):pass
        finally:held.close();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(len(result),1)
        native._invoke({'Release':dict(token=token,path=str(root),role='Mesh')});self.assertEqual(native.usage(),before-1)
    def test_duplicate_token_or_wrong_release_binding_never_closes_original_owner(self):
        root=self.root();held=native.Lock.acquire(root,'Mesh',True);self.addCleanup(held.close)
        with patch.object(native.secrets,'token_hex',return_value=held.token),self.assertRaisesRegex(ValueError,'already exists'):
            native.Lock.acquire(root/'other','Mesh',True)
        for role,path in [('Service',root),('Mesh',root/'other')]:
            with self.assertRaisesRegex(ValueError,'binding differs'):
                native._invoke({'Release':dict(token=held.token,path=str(path),role=role)})
        with self.assertRaises(BlockingIOError):reference.Lock.acquire(root,'Mesh',True)
    def test_lost_acquisition_cleans_only_its_known_reservation_and_lost_close_retries(self):
        root=self.root();engine=backend();invoke=engine.invoke;before=native.usage()
        def lose_acquire(operation,request,*args):
            value=invoke(operation,request,*args)
            if type(request) is dict and 'Acquire' in request:raise ValueError('lost acquire result')
            return value
        with patch.object(engine,'invoke',side_effect=lose_acquire),self.assertRaisesRegex(ValueError,'lost acquire'):
            native.Lock.acquire(root,'Mesh',True)
        self.assertEqual(native.usage(),before)
        held=native.Lock.acquire(root,'Mesh',True)
        def lose_close(operation,request,*args):
            value=invoke(operation,request,*args)
            if type(request) is dict and 'Release' in request:raise ValueError('lost release result')
            return value
        with patch.object(engine,'invoke',side_effect=lose_close),self.assertRaisesRegex(ValueError,'lost release'):held.close()
        self.assertFalse(held.closed)
        with native.Lock.acquire(root,'Mesh',True):held.close();self.assertTrue(held.closed)
        self.assertEqual(native.usage(),before)
    def test_ancestor_symlink_nonregular_lock_and_native_default_syscalls(self):
        root=self.root();native.safe_directory(root/'real');alias=root/'alias';alias.symlink_to(root/'real')
        for module in (native,reference):
            with self.assertRaisesRegex(ValueError,'symlink'):module.safe_directory(alias/'child')
        self.assertFalse((root/'real'/'child').exists())
        target=root/'protected';target.write_bytes(b'protected');(root/'.lock').symlink_to(target)
        with self.assertRaises(OSError) as refused:native.Lock.acquire(root,'Mesh',True)
        self.assertEqual(refused.exception.errno,errno.ELOOP);self.assertEqual(target.read_bytes(),b'protected')
        (root/'.lock').unlink();native.safe_directory(root/'api')
        with (patch.object(os,'open',side_effect=AssertionError('Python open')),
              patch.object(Path,'is_symlink',side_effect=AssertionError('Python stat')),
              patch.object(reference.fcntl,'flock',side_effect=AssertionError('Python flock'))):
            self.assertEqual(mesh.safe_dir(root/'api'),root/'api')
            with native.Lock.acquire(root/'api','Mesh',True):pass
    def test_constructor_failure_releases_mesh_owner_without_mutating_retained_state(self):
        root=self.root();fixture=Fixture(root);config=dict(fixture.configs['earth']);config['contacts']=['invalid']
        before=native.usage()
        with self.assertRaises(ValueError):mesh.Node(config)
        self.assertEqual(native.usage(),before)
        with fixture.node('earth'):pass
    def test_actual_cross_process_sigkill_releases_os_owner_but_retains_lock_file(self):
        root=self.root();code='''from pathlib import Path
import sys
from interstellar_process_lock import Lock
owner=Lock.acquire(Path(sys.argv[1]),'Mesh',True)
print('OWNED',flush=True)
sys.stdin.buffer.read(1)
raise AssertionError('unexpected release input')
'''
        child=subprocess.Popen([sys.executable,'-B','-c',code,str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,text=True,env=dict(os.environ,PYTHONPATH=str(Path(native.__file__).parent)))
        try:
            with selectors.DefaultSelector() as poll:
                poll.register(child.stdout,selectors.EVENT_READ);self.assertTrue(poll.select(3),'missing actual owner')
            self.assertEqual(child.stdout.readline().strip(),'OWNED')
            with self.assertRaises(BlockingIOError):native.Lock.acquire(root,'Mesh',True)
            inode=(root/'.lock').stat().st_ino;child.kill();child.wait(timeout=3)
            self.assertEqual(child.returncode,-signal.SIGKILL)
            with native.Lock.acquire(root,'Mesh',True):pass
            self.assertEqual((root/'.lock').stat().st_ino,inode)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=3)
            for stream in (child.stdin,child.stdout,child.stderr):stream.close()

    def test_handle_capacity_refusal_retains_every_owner_and_release_allows_new_owner(self):
        root=self.root();held=[];self.assertEqual(native.usage(),0)
        try:
            for n in range(native.MAX_HANDLES):held.append(native.Lock.acquire(root/str(n),'Mesh',True))
            self.assertEqual(native.usage(),native.MAX_HANDLES)
            with self.assertRaisesRegex(ValueError,'handle capacity'):native.Lock.acquire(root/'overflow','Mesh',True)
            self.assertFalse((root/'overflow').exists())
            with self.assertRaises(BlockingIOError):reference.Lock.acquire(root/'0','Mesh',True)
            held.pop().close()
            with native.Lock.acquire(root/'new','Mesh',True):self.assertEqual(native.usage(),native.MAX_HANDLES)
        finally:
            for lease in held:lease.close()
        self.assertEqual(native.usage(),0)

if __name__=='__main__':unittest.main()
