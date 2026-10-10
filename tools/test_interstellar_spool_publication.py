"""Atomic visible names, retained failures, unchanged bounded admission."""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_spool_codec as codec
import interstellar_transfer as wire


class SpoolPublicationTests(unittest.TestCase):
    def fixture(self):
        tmp = tempfile.TemporaryDirectory(prefix='rld-spool-publish-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        raw = wire.canonical({'exact': 'immutable-message' * 2000})
        encoded = codec.encode(raw, limit=mesh.MAX_BATCH)
        target = root / (hashlib.sha256(raw).hexdigest() + '.json')
        return root, target, raw, encoded

    def checked(self, root, raw):
        paths, total = mesh.spool_files(root, codec.FORMAT)
        for path in paths:
            self.assertEqual(codec.decode(path.read_bytes(), limit=mesh.MAX_BATCH), raw)
        return paths, total

    def test_old_writer_exposes_zero_length_final_name(self):
        root, target, raw, encoded = self.fixture()
        create, release, done = threading.Event(), threading.Event(), threading.Event()
        errors = []
        original = os.open
        old_stat = Path.stat
        def read_stat(path, *args, **kwargs):
            info = old_stat(path, *args, **kwargs)
            if path == target and threading.current_thread() is threading.main_thread():
                self.assertEqual(info.st_size, 0)
                release.set()
                self.assertTrue(done.wait(2))
            return info
        def opened(path, flags, *args, **kwargs):
            fd = original(path, flags, *args, **kwargs)
            if Path(path) == target and flags & os.O_WRONLY:
                create.set()
                if not release.wait(2):raise TimeoutError('writer gate')
            return fd
        def writer():
            try:wire.write_new(target, encoded)
            except BaseException as e:errors.append(repr(e))
            finally:done.set()
        with patch.object(os, 'open', side_effect=opened), patch.object(Path, 'stat', read_stat):
            t = threading.Thread(target=writer);t.start()
            try:
                self.assertTrue(create.wait(2))
                self.assertEqual(old_stat(target).st_size, 0)
                with self.assertRaisesRegex(ValueError, 'encoded spool bound exceeded'):
                    mesh.spool_files(root, codec.FORMAT)
            finally:release.set();t.join(2)
        self.assertFalse(t.is_alive());self.assertEqual(errors, [])
        self.assertEqual(self.checked(root, raw), ([target], len(raw)))

    def test_new_writer_partial_temporary_never_receivable(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                root, target, raw, encoded = self.fixture()
                create, release = threading.Event(), threading.Event();errors=[]
                original = wire.write_new
                def delayed(path, data):
                    if partial:
                        fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd,'wb') as handle:
                            handle.write(data[:len(data)//2]);handle.flush();create.set()
                            if not release.wait(2):raise TimeoutError('partial gate')
                            handle.write(data[len(data)//2:]);handle.flush();os.fsync(handle.fileno())
                        mesh._sync_spool_directory(path.parent)
                    else:
                        fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                        create.set()
                        if not release.wait(2):raise TimeoutError('zero gate')
                        with os.fdopen(fd,'wb') as handle:
                            handle.write(data);handle.flush();os.fsync(handle.fileno())
                        mesh._sync_spool_directory(path.parent)
                def writer():
                    try:mesh.publish_spool(target, encoded, raw, codec.FORMAT)
                    except BaseException as e:errors.append(repr(e))
                with patch.object(wire,'write_new',side_effect=delayed):
                    t=threading.Thread(target=writer);t.start()
                    try:
                        self.assertTrue(create.wait(2));self.assertFalse(target.exists())
                        for _ in range(8):self.assertEqual(self.checked(root,raw),([],len(raw)))
                    finally:release.set();t.join(2)
                self.assertFalse(t.is_alive());self.assertEqual(errors,[])
                self.assertEqual(self.checked(root,raw),([target],len(raw)))
                self.assertEqual(list(root.iterdir()),[target])

    def test_parallel_readers_only_complete_public_files(self):
        root,target,raw,encoded=self.fixture();errors=[];stop=threading.Event();observations=[]
        def reader():
            try:
                while not stop.is_set():observations.append(self.checked(root,raw)[0])
            except BaseException as e:errors.append(repr(e))
        threads=[threading.Thread(target=reader) for _ in range(3)]
        for t in threads:t.start()
        try:mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        finally:
            stop.set()
            for t in threads:t.join(2)
        self.assertTrue(observations);self.assertEqual(errors,[])
        self.assertTrue(all(not t.is_alive() for t in threads));self.checked(root,raw)

    def test_recipient_can_consume_public_name_before_sender_directory_sync(self):
        root,target,raw,encoded=self.fixture();original=os.link
        def linked(*args,**kwargs):
            original(*args,**kwargs)
            self.assertEqual(self.checked(root,raw)[0],[target])
            target.unlink();mesh._sync_spool_directory(root)
        with patch.object(os,'link',side_effect=linked):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(list(root.iterdir()),[])

    def test_duplicates_reaffirm_without_rewrite_and_collision_preserves(self):
        root,target,raw,encoded=self.fixture();mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        before=target.stat()
        with patch.object(mesh,'sync_retained',wraps=mesh.sync_retained) as sync:
            mesh.publish_spool(target,encoded,raw,codec.FORMAT);sync.assert_called_once_with(target)
        self.assertEqual(target.stat().st_ino,before.st_ino)
        wrong=wire.canonical({'different':'x'*30000});other=codec.encode(wrong,limit=mesh.MAX_BATCH)
        with self.assertRaisesRegex(ValueError,'collision'):mesh.publish_spool(target,other,wrong,codec.FORMAT)
        self.assertEqual(target.read_bytes(),encoded);self.assertEqual(list(root.iterdir()),[target])

    def test_competing_publication_no_overwrite(self):
        for same in (True,False):
            with self.subTest(same=same):
                root,target,raw,encoded=self.fixture();original=os.link
                other=encoded if same else codec.encode(wire.canonical({'other':'x'*30000}),limit=mesh.MAX_BATCH)
                def competing(*args,**kwargs):
                    wire.write_new(target,other)
                    return original(*args,**kwargs)
                with patch.object(os,'link',side_effect=competing):
                    if same:mesh.publish_spool(target,encoded,raw,codec.FORMAT)
                    else:
                        with self.assertRaisesRegex(ValueError,'collision'):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
                self.assertEqual(target.read_bytes(),other)
                self.assertEqual(len(list(root.iterdir())),1 if same else 2)

    def test_disk_full_keeps_partial_pending_and_no_final(self):
        root,target,raw,encoded=self.fixture()
        original_write = wire.write_new
        def full(path,data):
            original_write(path,data[:20]);raise OSError(errno.ENOSPC,'disk full')
        with patch.object(wire,'write_new',side_effect=full):
            with self.assertRaises(OSError):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertFalse(target.exists());self.assertEqual(len(list(root.iterdir())),1)
        self.assertEqual(self.checked(root,raw),([],len(raw)))

    def test_every_persistence_failure_refuses_and_preserves_residue(self):
        for point in ('write','link','public-dir','unlink','cleanup-dir','existing-sync'):
            with self.subTest(point=point):
                root,target,raw,encoded=self.fixture()
                if point=='existing-sync':mesh.publish_spool(target,encoded,raw,codec.FORMAT)
                original_sync=mesh._sync_spool_directory;calls=[]
                def sync(path):
                    calls.append(path)
                    if len(calls)==(1 if point=='public-dir' else 2):raise OSError('directory sync refused')
                    original_sync(path)
                operation={'write':patch.object(wire,'write_new',side_effect=OSError('write refused')),
                           'link':patch.object(os,'link',side_effect=OSError('link refused')),
                           'public-dir':patch.object(mesh,'_sync_spool_directory',side_effect=sync),
                           'unlink':patch.object(Path,'unlink',side_effect=OSError('unlink refused')),
                           'cleanup-dir':patch.object(mesh,'_sync_spool_directory',side_effect=sync),
                           'existing-sync':patch.object(mesh,'sync_retained',side_effect=OSError('sync refused'))}[point]
                with operation:
                    with self.assertRaises(OSError):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
                paths,total=self.checked(root,raw)
                self.assertEqual(paths,[target] if point in ('public-dir','unlink','cleanup-dir','existing-sync') else [])
                self.assertEqual(len(list(root.iterdir())),{'write':0,'link':1,'public-dir':2,'unlink':2,'cleanup-dir':1,'existing-sync':1}[point])

    def test_pending_accounting_malformed_symlink_and_overbound_refuse(self):
        root,target,raw,encoded=self.fixture()
        pending=root/f'.rld-spool-pending-v1-{target.stem}-{len(raw)}-{"1"*32}.tmp'
        wire.write_new(pending,b'x')
        self.assertEqual(mesh.spool_inventory(root,codec.FORMAT),([],len(raw),1))
        with patch.object(mesh,'MAX_SPOOL_FILES',2):
            with self.assertRaisesRegex(ValueError,'capacity'):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        with patch.object(mesh,'MAX_SPOOL_BYTES',3*len(raw)-1):
            with self.assertRaisesRegex(ValueError,'capacity'):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(pending.read_bytes(),b'x');pending.unlink()
        for name in ('.write-unknown',f'.rld-spool-pending-v1-{target.stem}-0-{"1"*32}.tmp',
                     f'.rld-spool-pending-v1-{target.stem}-{mesh.MAX_BATCH+1}-{"1"*32}.tmp'):
            p=root/name;wire.write_new(p,b'x')
            with self.assertRaises(ValueError):mesh.spool_files(root,codec.FORMAT)
            self.assertEqual(p.read_bytes(),b'x');p.unlink()
        wire.write_new(pending,b'x'*(len(raw)+1))
        with self.assertRaises(ValueError):mesh.spool_files(root,codec.FORMAT)
        pending.unlink();pending.symlink_to(target)
        with self.assertRaises(ValueError):mesh.spool_files(root,codec.FORMAT)

    def test_pending_cleanup_race_still_charges_reservation(self):
        root,target,raw,encoded=self.fixture()
        pending=root/f'.rld-spool-pending-v1-{target.stem}-{len(raw)}-{"1"*32}.tmp'
        wire.write_new(pending,b'x');original=Path.lstat
        def disappeared(path):
            if path==pending:pending.unlink()
            return original(path)
        with patch.object(Path,'lstat',disappeared):self.assertEqual(mesh.spool_files(root,codec.FORMAT),([],len(raw)))

    def test_corrupt_complete_target_remains_refused(self):
        root,target,raw,encoded=self.fixture();wire.write_new(target,encoded+b'trailing')
        with self.assertRaises(ValueError):mesh.publish_spool(target,encoded,raw,codec.FORMAT)
        self.assertEqual(target.read_bytes(),encoded+b'trailing')
        target.unlink();wire.write_new(target,b'')
        with self.assertRaises(ValueError):mesh.spool_files(root,codec.FORMAT)
        self.assertEqual(target.read_bytes(),b'')
        target.unlink();wire.write_new(target,encoded)
        with patch.object(mesh,'MAX_BATCH',len(raw)-1):
            with self.assertRaises(ValueError):mesh.spool_files(root,codec.FORMAT)

    def test_owned_sigkill_boundaries_cold_reader(self):
        child = r'''
import os,sys,stat
from pathlib import Path
import interstellar_mesh as mesh,interstellar_spool_codec as codec,interstellar_transfer as wire
root=Path(sys.argv[1]);point=sys.argv[2]
raw=wire.canonical({'exact':'immutable-message'*2000});encoded=codec.encode(raw,limit=mesh.MAX_BATCH)
target=root/( __import__('hashlib').sha256(raw).hexdigest()+'.json')
def gate():
 print('BOUNDARY',flush=True);sys.stdin.buffer.read(1);raise RuntimeError('kill did not occur')
oldopen=os.open;oldsync=os.fsync;oldlink=os.link;oldunlink=Path.unlink;count=0
def opened(path,flags,*a,**k):
 fd=oldopen(path,flags,*a,**k)
 if point=='zero' and flags&os.O_WRONLY and mesh.SPOOL_PENDING.fullmatch(Path(path).name):gate()
 return fd
def synced(fd):
 global count
 oldsync(fd);count+=1
 if point=='file' and count==1:gate()
 if point=='pending-dir' and count==2:gate()
 if point=='public-dir' and count==3:gate()
def linked(*a,**k):
 oldlink(*a,**k)
 if point=='public':gate()
def unlinked(path,*a,**k):
 oldunlink(path,*a,**k)
 if point=='cleanup':gate()
os.open=opened;os.fsync=synced;os.link=linked;Path.unlink=unlinked
if point=='partial':
 def write_partial(path,data):
  fd=oldopen(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  os.write(fd,data[:len(data)//2]);gate()
 wire.write_new=write_partial
mesh.publish_spool(target,encoded,raw,codec.FORMAT)
'''
        for point in ('zero','partial','file','pending-dir','public','public-dir','cleanup'):
            with self.subTest(point=point):
                root,target,raw,encoded=self.fixture()
                process=subprocess.Popen([sys.executable,'-B','-c',child,str(root),point],stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    # A bounded reader prevents a stuck child gate from hanging tests.
                    import selectors
                    with selectors.DefaultSelector() as poll:
                        poll.register(process.stdout,selectors.EVENT_READ)
                        self.assertTrue(poll.select(3),'missing owned child boundary')
                    self.assertEqual(process.stdout.readline().strip(),'BOUNDARY')
                    process.send_signal(signal.SIGKILL);process.wait(timeout=3)
                    self.assertEqual(process.returncode,-signal.SIGKILL)
                    paths,total=self.checked(root,raw)
                    expected=point in ('public','public-dir','cleanup')
                    self.assertEqual(paths,[target] if expected else [])
                    self.assertEqual(len(list(root.iterdir())),1 if point=='cleanup' or not expected else 2)
                    self.assertEqual(total,len(raw)*(2 if expected and point!='cleanup' else 1))
                    before={p.name:p.read_bytes() for p in root.iterdir()}
                    self.checked(root,raw)
                    self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})
                    # Exact republish retains interrupted residue; no automatic cleanup.
                    mesh.publish_spool(target,encoded,raw,codec.FORMAT)
                    self.assertEqual(target.read_bytes(),encoded)
                    for name,data in before.items():self.assertEqual((root/name).read_bytes(),data)
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=3)
                    for stream in (process.stdin,process.stdout,process.stderr):stream.close()


if __name__=='__main__':unittest.main()
