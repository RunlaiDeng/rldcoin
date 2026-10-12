"""Actual native opaque file/queue IO and retained interruption boundaries."""
import errno
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import interstellar_transfer as wire
import interstellar_file_native as native
import interstellar_file_reference as reference
from interstellar_crypto import backend

SOURCE='1'*64
DESTINATION='2'*64
EXPORT='3'*64
class NativeFilesTests(unittest.TestCase):
    def root(self):
        tmp=tempfile.TemporaryDirectory(prefix='rld-native-files-');self.addCleanup(tmp.cleanup);return Path(tmp.name)
    def frame(self,payload=b'original payload'):
        return wire.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,payload)
    def test_exact_file_bytes_and_exclusive_duplicate_semantics_match_oracle(self):
        root=self.root()
        for raw in (b'',bytes(range(256))*128,b'exact arbitrary opaque bytes'):
            index=len(list(root.iterdir()));a=root/f'native-{index}'/ 'file';b=root/f'python-{index}'/'file'
            native.write_new(a,raw);reference.write_new(b,raw)
            self.assertEqual(native.read_file(a,len(raw)),reference.read_file(b,len(raw)))
            with self.assertRaises(FileExistsError):native.write_new(a,raw)
            before=a.stat().st_ino;native.write_same_or_new(a,raw);self.assertEqual(a.stat().st_ino,before)
            with self.assertRaises(ValueError):native.write_same_or_new(a,raw+b'different')
            self.assertEqual(a.read_bytes(),raw)
            if raw:
                with patch.object(wire,'MAX_FRAME',len(raw)-1),self.assertRaises(ValueError):native.write_same_or_new(a,raw)
                self.assertEqual(a.read_bytes(),raw)
    def test_complete_file_ceiling_and_smaller_read_refusal(self):
        root=self.root();raw=b'x'*native.MAX_FILE;path=root/'full'
        native.write_new(path,raw);self.assertEqual(native.read_file(path,native.MAX_FILE),raw)
        with self.assertRaises(ValueError):native.read_file(path,len(raw)-1)
        with self.assertRaises(ValueError):native.read_file(path,native.MAX_FILE+1)
        self.assertEqual(path.stat().st_size,len(raw))
    def test_actual_default_file_io_uses_no_python_syscalls(self):
        root=self.root();native._profile();path=root/'new'/'target'
        with (patch.object(os,'open',side_effect=AssertionError('Python open')),
              patch.object(os,'fsync',side_effect=AssertionError('Python sync')),
              patch.object(Path,'mkdir',side_effect=AssertionError('Python mkdir')),
              patch.object(Path,'open',side_effect=AssertionError('Python read/write'))):
            wire.ensure_dir(path.parent);wire.write_new(path,b'exact');self.assertEqual(wire.read_file(path,5),b'exact')
    def test_queue_receive_carry_full_bytes_and_caps_match_python(self):
        root=self.root();data=self.frame();identifier=wire.decode_json(data)['message_id']
        for module,label in ((native,'native'),(reference,'python')):
            directory=root/label
            self.assertEqual(module.queue_receive(directory,data,SOURCE,DESTINATION),(identifier,True))
            self.assertEqual(module.queue_receive(directory,data,SOURCE,DESTINATION),(identifier,False))
            result=module.queue_carry(directory,identifier,root/(label+'-out'),SOURCE,DESTINATION)
            self.assertEqual(result,wire.decode_json(data));self.assertEqual((root/(label+'-out')).read_bytes(),data)
        directory=root/'native';other=self.frame(b'other')
        for name,value in (('MAX_QUEUE_FILES',1),('MAX_QUEUE_BYTES',len(data))):
            with patch.object(wire,name,value),self.assertRaisesRegex(ValueError,'capacity'):
                native.queue_receive(directory,other,SOURCE,DESTINATION)
            with patch.object(wire,name,0):self.assertEqual(native.queue_receive(directory,data,SOURCE,DESTINATION),(identifier,False))
        self.assertEqual((directory/(identifier+'.json')).read_bytes(),data)
    def test_symlinks_unknown_corruption_route_and_filename_refuse_unchanged(self):
        root=self.root();data=self.frame();identifier=wire.decode_json(data)['message_id'];directory=root/'queue'
        native.queue_receive(directory,data,SOURCE,DESTINATION)
        target=directory/(identifier+'.json');target.write_bytes(data[:10])
        with self.assertRaisesRegex(ValueError,'collision'):native.queue_receive(directory,data,SOURCE,DESTINATION)
        with self.assertRaises(ValueError):native.queue_carry(directory,identifier,root/'out',SOURCE,DESTINATION)
        self.assertFalse((root/'out').exists());self.assertEqual(target.read_bytes(),data[:10])
        unknown=directory/'unknown';unknown.write_bytes(b'retained')
        with self.assertRaisesRegex(ValueError,'unexpected queue'):native.queue_receive(directory,data,SOURCE,DESTINATION)
        self.assertEqual(unknown.read_bytes(),b'retained')
        alias=root/'alias';alias.symlink_to(directory)
        with self.assertRaises(ValueError):native.queue_receive(alias,data,SOURCE,DESTINATION)
        with self.assertRaises(OSError) as refused:native.read_file(alias/target.name,wire.MAX_FRAME)
        self.assertIn(refused.exception.errno,(errno.ELOOP,errno.ENOTDIR))
        with self.assertRaisesRegex(ValueError,'wrong source'):native.queue_receive(root/'wrong',data,DESTINATION,SOURCE)
        self.assertFalse((root/'wrong').exists())
    def test_lost_native_result_preserves_installed_bytes_and_rechecks_without_replacement(self):
        root=self.root();data=self.frame();engine=backend();invoke=engine.invoke
        def lose(operation,request,*args):
            value=invoke(operation,request,*args)
            if type(request) is dict and 'Receive' in request:raise ValueError('lost native queue result')
            return value
        with patch.object(engine,'invoke',side_effect=lose),self.assertRaises(ValueError):native.queue_receive(root/'queue',data,SOURCE,DESTINATION)
        path=root/'queue'/(wire.decode_json(data)['message_id']+'.json');inode=path.stat().st_ino
        self.assertEqual(path.read_bytes(),data)
        self.assertEqual(native.queue_receive(root/'queue',data,SOURCE,DESTINATION)[1],False)
        self.assertEqual(path.stat().st_ino,inode)
    def test_real_native_sigkill_boundaries_preserve_partial_and_complete_files(self):
        binary=os.environ.get('RLD_EVIDENCE_TEST_BINARY');self.assertTrue(binary,'requires current bound native test executable')
        raw=b'complete original opaque bytes'
        for point in ('zero','partial','written','file','directory'):
            root=self.root();path=root/'target'
            result=subprocess.run([binary,'--exact','evidence_files::tests::native_crash_child','--nocapture'],
                env=dict(os.environ,RLD_EVIDENCE_CRASH_TARGET=str(path),RLD_EVIDENCE_CRASH_POINT=point),capture_output=True,timeout=10)
            self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr.decode())
            expected=b'' if point=='zero' else raw[:len(raw)//2] if point=='partial' else raw
            self.assertEqual(native.read_file(path,len(raw)),expected)
            with self.assertRaises(FileExistsError):native.write_new(path,raw)
            if expected==raw:native.write_same_or_new(path,raw)
            else:
                with self.assertRaises(ValueError):native.write_same_or_new(path,raw)
            self.assertEqual(path.read_bytes(),expected)
    def test_payload_binding_and_response_flags_are_strict(self):
        root=self.root();path=root/'target'
        with self.assertRaisesRegex(ValueError,'payload binding'):
            native._invoke({'Write':dict(path=str(path),same=False,retained_limit=wire.MAX_FRAME,size_bytes=1,sha256='0'*64)},b'x')
        self.assertFalse(path.exists())
        native.write_new(path,b'x');invoke=native._invoke
        def forged(request,raw=b''):
            value,data=invoke(request,raw);value=dict(value);value['ledger_authority']=0;return value,data
        with patch.object(native,'_invoke',side_effect=forged),self.assertRaises(ValueError):native.read_file(path,1)

if __name__=='__main__':unittest.main()
