"""Actual native TLS against independent Python peers, only no-value fixtures."""
import datetime
import dis
import hashlib
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import interstellar_tls as native
import interstellar_tcp as tcp
import interstellar_tcp_reference as reference
import interstellar_transfer as wire

NETWORK='a'*64
PEER='b'*64

class NativeTlsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-tls-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.provider=native.engine()
        self.before=self.provider.call({'Tls':'Usage'})
        self.addCleanup(self.assert_usage)
        self.sequence=0
    def assert_usage(self):self.assertEqual(self.provider.call({'Tls':'Usage'}),self.before)

    def test_native_generation_private_restart_and_independent_bytes(self):
        with patch.object(Ed25519PrivateKey,'generate',side_effect=AssertionError('Python private generation')),patch.object(serialization,'load_pem_private_key',side_effect=AssertionError('Python private read')):
            result=native.material(self.root,NETWORK,PEER)
            self.assertEqual(native.material(self.root,NETWORK,PEER),result)
        raw=result['path'].read_bytes();cert=x509.load_pem_x509_certificate(raw)
        key=serialization.load_pem_private_key(raw,None)
        reference.certificate_check(cert,NETWORK,PEER)
        self.assertEqual(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),cert.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        self.assertEqual(result['fingerprint'],hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
        self.assertEqual(result['expires'],cert.not_valid_after_utc.isoformat())
        self.assertEqual(result['path'].stat().st_mode & 0o777,0o600)
        self.assertEqual(raw,cert.public_bytes(serialization.Encoding.PEM)+key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

    def test_python_material_compatibility_and_retained_refusal(self):
        path,pin,expires=reference.tls_material(self.root,NETWORK,PEER)
        before=path.read_bytes()
        self.assertEqual(native.material(self.root,NETWORK,PEER),dict(path=path,fingerprint=pin,expires=expires))
        path.write_bytes(before+b'\n')
        with self.assertRaisesRegex(ValueError,'malformed'):native.material(self.root,NETWORK,PEER)
        self.assertEqual(path.read_bytes(),before+b'\n')
        path.write_bytes(before)
        link=self.root/'hardlink';link.hardlink_to(path)
        with self.assertRaisesRegex(ValueError,'hardlink'):native.material(self.root,NETWORK,PEER)
        self.assertEqual(path.read_bytes(),before)

    def native_server(self,action,client_action):
        context=native.Context(self.root,NETWORK,PEER)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        errors=[];result=[]
        def run():
            try:
                raw,_=listener.accept();deadline=time.monotonic()+3
                with context.wrap_socket(raw,deadline) as connection:
                    connection.do_handshake();result.append(action(connection,deadline))
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=run);worker.start()
        try:
            deadline=time.monotonic()+3
            with reference.client_connect(listener.getsockname(),context.material['fingerprint'],NETWORK,PEER,deadline) as client:client_action(client,deadline)
        finally:
            listener.close();worker.join(4);context.close()
        self.assertFalse(worker.is_alive());return result,errors

    def test_native_server_python_peer_exact_bidirectional_frames(self):
        value={'unicode':'星际','float':[1e-6,1e20,-0.0],'nested':{'complete':True}}
        def server(connection,deadline):
            self.assertEqual(connection.version(),'TLSv1.3')
            received=tcp.receive(connection,deadline);tcp.send(connection,received,deadline);return received
        def client(connection,deadline):
            tcp.send(connection,value,deadline);self.assertEqual(tcp.receive(connection,deadline),value)
        result,errors=self.native_server(server,client)
        self.assertEqual(result,[value]);self.assertEqual(errors,[])

    def sdk_server(self,expired=False,tls12=False):
        self.sequence+=1
        path=self.root/f'sdk-peer-{self.sequence}.pem';key=Ed25519PrivateKey.generate()
        now=datetime.datetime.now(datetime.timezone.utc)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,PEER),x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,NETWORK)])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=2))
            .not_valid_after(now+datetime.timedelta(days=-1 if expired else 1)).sign(key,None))
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM)+key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));path.chmod(0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(path)
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
        context.num_tickets=0
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        rows=[];errors=[]
        def run():
            try:
                raw,_=listener.accept();raw.settimeout(3)
                with context.wrap_socket(raw,server_side=True) as connection:
                    deadline=time.monotonic()+3;value=tcp.receive(connection,deadline);rows.append(value);tcp.send(connection,value,deadline)
            except BaseException as error:errors.append(error)
            finally:listener.close()
        worker=threading.Thread(target=run);worker.start()
        return listener.getsockname(),hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),worker,rows,errors

    def test_native_client_python_peer_and_complete_authentication_refusals(self):
        address,pin,worker,rows,errors=self.sdk_server()
        deadline=time.monotonic()+3
        with native.connect(address,pin,NETWORK,PEER,deadline) as connection:
            value={'whole':'frame','amount':0};connection.send(value,deadline);self.assertEqual(connection.receive(deadline),value)
        worker.join(4);self.assertFalse(worker.is_alive());self.assertEqual(rows,[value]);self.assertEqual(errors,[])
        for condition in ('pin','network','peer','expired','tls12'):
            with self.subTest(condition=condition):
                address,pin,worker,rows,errors=self.sdk_server(expired=condition=='expired',tls12=condition=='tls12')
                try:
                    with self.assertRaises((ValueError,OSError)):
                        native.connect(address,'c'*64 if condition=='pin' else pin,'c'*64 if condition=='network' else NETWORK,'c'*64 if condition=='peer' else PEER,time.monotonic()+3)
                finally:worker.join(4)
                self.assertFalse(worker.is_alive());self.assertEqual(rows,[])

    def test_native_server_rejects_noncanonical_duplicate_and_incomplete_frames(self):
        for raw,prefix in [(b'{}',0),(b'{}',tcp.MAX_WIRE+1),(b'{"x":1,"x":2}',None),(b'{ "x":1}',None),(b'{',2)]:
            with self.subTest(raw=raw,prefix=prefix):
                def client(connection,deadline):
                    connection.sendall(struct.pack('!I',len(raw) if prefix is None else prefix)+raw)
                    connection.shutdown(socket.SHUT_WR)
                    try:connection.recv(1)
                    except OSError:pass
                result,errors=self.native_server(lambda c,d:c.receive(d),client)
                self.assertEqual(result,[]);self.assertEqual(len(errors),1)

    def test_original_deadline_refuses_rebase_and_interrupts_waiting_handshake(self):
        context=native.Context(self.root,NETWORK,PEER)
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        client=socket.create_connection(listener.getsockname());raw,_=listener.accept();listener.close()
        connection=context.wrap_socket(raw,time.monotonic()+3);entered=threading.Event();errors=[]
        def run():
            entered.set()
            try:connection.do_handshake()
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=run);worker.start();self.assertTrue(entered.wait(1))
        start=time.monotonic();connection.shutdown(socket.SHUT_RDWR);connection.close();worker.join(1)
        self.assertFalse(worker.is_alive());self.assertLess(time.monotonic()-start,1)
        self.assertEqual(len(errors),1);client.close();context.close()
        def server(connection,deadline):
            with self.assertRaisesRegex(ValueError,'cannot be rebased'):connection.receive(deadline+1)
            time.sleep(.06)
            with self.assertRaises(TimeoutError):connection.receive(time.monotonic()-.01)
            return True
        result,errors=self.native_server(server,lambda c,d:None)
        self.assertEqual(result,[True]);self.assertEqual(errors,[])

    def test_concurrent_close_retains_local_raw_socket_before_clearing_shared_field(self):
        # Deterministic exact bridge interleaving, with no native authority.
        class Provider:
            def call(self,request):return None
        class Raw:
            def __init__(self):self.closes=0
            def close(self):self.closes+=1
        raw=Raw();connection=native.Connection(Provider(),1,raw)
        paused=threading.Event();resume=threading.Event();errors=[]
        ordinary=[]
        for instruction in dis.get_instructions(native.Connection.close):
            if instruction.opname.startswith('RETURN'):break
            ordinary.append(instruction)
        # Python duplicates finally for exception handling. Pause the last
        # shared-field read on the normal path, not its unreachable duplicate.
        target=[i.offset for i in ordinary if i.opname=='LOAD_ATTR' and i.argval=='raw'][-1]
        def trace(frame,event,arg):
            if frame.f_code is native.Connection.close.__code__:
                frame.f_trace_opcodes=True
                if event=='opcode' and frame.f_lasti==target:
                    paused.set()
                    if not resume.wait(2):raise AssertionError('model close resume timeout')
            return trace
        def run():
            sys.settrace(trace)
            try:connection.close()
            except BaseException as error:errors.append(error)
            finally:sys.settrace(None)
        worker=threading.Thread(target=run);worker.start()
        try:
            self.assertTrue(paused.wait(2));connection.close()
        finally:resume.set();worker.join(2)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[]);self.assertEqual(raw.closes,1)

if __name__=='__main__':unittest.main()
