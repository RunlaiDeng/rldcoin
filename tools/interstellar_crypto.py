"""In-process native transport crypto, with exact binary/library source binding."""
import ctypes
import hashlib
from pathlib import Path
import sys
import threading
import interstellar_transfer as wire

FORMAT='RLD-NATIVE-CONTACT-CRYPTO-V1'
MAX_ABI=64*1024*1024+16384
class Buffer(ctypes.Structure):
    _fields_=[('data',ctypes.POINTER(ctypes.c_ubyte)),('len',ctypes.c_size_t)]

def sibling(binary):
    suffix='.dylib' if sys.platform=='darwin' else '.so'
    return Path(binary).resolve().parent/('librld_regional_ledger_candidate'+suffix)

class Backend:
    def __init__(self,path):
        self.path=Path(path).resolve(strict=True)
        self.library=ctypes.CDLL(str(self.path))
        self.library.rld_contact_crypto.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t]
        self.library.rld_contact_crypto.restype=Buffer
        self.library.rld_contact_crypto_free.argtypes=[Buffer];self.library.rld_contact_crypto_free.restype=None
        self.implementation=None
        info=self.call('Info')
        import interstellar_mesh as mesh
        expected=dict(mesh=mesh.VERSION,active_storage=mesh.ACTIVE_STORAGE,archive_storage=mesh.ARCHIVE_STORAGE,
            receipt_scheduler=mesh.RECEIPT_SCHEDULER,transit_scheduler=mesh.TRANSIT_SCHEDULER,max_abi=MAX_ABI)
        if info!=expected:raise ValueError('native contact profile/library differs')

    def call(self,request):
        return self.invoke(self.library.rld_contact_crypto,request)

    def invoke(self,operation,request,*arguments):
        return self.invoke_raw(operation,wire.canonical(request),*arguments)

    def invoke_raw(self,operation,raw,*arguments):
        if type(raw) is not bytes or not 0<len(raw)<=MAX_ABI:raise ValueError('native contact ABI byte bound')
        memory=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
        result=operation(memory,len(raw),*arguments)
        try:
            if not result.data or not 0<result.len<=MAX_ABI:raise ValueError('native contact output byte bound')
            output=ctypes.string_at(result.data,result.len)
        finally:self.library.rld_contact_crypto_free(result)
        value=wire.decode_json(output)
        fields={'format','implementation','request_sha256','success','value','error',
            'ledger_authority','durable_custody_qualified','independent_security_qualified'}
        if (type(value) is not dict or set(value)!=fields or value['format']!=FORMAT
                or value['request_sha256']!=hashlib.sha256(raw).hexdigest()
                or type(value['implementation']) is not str or len(value['implementation'])!=64
                or any(c not in '0123456789abcdef' for c in value['implementation'])
                or self.implementation is not None and value['implementation']!=self.implementation
                or type(value['success']) is not bool or value['ledger_authority'] is not False
                or value['durable_custody_qualified'] is not False or value['independent_security_qualified'] is not False):
            raise ValueError('native contact receipt binding differs')
        self.implementation=value['implementation']
        if not value['success']:
            if value['value'] is not None or type(value['error']) is not str:raise ValueError('native contact refusal shape differs')
            raise ValueError(value['error'])
        if value['error'] is not None:raise ValueError('native contact success shape differs')
        return value['value']

_backend=None
_guard=threading.Lock()
def backend():
    global _backend
    with _guard:
        if _backend is None:
            binary=Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'
            _backend=Backend(sibling(binary))
        return _backend

def bind_binary(binary,expected):
    global _backend
    path=sibling(binary)
    with _guard:
        candidate=_backend if _backend is not None and _backend.path==path else Backend(path)
        if expected!=dict(format=FORMAT,implementation=candidate.implementation):
            raise ValueError('native contact binary/library implementation differs')
        _backend=candidate

def validation_domain():
    engine=backend()
    return (FORMAT,engine.implementation,str(engine.path),id(engine.library))

class NativeSigner:
    def __init__(self,path,identity,engine=None):
        self.path=Path(path);self.identity=dict(identity);self.engine=backend() if engine is None else engine
    def public_key(self):
        # Public representation only; verification always uses the native backend.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.identity['public_key']))
    def sign_object(self,kind,body):
        return self.engine.call({'Sign':dict(identity=str(self.path),network=self.identity['network'],
            public_key=self.identity['public_key'],kind=kind,body=body)})

def inspect(path,network):return backend().call({'Inspect':dict(identity=str(path),network=network)})
def initialize(root,network,region,label):
    return backend().call({'Initialize':dict(root=str(root),network=network,region=region,label=label)})
def verify(value,kind,network):return backend().call({'Verify':dict(network=network,kind=kind,signed=value)})
