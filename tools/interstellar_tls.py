"""Native pinned TLS handle bridge. Frames grant no ledger or custody rights."""
from pathlib import Path
import threading
import interstellar_crypto as crypto
import ctypes

FORMAT='RLD-NATIVE-CONTACT-TLS-V1'
_verified=None
_guard=threading.Lock()
_callback_custody={}
Callback=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_uint32,ctypes.c_uint64,ctypes.c_double)
def engine():
    global _verified
    current=crypto.backend()
    with _guard:
        if _verified is not current:
            expected=dict(format=FORMAT,max_wire=20*1024*1024+4096,max_contexts=64,
                max_connections=192,attempt_seconds=3,certificate_days=90,tls='TLSv1.3')
            if current.call({'Tls':'Info'})!=expected:raise ValueError('native contact TLS profile differs')
            _verified=current
    return current

def call(provider,operation,**fields):
    try:return provider.call({'Tls':{operation:fields}})
    except ValueError as error:
        if str(error).startswith('TLS_TIMEOUT:'):raise TimeoutError(str(error)) from error
        if str(error).startswith('TLS_IO:'):raise OSError(str(error)) from error
        raise

def checked_material(value,root):
    if (type(value) is not dict or set(value)!={'path','fingerprint','expires'}
            or value['path']!=str(Path(root)/'tcp-tls.private.pem')
            or type(value['fingerprint']) is not str or len(value['fingerprint'])!=64
            or any(c not in '0123456789abcdef' for c in value['fingerprint'])
            or type(value['expires']) is not str):raise ValueError('native TLS material response differs')
    return dict(value,path=Path(value['path']))

def material(root,network,peer):
    return checked_material(call(engine(),'Material',root=str(root),network=network,peer=peer),root)

class Connection:
    def __init__(self,provider,handle,raw=None,deadline=None):
        if type(handle) is not int or handle<=0:raise ValueError('native TLS handle differs')
        self.provider=provider;self.handle=handle;self.raw=raw;self.deadline=deadline
    def __enter__(self):return self
    def __exit__(self,*unused):self.close()
    def do_handshake(self):call(self.provider,'Handshake',handle=self.handle)
    def version(self):return call(self.provider,'Version',handle=self.handle)
    def cipher(self):return call(self.provider,'Cipher',handle=self.handle)
    def send(self,value,deadline):call(self.provider,'Send',handle=self.handle,value=value,deadline=deadline)
    def receive(self,deadline):return call(self.provider,'Receive',handle=self.handle,deadline=deadline)
    def shutdown(self,how):
        if how!=2:raise ValueError('native TLS shutdown requires both directions')
        call(self.provider,'Shutdown',handle=self.handle)
    def close(self):
        # Native shutdown does not acquire the per-connection I/O mutex. A worker
        # retains its Arc until it exits; the service joins it before custody release.
        try:call(self.provider,'Close',handle=self.handle)
        finally:
            raw=self.raw;self.raw=None
            if raw is not None:raw.close()

class Context:
    def __init__(self,root,network,peer):
        self.provider=engine()
        value=call(self.provider,'Context',root=str(root),network=network,peer=peer)
        if type(value) is not dict or set(value)!={'handle','material'}:raise ValueError('native TLS context response differs')
        if type(value['handle']) is not int or value['handle']<=0:raise ValueError('native TLS context handle differs')
        self.handle=value['handle'];self.material=checked_material(value['material'],root)
    def wrap_socket(self,raw,deadline):
        handle=call(self.provider,'Accept',context=self.handle,fd=raw.fileno(),deadline=deadline)
        return Connection(self.provider,handle,raw,deadline)
    def close(self):call(self.provider,'ContextClose',handle=self.handle)

def connect(address,fingerprint,network,peer,deadline):
    provider=engine()
    return Connection(provider,call(provider,'Connect',host=address[0],port=address[1],
        fingerprint=fingerprint,network=network,peer=peer,deadline=deadline),deadline=deadline)

class Listener:
    """Rust owns accept and connection tasks; callback custody lasts through join."""
    def __init__(self,context,address,callback,start=True):
        self.provider=context.provider;self.closed=False;self.failed=False
        expected=dict(format='RLD-NATIVE-CONTACT-LIFECYCLE-V1',max_listeners=64,workers=2,
            backlog=2,local_handoff_seconds=.2,attempt_seconds=3,callback_events=[0,1,2,3,4])
        if self.provider.call({'Tls':'ListenerInfo'})!=expected:raise ValueError('native listener profile differs')
        prepared=call(self.provider,'ListenerPrepare',context=context.handle,host=address[0],port=address[1])
        if (type(prepared) is not dict or set(prepared)!={'handle','host','port','format'}
                or prepared['format']!=expected['format'] or type(prepared['handle']) is not int
                or prepared['handle']<=0 or prepared['host']!=address[0]
                or type(prepared['port']) is not int or not 0<prepared['port']<65536):
            raise ValueError('native listener prepare response differs')
        self.handle=prepared['handle'];self.address=(prepared['host'],prepared['port'])
        def hook(event,handle,deadline):
            try:return callback(event,handle,deadline)
            except BaseException:self.failed=True;return -1
        self.callback=Callback(hook)
        # Retain executable callback custody even if a start/close response is
        # malformed or lost. Only proven joined close releases it.
        self.token=object();_callback_custody[self.token]=self
        if start:self.start()
    def start(self):
        if self.closed:raise ValueError('native listener is closed')
        operation=self.provider.library.rld_contact_listener_start
        operation.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t,Callback]
        operation.restype=crypto.Buffer
        try:
            result=self.provider.invoke(operation,dict(handle=self.handle),self.callback)
            if result!=dict(started=True,handle=self.handle,authority=False):raise ValueError('native listener start response differs')
        except BaseException:
            self.close();raise
    def status(self):
        if self.closed:return dict(running=False,failed=self.failed,active=0,authority=False)
        value=call(self.provider,'ListenerStatus',handle=self.handle)
        if (type(value) is not dict or set(value)!={'running','failed','active','accepted','completed','refused','authority'}
                or type(value['running']) is not bool or type(value['failed']) is not bool
                or value['authority'] is not False or type(value['active']) is not int or not 0<=value['active']<=2
                or any(type(value[k]) is not int or value[k]<0 for k in ('accepted','completed','refused'))):
            raise ValueError('native listener status response differs')
        return value
    def is_alive(self):return self.status()['running']
    def close(self):
        if self.closed:return
        value=call(self.provider,'ListenerClose',handle=self.handle)
        if (type(value) is not dict or set(value)!={'closed','failed','authority'}
                or value['closed'] is not True or type(value['failed']) is not bool or value['authority'] is not False):
            raise ValueError('native listener joined-close response differs')
        self.closed=True;self.failed=self.failed or value['failed']
        _callback_custody.pop(self.token,None);self.callback=None
        if self.failed:raise ValueError('native listener callback/task failed; retain evidence')
