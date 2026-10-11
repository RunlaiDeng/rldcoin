"""Native pinned TLS handle bridge. Frames grant no ledger or custody rights."""
from pathlib import Path
import threading
import interstellar_crypto as crypto

FORMAT='RLD-NATIVE-CONTACT-TLS-V1'
_verified=None
_guard=threading.Lock()
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
