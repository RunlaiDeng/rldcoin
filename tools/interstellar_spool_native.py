"""Bound native spool IO; ordinary full authentication remains at the caller."""
import ctypes
import hashlib
from pathlib import Path
from interstellar_crypto import backend, Buffer

FORMAT='RLD-NATIVE-CONTACT-SPOOL-V1'
CODEC='RLD-CONTACT-SPOOL-ZLIB-V1'
MAX_BATCH=20*1024*1024
MAX_FILES=256
MAX_BYTES=64*1024*1024
MAX_CONTROL=8192

def limits():
    import interstellar_mesh as mesh
    result=dict(batch=mesh.MAX_BATCH,files=mesh.MAX_SPOOL_FILES,bytes=mesh.MAX_SPOOL_BYTES)
    if any(type(v) is not int or not 0<=v<=bound for v,bound in
           ((result['batch'],MAX_BATCH),(result['files'],MAX_FILES),(result['bytes'],MAX_BYTES))) or result['batch']==0:
        raise ValueError('native spool limits differ')
    return result

def _invoke(request,encoded=b'',data=b''):
    if any(type(raw) is not bytes or len(raw)>MAX_BATCH for raw in (encoded,data)):
        raise ValueError('native spool payload capacity')
    engine=backend();operation=engine.library.rld_contact_spool
    pointer=ctypes.POINTER(ctypes.c_ubyte)
    operation.argtypes=[pointer,ctypes.c_size_t,pointer,ctypes.c_size_t,pointer,ctypes.c_size_t]
    operation.restype=Buffer
    a=(ctypes.c_ubyte*len(encoded)).from_buffer_copy(encoded)
    b=(ctypes.c_ubyte*len(data)).from_buffer_copy(data)
    def call(request,a=a,b=b):
        try:return engine.invoke(operation,request,a,len(a),b,len(b))
        except ValueError as error:
            fields=str(error).split(':',2)
            if len(fields)==3 and fields[0]=='CONTACT_STORAGE_IO' and fields[1].isdigit():
                raise OSError(int(fields[1]),fields[2]) from error
            raise
    if not getattr(engine,'_contact_spool_profile',False):
        empty=(ctypes.c_ubyte*0)()
        info=call('Info',empty,empty)
        if info!=dict(format=FORMAT,codec=CODEC,max_batch=MAX_BATCH,max_files=MAX_FILES,
                      max_bytes=MAX_BYTES,max_control=MAX_CONTROL,ledger_authority=False,custody_acknowledgment=False):
            raise ValueError('native spool profile differs')
        engine._contact_spool_profile=True
    return call(request)

def spool_inventory(root,adapter=None):
    root=Path(root).absolute()
    value=_invoke({'Inventory':dict(path=str(root),adapter=adapter,limits=limits())})
    if (type(value) is not dict or set(value)!={'format','files','total','entries','ledger_authority','custody_acknowledgment'}
        or value['format']!=FORMAT or value['ledger_authority'] is not False or value['custody_acknowledgment'] is not False
        or type(value['files']) is not list or any(type(p) is not str or '/' in p or '\\' in p for p in value['files'])
        or type(value['total']) is not int or type(value['entries']) is not int):
        raise ValueError('native spool inventory response differs')
    return [root/p for p in value['files']],value['total'],value['entries']

def publish_spool(target,encoded,data,adapter=None):
    value=_invoke({'Publish':dict(path=str(Path(target).absolute()),adapter=adapter,limits=limits(),
        encoded_size=len(encoded),encoded_sha256=hashlib.sha256(encoded).hexdigest(),
        data_size=len(data),data_sha256=hashlib.sha256(data).hexdigest())},encoded,data)
    if value!=dict(format=FORMAT,encoded_size=len(encoded),encoded_sha256=hashlib.sha256(encoded).hexdigest(),
                   data_size=len(data),data_sha256=hashlib.sha256(data).hexdigest(),ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native spool publication response differs')
