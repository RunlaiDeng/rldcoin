"""Bound native durable byte operations; complete authentication remains at caller."""
import ctypes
import hashlib
from pathlib import Path
from interstellar_crypto import backend, Buffer

FORMAT='RLD-NATIVE-CONTACT-STORAGE-V1'
MAX_FILE=64*1024*1024
MAX_PATHS=2*(256+4)
MAX_CONTROL=3*1024*1024

def _invoke(request,raw=b''):
    from interstellar_mesh import MAX_MESSAGES, MAX_PACKET_BATCH, MAX_STATE
    state_write=(type(request) is dict and set(request)=={'AtomicWrite'}
        and type(MAX_STATE) is int and 0<=MAX_STATE<=MAX_FILE
        and request['AtomicWrite']['limit']==MAX_STATE)
    if not state_write and (MAX_PATHS!=2*(MAX_MESSAGES+MAX_PACKET_BATCH) or MAX_FILE!=MAX_STATE):
        raise ValueError('native contact storage runtime bounds differ')
    engine=backend()
    operation=engine.library.rld_contact_storage
    operation.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t]
    operation.restype=Buffer
    if type(raw) is not bytes or len(raw)>MAX_FILE:raise ValueError('native contact archive capacity')
    payload=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
    def call(value,data=payload):
        try:return engine.invoke(operation,value,data,len(data))
        except ValueError as error:
            fields=str(error).split(':',2)
            if len(fields)==3 and fields[0]=='CONTACT_STORAGE_IO' and fields[1].isdigit():
                raise OSError(int(fields[1]),fields[2]) from error
            raise
    if not getattr(engine,'_contact_storage_profile',False):
        info=call('Info',(ctypes.c_ubyte*0)())
        if info!=dict(format=FORMAT,max_file=MAX_FILE,max_paths=MAX_PATHS,max_control=MAX_CONTROL,atomic_write=True,
                      ledger_authority=False,custody_acknowledgment=False):
            raise ValueError('native contact storage profile differs')
        engine._contact_storage_profile=True
    return call(request)

def archive_write(path,raw):
    if type(raw) is not bytes or len(raw)>MAX_FILE:raise ValueError('native contact archive capacity')
    digest=hashlib.sha256(raw).hexdigest()
    value=_invoke({'ArchiveWrite':dict(path=str(Path(path).absolute()),size_bytes=len(raw),sha256=digest)},raw)
    if value!=dict(format=FORMAT,size_bytes=len(raw),sha256=digest,
                   ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native contact archive response differs')

def atomic_write(path,raw):
    from interstellar_mesh import MAX_STATE
    if type(MAX_STATE) is not int or not 0<=MAX_STATE<=MAX_FILE or type(raw) is not bytes or len(raw)>MAX_STATE:
        raise ValueError('native contact state capacity')
    digest=hashlib.sha256(raw).hexdigest()
    value=_invoke({'AtomicWrite':dict(path=str(Path(path).absolute()),size_bytes=len(raw),sha256=digest,limit=MAX_STATE)},raw)
    if value!=dict(format=FORMAT,size_bytes=len(raw),sha256=digest,
                   ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native contact state response differs')

def sync_retained_many(paths):
    paths=list(dict.fromkeys(Path(path).absolute() for path in paths))
    if len(paths)>MAX_PATHS:raise ValueError('retained custody sync capacity exceeded')
    value=_invoke({'SyncMany':dict(paths=[str(path) for path in paths])})
    if value!=dict(format=FORMAT,files_synced=len(paths),directories_synced=len({path.parent for path in paths}),
                   ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native retained sync response differs')

def sync_retained(path):sync_retained_many([path])
