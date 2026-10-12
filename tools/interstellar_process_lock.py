"""Native process-local lock handles; no ledger, signing or custody rights."""
import ctypes
from pathlib import Path
import secrets
from interstellar_crypto import backend,Buffer
import interstellar_transfer as wire

FORMAT='RLD-NATIVE-CONTACT-PROCESS-LOCK-V1'
MAX_CONTROL=8192
MAX_HANDLES=256
ROLES=('Mesh','Startup','Service')

def _invoke(request,engine=None):
    if len(wire.canonical(request))>MAX_CONTROL:raise ValueError('native process lock control bound')
    engine=engine or backend();operation=engine.library.rld_contact_process_lock
    operation.argtypes=[ctypes.POINTER(ctypes.c_ubyte),ctypes.c_size_t];operation.restype=Buffer
    try:return engine.invoke(operation,request)
    except ValueError as error:
        fields=str(error).split(':',2)
        if len(fields)==3 and fields[0]=='CONTACT_STORAGE_IO' and fields[1].isdigit():
            raise OSError(int(fields[1]),fields[2]) from error
        raise

def _profile(engine):
    if not getattr(engine,'_contact_process_lock_profile',False):
        value=_invoke('Info',engine)
        if value!=dict(format=FORMAT,max_handles=MAX_HANDLES,max_control=MAX_CONTROL,roles=list(ROLES),
                       ledger_authority=False,custody_acknowledgment=False):raise ValueError('native process lock profile differs')
        engine._contact_process_lock_profile=True

def safe_directory(path):
    path=Path(path)
    if not path.is_absolute():raise ValueError('directory must be absolute')
    engine=backend();_profile(engine)
    value=_invoke({'Directory':dict(path=str(path))},engine)
    if value!=dict(format=FORMAT,path=str(path),ensured=True,ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native directory receipt differs')
    return path

class Lock:
    @classmethod
    def acquire(cls,path,role,nonblocking=False):
        if role not in ROLES or type(nonblocking) is not bool:raise ValueError('native process lock selection differs')
        result=cls();result.path=str(Path(path));result.role=role;result.token=secrets.token_hex(16)
        result.engine=backend();result.closed=False;_profile(result.engine)
        try:
            value=_invoke({'Acquire':dict(token=result.token,path=result.path,role=role,nonblocking=nonblocking)},result.engine)
            if value!=dict(format=FORMAT,token=result.token,path=result.path,role=role,nonblocking=nonblocking,
                           acquired=True,ledger_authority=False,custody_acknowledgment=False):
                raise ValueError('native process lock acquisition receipt differs')
        except BaseException as error:
            # A duplicate token refusal never owns the original reservation.
            if str(error)!='native process lock token already exists':
                try:result.close()
                except BaseException as cleanup:raise ValueError(f'{error}; native lock cleanup: {cleanup}') from error
            raise
        return result
    def close(self):
        if self.closed:return
        value=_invoke({'Release':dict(token=self.token,path=self.path,role=self.role)},self.engine)
        if value!=dict(format=FORMAT,token=self.token,path=self.path,role=self.role,released=True,
                       ledger_authority=False,custody_acknowledgment=False):raise ValueError('native process lock release receipt differs')
        self.closed=True
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def usage():
    engine=backend();_profile(engine);value=_invoke('Usage',engine)
    if (type(value) is not dict or set(value)!={'format','handles','ledger_authority','custody_acknowledgment'}
        or value['format']!=FORMAT or type(value['handles']) is not int or not 0<=value['handles']<=MAX_HANDLES
        or value['ledger_authority'] is not False or value['custody_acknowledgment'] is not False):raise ValueError('native lock usage receipt differs')
    return value['handles']
