"""Bound native file/queue IO; results grant no ledger or custody authority."""
import ctypes
import hashlib
from pathlib import Path
from interstellar_crypto import backend
from interstellar_spool_codec_native import CodecOutput

FORMAT='RLD-NATIVE-EVIDENCE-FILES-V1'
MAX_FILE=64*1024*1024
MAX_FILES=4096
MAX_BYTES=256*1024*1024
MAX_CONTROL=8192

def _invoke(request,raw=b''):
    if type(raw) is not bytes or len(raw)>MAX_FILE:raise ValueError('native evidence payload bound')
    engine=backend();operation=engine.library.rld_evidence_files;pointer=ctypes.POINTER(ctypes.c_ubyte)
    operation.argtypes=[pointer,ctypes.c_size_t,pointer,ctypes.c_size_t];operation.restype=CodecOutput
    memory=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw);data=None
    def call(control,size):
        nonlocal data
        result=operation(control,size,memory,len(memory))
        try:
            try:
                if result.payload.len>MAX_FILE or (result.payload.len and not result.payload.data):raise ValueError('native evidence result bound')
                data=ctypes.string_at(result.payload.data,result.payload.len) if result.payload.len else b''
            finally:engine.library.rld_contact_crypto_free(result.payload)
        except BaseException:
            engine.library.rld_contact_crypto_free(result.receipt);raise
        return result.receipt
    try:value=engine.invoke(call,request)
    except ValueError as error:
        fields=str(error).split(':',2)
        if len(fields)==3 and fields[0]=='CONTACT_STORAGE_IO' and fields[1].isdigit():raise OSError(int(fields[1]),fields[2]) from error
        raise
    return value,data

def _profile():
    engine=backend()
    if not getattr(engine,'_evidence_files_profile',False):
        value,data=_invoke('Info')
        if data or value!=dict(format=FORMAT,max_file=MAX_FILE,max_files=MAX_FILES,max_bytes=MAX_BYTES,max_control=MAX_CONTROL,
                              max_frame=4*1024*1024+4096,max_payload=3*1024*1024,ledger_authority=False,custody_acknowledgment=False):
            raise ValueError('native evidence profile differs')
        engine._evidence_files_profile=True

def _path(path):return str(Path(path).absolute())
def _bound(raw):
    if type(raw) is not bytes:raise ValueError('native evidence bytes required')
    return dict(size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def _checked(value,data):
    if (type(value) is not dict or type(value.get('size_bytes')) is not int
        or value.get('ledger_authority') is not False or value.get('custody_acknowledgment') is not False
        or value!=dict(format=FORMAT,**_bound(data),ledger_authority=False,custody_acknowledgment=False)):
        raise ValueError('native evidence byte receipt differs')

def read_file(path,limit):
    if type(limit) is not int or not 0<=limit<=MAX_FILE:raise ValueError('native evidence read bound')
    _profile();value,data=_invoke({'Read':dict(path=_path(path),limit=limit)});_checked(value,data)
    if len(data)>limit:raise ValueError('native evidence read bound')
    return data

def ensure_dir(path):
    _profile();value,data=_invoke({'Ensure':dict(path=_path(path))})
    if data or value!=dict(format=FORMAT,ensured=True,ledger_authority=False,custody_acknowledgment=False):
        raise ValueError('native evidence directory receipt differs')

def _write(path,data,same):
    import interstellar_transfer as wire
    limit=wire.MAX_FRAME
    if type(limit) is not int or not 0<=limit<=4*1024*1024+4096:raise ValueError('native evidence retained bound')
    _profile();value,returned=_invoke({'Write':dict(path=_path(path),same=same,retained_limit=limit,**_bound(data))},data)
    _checked(value,data)
    if returned:raise ValueError('native evidence write payload differs')
def write_new(path,data):_write(path,data,False)
def write_same_or_new(path,data):_write(path,data,True)

def _limits():
    import interstellar_transfer as wire
    limits=dict(files=wire.MAX_QUEUE_FILES,bytes=wire.MAX_QUEUE_BYTES,frame=wire.MAX_FRAME,payload=wire.MAX_PAYLOAD)
    bounds=dict(files=MAX_FILES,bytes=MAX_BYTES,frame=4*1024*1024+4096,payload=3*1024*1024)
    if any(type(v) is not int or not 0<=v<=bounds[k] for k,v in limits.items()):raise ValueError('native evidence queue limits differ')
    return limits

def queue_receive(root,data,source,destination):
    _profile();value,returned=_invoke({'Receive':dict(path=_path(root),source=source,destination=destination,
                                 limits=_limits(),**_bound(data))},data)
    import interstellar_transfer as wire
    if (returned or type(value) is not dict or set(value)!={'format','message_id','new','size_bytes','sha256','ledger_authority','custody_acknowledgment'}
        or type(value['new']) is not bool or type(value['size_bytes']) is not int
        or value['ledger_authority'] is not False or value['custody_acknowledgment'] is not False):raise ValueError('native evidence queue receipt differs')
    expected=dict(format=FORMAT,message_id=value['message_id'],new=value['new'],**_bound(data),ledger_authority=False,custody_acknowledgment=False)
    if value!=expected:raise ValueError('native evidence queue bytes differ')
    wire.hex32(value['message_id'],'message ID')
    return value['message_id'],value['new']

def queue_carry(root,message_id,output,source,destination):
    _profile();value,data=_invoke({'Carry':dict(path=_path(root),message_id=message_id,output=_path(output),
                                      source=source,destination=destination,limits=_limits())})
    _checked(value,data)
    import interstellar_transfer as wire
    frame=wire.decode_json(data)
    if frame['message_id']!=message_id:raise ValueError('native evidence carry assembly differs')
    return frame
