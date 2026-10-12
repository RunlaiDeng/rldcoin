"""Native opaque frame bridge; ordinary full evidence authentication follows."""
import ctypes
import hashlib
from interstellar_crypto import backend
from interstellar_spool_codec_native import CodecOutput

FORMAT='RLD-NATIVE-CONTACT-FRAME-V1'
MAX_PAYLOAD=3*1024*1024
MAX_FRAME=4*1024*1024+4096
MAX_CONTROL=8192

def _invoke(request,raw=b''):
    if type(raw) is not bytes or len(raw)>MAX_FRAME:
        raise ValueError('native frame input byte bound')
    engine=backend();operation=engine.library.rld_contact_frame
    pointer=ctypes.POINTER(ctypes.c_ubyte)
    operation.argtypes=[pointer,ctypes.c_size_t,pointer,ctypes.c_size_t]
    operation.restype=CodecOutput
    memory=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
    payload=None
    def call(control,size):
        nonlocal payload
        result=operation(control,size,memory,len(memory))
        try:
            try:
                if result.payload.len>MAX_FRAME or (result.payload.len and not result.payload.data):
                    raise ValueError('native frame output byte bound')
                payload=ctypes.string_at(result.payload.data,result.payload.len) if result.payload.len else b''
            finally:engine.library.rld_contact_crypto_free(result.payload)
        except BaseException:
            engine.library.rld_contact_crypto_free(result.receipt);raise
        return result.receipt
    value=engine.invoke(call,request)
    return value,payload

def _profile():
    engine=backend()
    if not getattr(engine,'_contact_frame_profile',False):
        import interstellar_transfer as wire
        value,data=_invoke('Info')
        if data or value!=dict(format=FORMAT,frame=wire.FORMAT,kinds=sorted(wire.KINDS|wire.CONTROL_KINDS),
                              max_payload=MAX_PAYLOAD,max_frame=MAX_FRAME,max_control=MAX_CONTROL,
                              ledger_authority=False,authenticated=False):
            raise ValueError('native frame profile differs')
        engine._contact_frame_profile=True

def _limits():
    import interstellar_transfer as wire
    if (type(wire.MAX_PAYLOAD) is not int or not 0<=wire.MAX_PAYLOAD<=MAX_PAYLOAD
        or type(wire.MAX_FRAME) is not int or not 0<=wire.MAX_FRAME<=MAX_FRAME):
        raise ValueError('native frame limits differ')
    return dict(payload=wire.MAX_PAYLOAD,frame=wire.MAX_FRAME)

def _request(mode,raw,**fields):
    if type(raw) is not bytes:raise ValueError('invalid evidence frame bytes')
    _profile()
    return _invoke({mode:dict(limits=_limits(),size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),**fields)},raw)

def _metadata(value,frame,payload):
    import interstellar_transfer as wire
    if (type(value) is not dict or set(value)!={'format','frame_size','frame_sha256','payload_size',
        'payload_sha256','message_id','ledger_authority','authenticated'}
        or value['format']!=FORMAT or value['ledger_authority'] is not False or value['authenticated'] is not False
        or type(value['frame_size']) is not int or type(value['payload_size']) is not int
        or value['frame_size']!=len(frame) or value['frame_sha256']!=hashlib.sha256(frame).hexdigest()
        or value['payload_size']!=len(payload) or value['payload_sha256']!=hashlib.sha256(payload).hexdigest()
        or not 0<len(frame)<=wire.MAX_FRAME or not 0<len(payload)<=wire.MAX_PAYLOAD):
        raise ValueError('native frame byte receipt differs')
    wire.hex32(value['message_id'],'message ID')

def make_frame(kind,source,destination,export,payload):
    value,data=_request('Make',payload,kind=kind,source=source,destination=destination,export=export)
    _metadata(value,data,payload)
    return data

def inspect_frame(data,source=None,destination=None):
    value,payload=_request('Inspect',data,source=source,destination=destination)
    _metadata(value,data,payload)
    import interstellar_transfer as wire
    frame=wire.decode_json(data)
    if type(frame) is not dict or frame.get('message_id')!=value['message_id']:
        raise ValueError('native frame assembly differs')
    return frame,payload
