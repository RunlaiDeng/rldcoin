"""Checked native carriage codec with separate bounded byte and receipt buffers."""
import ctypes
import hashlib
from interstellar_crypto import backend, Buffer

FORMAT = 'RLD-NATIVE-CONTACT-SPOOL-CODEC-V1'
CODEC = 'RLD-CONTACT-SPOOL-ZLIB-V1'
MAX_BYTES = 20 * 1024 * 1024
MAX_CONTROL = 8192
HEADER_SIZE = len(CODEC) + 1 + 8 + 32

class CodecOutput(ctypes.Structure):
    _fields_ = [('receipt', Buffer), ('payload', Buffer)]

def _invoke(request, raw=b''):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError('native spool codec payload capacity')
    engine = backend()
    operation = engine.library.rld_contact_spool_codec
    pointer = ctypes.POINTER(ctypes.c_ubyte)
    operation.argtypes = [pointer, ctypes.c_size_t, pointer, ctypes.c_size_t]
    operation.restype = CodecOutput
    memory = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    payload = None
    def call(control, size, *unused):
        nonlocal payload
        result = operation(control, size, memory, len(memory))
        try:
            try:
                if result.payload.len > MAX_BYTES or (result.payload.len and not result.payload.data):
                    raise ValueError('native spool codec output capacity')
                payload = ctypes.string_at(result.payload.data, result.payload.len) if result.payload.len else b''
            finally:
                engine.library.rld_contact_crypto_free(result.payload)
        except BaseException:
            engine.library.rld_contact_crypto_free(result.receipt)
            raise
        return result.receipt
    value = engine.invoke(call, request)
    return value, payload

def _profile():
    engine = backend()
    if not getattr(engine, '_contact_spool_codec_profile', False):
        value, raw = _invoke('Info')
        if raw or value != dict(format=FORMAT, codec=CODEC, max_bytes=MAX_BYTES,
                               max_control=MAX_CONTROL, header_size=HEADER_SIZE, level=1,
                               window_bits=15, ledger_authority=False, authenticated=False):
            raise ValueError('native spool codec profile differs')
        engine._contact_spool_codec_profile = True

def _request(mode, raw, limit, **extra):
    if type(limit) is not int or not 0 < limit <= MAX_BYTES:
        raise ValueError('invalid spool codec limit')
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError('invalid spool codec bytes')
    _profile()
    return _invoke({mode: dict(limit=limit, size_bytes=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest(), **extra)}, raw)

def _bytes(mode, raw, limit):
    value, data = _request(mode, raw, limit)
    if value != dict(format=FORMAT, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                     ledger_authority=False, authenticated=False) or not 0 < len(data) <= limit:
        raise ValueError('native spool codec byte receipt differs')
    return data

def encode(raw, *, limit):
    return _bytes('Encode', raw, limit)

def decode(data, *, limit):
    return _bytes('Decode', data, limit)

def expanded_size(header, *, encoded_size, limit):
    if type(encoded_size) is not int or not 0 < encoded_size <= MAX_BYTES:
        raise ValueError('encoded spool bound exceeded')
    value, data = _request('Header', header, limit, encoded_size=encoded_size)
    if (data or type(value) is not dict or set(value) != {'format', 'expanded_size', 'ledger_authority', 'authenticated'}
        or value['format'] != FORMAT or value['ledger_authority'] is not False or value['authenticated'] is not False
        or type(value['expanded_size']) is not int or not 0 < value['expanded_size'] <= limit):
        raise ValueError('native spool codec header receipt differs')
    return value['expanded_size']
