"""Native bounded shared-frame codec; callers still authenticate every transit.

Python encodes one ABI input at a time and assembles immutable shared strings
after Native has checked the complete image. The independent Python codec is
kept in interstellar_active_state for explicit test comparison only.
"""
import copy
import ctypes
import hashlib
import secrets
import interstellar_transfer as wire
from interstellar_crypto import backend, Buffer
from interstellar_frame_digest import packet_body_bytes

FORMAT = 'RLD-NATIVE-CONTACT-STATE-CODEC-V1'
STORAGE = 'RLD-CONTACT-ACTIVE-SHARED-FRAME-V1'
FRAME = 'RLD-CONTACT-ACTIVE-FRAME-V1'
MAX_STATE = 64 * 1024 * 1024
MAX_MESSAGES = 256
MAX_TRANSIT = 20 * 1024 * 1024
MAX_CONTROL = 8192
MAX_CONTEXTS = 8


def _invoke(request, raw=b''):
    if type(raw) is not bytes or len(raw) > MAX_STATE:
        raise ValueError('active state byte capacity exceeded')
    engine = backend()
    operation = engine.library.rld_contact_state_codec
    operation.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                          ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t]
    operation.restype = Buffer
    memory = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    if not getattr(engine, '_contact_state_codec_profile', False):
        info = engine.invoke(operation, 'Info', (ctypes.c_ubyte * 0)(), 0)
        if info != dict(format=FORMAT, storage=STORAGE, frame=FRAME, max_state=MAX_STATE,
                        max_messages=MAX_MESSAGES, max_transit=MAX_TRANSIT,
                        max_control=MAX_CONTROL, max_contexts=MAX_CONTEXTS, ledger_authority=False):
            raise ValueError('native active state codec profile differs')
        engine._contact_state_codec_profile = True
    return engine.invoke(operation, request, memory, len(raw))


def _limits(max_state, max_messages, max_transit):
    values = dict(max_state=max_state, max_messages=max_messages, max_transit=max_transit)
    bounds = dict(max_state=MAX_STATE, max_messages=MAX_MESSAGES, max_transit=MAX_TRANSIT)
    if any(type(value) is not int or not 0 <= value <= bounds[key] for key, value in values.items()):
        raise ValueError('active state native limits differ')
    return values


def _payload(raw):
    return dict(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _image(value, max_state):
    if (type(value) is not dict
            or set(value) != {'format', 'image', 'image_sha256', 'ledger_authority', 'authenticated'}
            or value['format'] != FORMAT or value['ledger_authority'] is not False
            or value['authenticated'] is not False):
        raise ValueError('native active codec response differs')
    raw = wire.canonical(value['image'])
    if len(raw) > max_state or hashlib.sha256(raw).hexdigest() != value['image_sha256']:
        raise ValueError('native active image bytes differ')
    return value['image']


def pack(state, *, max_state, max_messages, max_transit):
    limits = _limits(max_state, max_messages, max_transit)
    if type(state) is not dict or type(state.get('messages')) is not dict or len(state['messages']) > max_messages:
        raise ValueError('active state message capacity/schema invalid')
    token = secrets.token_hex(16)
    raw = wire.canonical(dict(state, messages={}))
    cleanup = True
    try:
        try:
            value = _invoke({'Begin': dict(token=token, limits=limits, **_payload(raw))}, raw)
        except ValueError as error:
            # A refused duplicate must never close the original operation.
            if str(error) == 'active codec context already exists':
                cleanup = False
            raise
        if value != dict(format=FORMAT, token=token, begun=True, ledger_authority=False):
            raise ValueError('native active codec begin differs')
        for ident, transit in state['messages'].items():
            # Exact complete ABI bytes, without serializing the expanded map.
            raw = packet_body_bytes(transit)
            value = _invoke({'Transit': dict(token=token, ident=ident, **_payload(raw))}, raw)
            if value != dict(format=FORMAT, token=token, retained=True, ledger_authority=False):
                raise ValueError('native active codec append differs')
        return _image(_invoke({'Finish': dict(token=token)}), max_state)
    finally:
        if cleanup:
            value = _invoke({'Abort': dict(token=token)})
            if value != dict(format=FORMAT, token=token, closed=True, ledger_authority=False):
                raise ValueError('native active codec close differs')


def decode(raw, *, network, node_id, max_state, max_messages, max_transit):
    limits = _limits(max_state, max_messages, max_transit)
    if type(raw) is not bytes or len(raw) > max_state:
        raise ValueError('active state byte capacity exceeded')
    value = _invoke({'Decode': dict(network=network, node_id=node_id, limits=limits, **_payload(raw))}, raw)
    image = _image(value, max_state)
    # Native checked all compact fields and every complete expanded record in
    # this call. This assembly grants no signature, custody or ledger rights.
    records = {}
    for ident, entry in image['state']['messages'].items():
        transit = copy.deepcopy(entry['transit'])
        transit['packet']['body']['frame'] = image['frames'][entry['frame']]['frame']
        records[ident] = transit
    return dict(image['state'], messages=records)


def unpack(image, **parameters):
    return decode(wire.canonical(image), **parameters)
