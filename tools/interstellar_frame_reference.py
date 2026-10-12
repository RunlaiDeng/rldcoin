"""Independent original Python frame codec for explicit tests only."""
import base64
import binascii
import hashlib
import interstellar_transfer as wire
FORMAT=wire.FORMAT
DOMAIN=wire.DOMAIN
KINDS=wire.KINDS
CONTROL_KINDS=wire.CONTROL_KINDS
MAX_PAYLOAD=wire.MAX_PAYLOAD
MAX_FRAME=wire.MAX_FRAME
canonical=wire.canonical
decode_json=wire.decode_json
hex32=wire.hex32

def make_frame(kind, source, destination, export, payload):
    if kind not in KINDS | CONTROL_KINDS or not 0 < len(payload) <= MAX_PAYLOAD:
        raise ValueError('invalid kind or payload length')
    hex32(source, 'source chain')
    hex32(destination, 'destination chain')
    hex32(export, 'export ID')
    if (source == destination) != (kind == 'regional-bft'):
        raise ValueError('source and destination are the same chain')
    fields = {'format': FORMAT, 'kind': kind, 'source_chain_id': source,
              'destination_chain_id': destination, 'export_id': export,
              'payload_sha256': hashlib.sha256(payload).hexdigest(),
              'payload_b64': base64.b64encode(payload).decode('ascii')}
    fields['message_id'] = hashlib.sha256(DOMAIN + canonical(fields)).hexdigest()
    data = canonical(fields)
    if len(data) > MAX_FRAME:
        raise ValueError('frame exceeds bound')
    return data


def inspect_frame(data, source=None, destination=None):
    if len(data) > MAX_FRAME:
        raise ValueError('frame exceeds bound')
    frame = decode_json(data)
    if not isinstance(frame, dict) or set(frame) != {
        'format', 'kind', 'source_chain_id', 'destination_chain_id', 'export_id',
        'payload_sha256', 'payload_b64', 'message_id',
    } or frame['format'] != FORMAT or not isinstance(frame['kind'], str) or frame['kind'] not in KINDS | CONTROL_KINDS:
        raise ValueError('invalid evidence frame')
    if data != canonical(frame):
        raise ValueError('noncanonical evidence frame')
    for name in ('source_chain_id', 'destination_chain_id', 'export_id',
                 'payload_sha256', 'message_id'):
        hex32(frame[name], name)
    if (frame['source_chain_id'] == frame['destination_chain_id']) != (frame['kind'] == 'regional-bft'):
        raise ValueError('same-chain evidence frame')
    if source is not None and frame['source_chain_id'] != source:
        raise ValueError('wrong source chain')
    if destination is not None and frame['destination_chain_id'] != destination:
        raise ValueError('wrong destination chain')
    if not isinstance(frame['payload_b64'], str):
        raise ValueError('invalid payload encoding')
    try:
        payload = base64.b64decode(frame['payload_b64'], validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError('invalid payload encoding') from error
    if (not 0 < len(payload) <= MAX_PAYLOAD
            or base64.b64encode(payload).decode('ascii') != frame['payload_b64']
            or hashlib.sha256(payload).hexdigest() != frame['payload_sha256']):
        raise ValueError('payload changed')
    body = {key: value for key, value in frame.items() if key != 'message_id'}
    if hashlib.sha256(DOMAIN + canonical(body)).hexdigest() != frame['message_id']:
        raise ValueError('message ID changed')
    if frame['kind'] == 'regional-bft':
        envelope = decode_json(payload)
        fields={'format','currency','region','evidence','body'}
        origin=isinstance(envelope,dict) and envelope.get('format')=='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3'
        if origin:fields.add('origins')
        if (not isinstance(envelope,dict) or set(envelope) != fields
                or envelope['format'] not in ('RLD-REGIONAL-BFT-NETWORK-V2','RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3')
                or (origin and (type(envelope['origins']) is not list or len(envelope['origins'])>4))
                or envelope['region'] != frame['source_chain_id']
                or frame['export_id'] != hashlib.sha256(payload).hexdigest()):
            raise ValueError('regional consensus carriage binding mismatch')
        hex32(envelope['currency'], 'consensus currency')
    return frame, payload
