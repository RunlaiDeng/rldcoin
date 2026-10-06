"""Exact active-frame sharing in a bounded private state image, never authority.

No wire/packet transformation. Each original transit is reconstructed one at a
time with its complete canonical size/digest, then ordinary mesh validation
checks every signature/route/frame. Old inline images refuse without conversion.
"""
import copy
import hashlib
import re
import interstellar_transfer as wire
from interstellar_frame_digest import commitment, packet_body_bytes

STORAGE = 'RLD-CONTACT-ACTIVE-SHARED-FRAME-V1'
FRAME = 'RLD-CONTACT-ACTIVE-FRAME-V1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
B64 = re.compile(r'[A-Za-z0-9+/]*={0,2}\Z')


BASE64_ASCII = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def base64_text(value):
    """Same bounded ASCII alphabet/padding test; no decoding or authority."""
    if type(value) is not str:
        return bool(B64.fullmatch(value))
    if not value.isascii():
        return False
    padding = 2 if value.endswith('==') else 1 if value.endswith('=') else 0
    raw = value.encode('ascii')
    return not raw[:len(raw)-padding if padding else len(raw)].translate(None, BASE64_ASCII)


def require(ok, message):
    if not ok:raise ValueError(message)


def identifier(value):
    require(isinstance(value,str) and HEX.fullmatch(value),'active state identifier invalid')
    return value


def digest(value):
    return hashlib.sha256(packet_body_bytes(value)).hexdigest()


def image_bytes(image, *, max_messages):
    """Exact canonical image, with operation-local large frame encoding.

    Frame strings use the existing escape-free encoder; unsupported values
    retain the ordinary complete canonical path. No checked state or frame
    bytes survive this call, and unpack still validates every original field.
    """
    if (type(image) is not dict
            or set(image) != {'format', 'network', 'node_id', 'state', 'frames'}
            or type(image['frames']) is not dict
            or len(image['frames']) > max_messages
            or any(type(ref) is not str for ref in image['frames'])):
        return wire.canonical(image)
    frames = b'{' + b','.join(wire.canonical(ref) + b':' + packet_body_bytes(obj)
                             for ref, obj in sorted(image['frames'].items())) + b'}'
    return b'{' + b','.join(wire.canonical(key) + b':'
                           + (frames if key == 'frames' else wire.canonical(image[key]))
                           for key in sorted(image)) + b'}'


def bounds(state, max_messages):
    require(isinstance(state,dict) and state.get('active_storage')==STORAGE,
            'active state storage binding differs; preserve legacy state')
    network,node=identifier(state.get('network')),identifier(state.get('node_id'))
    require(isinstance(state.get('messages'),dict) and len(state['messages'])<=max_messages,
            'active state message capacity/schema invalid')
    return network,node


def pack(state, *, max_state, max_messages, max_transit):
    network,node=bounds(state,max_messages);records={};frames={};exact_frames={}
    image=dict(format=STORAGE,network=network,node_id=node,
               state=dict(state,messages=records),frames=frames)
    size=len(image_bytes(image, max_messages=max_messages))
    require(size<=max_state,'durable state capacity reached; retain previous state')
    for ident,transit in state['messages'].items():
        identifier(ident)
        require(isinstance(transit,dict) and set(transit)=={'packet','routing','hops'}
                and isinstance(transit['packet'],dict) and isinstance(transit['packet'].get('body'),dict),
                'active transit shape invalid')
        complete_digest, complete_size = commitment(transit)
        require(0<complete_size<=max_transit,'active transit expanded bound exceeded')
        frame=transit['packet']['body'].get('frame')
        require(isinstance(frame,str) and frame.isascii() and len(frame)<=wire.MAX_FRAME*2
                and base64_text(frame),'active frame encoding/bound invalid')
        # One call only: exact string equality shares storage, never validation.
        ref=exact_frames.get(frame)
        if ref is None:
            obj=dict(format=FRAME,network=network,node_id=node,frame=frame);ref=digest(obj)
            require(ref not in frames,'active frame collision')
            size+=len(wire.canonical(ref))+1+len(packet_body_bytes(obj))+(1 if frames else 0)
            frames[ref]=obj;exact_frames[frame]=ref
        meta=copy.deepcopy(transit);del meta['packet']['body']['frame']
        entry=dict(transit=meta,frame=ref,expanded_size_bytes=complete_size,
                   expanded_sha256=complete_digest)
        size+=len(wire.canonical(ident))+1+len(wire.canonical(entry))+(1 if records else 0)
        require(size<=max_state,'durable state capacity reached; retain previous state')
        records[ident]=entry
    require(len(image_bytes(image, max_messages=max_messages))==size,'active state accounting differs')
    return image


def decode(raw, *, network, node_id, max_state, max_messages, max_transit):
    """Own decoded data; authenticate exact canonical bytes and bounds once."""
    require(type(raw) is bytes and len(raw)<=max_state, 'active state byte capacity exceeded')
    image=wire.decode_json(raw)
    require(raw==image_bytes(image, max_messages=max_messages), 'noncanonical state JSON')
    return _unpack(image, image_size=len(raw), network=network, node_id=node_id,
                   max_state=max_state, max_messages=max_messages, max_transit=max_transit)


def unpack(image, *, network, node_id, max_state, max_messages, max_transit):
    return _unpack(image, image_size=len(image_bytes(image, max_messages=max_messages)), network=network,
                   node_id=node_id, max_state=max_state, max_messages=max_messages,
                   max_transit=max_transit)


def _unpack(image, *, image_size, network, node_id, max_state, max_messages, max_transit):
    require(isinstance(image,dict) and set(image)=={'format','network','node_id','state','frames'}
            and image['format']==STORAGE,'active state image version differs; preserve legacy state')
    require(image['network']==network and image['node_id']==node_id,'corrupt active state identity ownership differs')
    # Both entry points computed this exact size from the complete canonical
    # image in this call. Never accept a caller-provided size or cached state.
    require(image_size<=max_state,'active state byte capacity exceeded')
    state=image['state'];n,p=bounds(state,max_messages)
    require((n,p)==(network,node_id),'active state metadata ownership differs')
    require(isinstance(image['frames'],dict) and len(image['frames'])<=max_messages,
            'active frame pool capacity/schema invalid')
    pool={}
    for ref,obj in image['frames'].items():
        identifier(ref)
        require(isinstance(obj,dict) and set(obj)=={'format','network','node_id','frame'}
                and obj['format']==FRAME and obj['network']==network and obj['node_id']==node_id,
                'active frame ownership/domain differs')
        frame=obj['frame']
        require(isinstance(frame,str) and frame.isascii() and len(frame)<=wire.MAX_FRAME*2
                and base64_text(frame),'active frame encoding/bound invalid')
        require(digest(obj)==ref,'active frame bytes differ')
        pool[ref]=frame
    records={};referenced=set()
    for ident,entry in state['messages'].items():
        identifier(ident)
        require(isinstance(entry,dict) and set(entry)=={'transit','frame','expanded_size_bytes','expanded_sha256'},
                'active transit record differs')
        ref=identifier(entry['frame']);identifier(entry['expanded_sha256'])
        require(ref in pool,'active frame reference missing')
        declared=entry['expanded_size_bytes']
        require(type(declared) is int and 0<declared<=max_transit,'active transit expanded bound exceeded')
        meta=entry['transit']
        require(isinstance(meta,dict) and set(meta)=={'packet','routing','hops'}
                and isinstance(meta['packet'],dict) and isinstance(meta['packet'].get('body'),dict)
                and 'frame' not in meta['packet']['body'],'active transit frame metadata differs')
        expanded=copy.deepcopy(meta);expanded['packet']['body']['frame']=pool[ref]
        complete_digest, complete_size = commitment(expanded)
        require(complete_size==declared,'active transit expanded size differs')
        require(complete_digest==entry['expanded_sha256'],
                'active transit complete bytes differ')
        records[ident]=expanded;referenced.add(ref)
    require(referenced==set(pool),'active frame orphan refused; preserve state')
    return dict(state,messages=records)
