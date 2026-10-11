"""Native companion archive bridge; byte receipts never replace cold authentication."""
import hashlib
from pathlib import Path
import interstellar_transfer as wire
import interstellar_mesh as mesh

FIELDS = {'format','currency','region','runtime_format','key','state_sha256','state_bytes',
          'message_count','new_envelopes_authenticated','full_cold_authentication_required',
          'ledger_changed','signing_authority'}
MAX_STATE = 32*1024*1024


def arguments(runtime):
    return ('--state-dir',runtime.root,'--expected-key',runtime.key,'--runtime-format',runtime.format)


def checked(runtime, receipt, raw, message_count, new_count):
    digest = hashlib.sha256(raw).hexdigest()
    mesh.require(type(receipt) is dict and set(receipt)==FIELDS
        and receipt['format']=='RLD-NATIVE-BFT-ARCHIVE-RECEIPT-V1'
        and receipt['currency']==runtime.native.currency and receipt['region']==runtime.region
        and receipt['runtime_format']==runtime.format and receipt['key']==runtime.key
        and receipt['state_sha256']==digest
        and type(receipt['state_bytes']) is int and receipt['state_bytes']==len(raw)<=MAX_STATE
        and type(receipt['message_count']) is int and receipt['message_count']==message_count
        and type(receipt['new_envelopes_authenticated']) is int and receipt['new_envelopes_authenticated']==new_count
        and receipt['full_cold_authentication_required'] is True
        and receipt['ledger_changed'] is False and receipt['signing_authority'] is False,
        'Native BFT archive receipt binding differs')
    return digest


def read(runtime):
    # Native validates the exact existing private bytes under its archive lock.
    # Python binds its subsequent local read to that receipt, then the original
    # complete cold Native checks still authenticate every reconstructed envelope.
    receipt = runtime.native.call('bft-runtime-archive-read',*arguments(runtime))
    from regional_bft_node import private
    path = private(runtime.state_path)
    with path.open('rb') as handle: raw=handle.read(MAX_STATE+1)
    mesh.require(len(raw)<=MAX_STATE,'BFT archive byte bound')
    value = wire.decode_json(raw)
    head = checked(runtime,receipt,raw,len(value['runtime']['messages']),0)
    return value,head


def store(runtime, packed, state):
    raw = wire.canonical(packed)
    mesh.require(len(raw)<=MAX_STATE,'BFT archive byte bound')
    previous = getattr(runtime,'_archive_head',None)
    old = getattr(runtime,'state',{}).get('messages',{})
    count = sum(ident not in old or old.record(ident)['local'] != state['messages'].record(ident)['local']
                for ident in state['messages'])
    args = arguments(runtime)
    if previous is not None: args += ('--expected-state-sha256',previous)
    receipt = runtime.with_json('bft-runtime-archive-store',packed,*args)
    return checked(runtime,receipt,raw,len(state['messages']),count)
