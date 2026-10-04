"""Bounded cold-only Native authentication; never retain, sync or sign."""
import hashlib
import os
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT = 'RLD-BFT-COLD-NETWORK-CHECK-V1'
MAX_BATCH = 4
MAX_INPUT = 8*1024*1024


def check_retained(runtime):
    """Stream one exact retained envelope at a time into a bounded request.

    Only ordered IDs/expected values survive reconstruction. Every complete
    batch is Native-checked before cold startup can reach recovery or signing.
    """
    def authenticate(handle, expected):
        handle.write(b']');handle.flush();os.fsync(handle.fileno())
        handle.seek(0);digest=hashlib.sha256()
        while chunk:=handle.read(65536):digest.update(chunk)
        started=time.monotonic();succeeded=False
        try:
            result=runtime.native.call('bft-network-check-batch','--file',handle.name)
            mesh.require(type(result) is dict and set(result)=={'format','currency','region',
                'request_sha256','results','verified','ledger_changed','signing_authority'}
                and result['format']==FORMAT and result['currency']==runtime.native.currency
                and result['region']==runtime.region and result['request_sha256']==digest.hexdigest()
                and result['verified'] is True and result['ledger_changed'] is False
                and result['signing_authority'] is False and type(result['results']) is list
                and len(result['results'])==len(expected), 'cold Native batch response binding differs')
            for row,(_,value) in zip(result['results'],expected):
                mesh.require(type(row) is dict and set(row)=={'message_id','value'}
                    and row['value']==value, 'BFT runtime message value changed')
                mesh.hex32(row['message_id'])
            succeeded=True
        finally:
            observation=getattr(runtime,'observation',None)
            if observation is not None:
                observation.operation('bft-network-check-batch',started,succeeded)

    with tempfile.NamedTemporaryFile(dir=runtime.root,prefix='.native-cold-',suffix='.json') as handle:
        handle.write(b'[');expected=[];size=2
        for ident in runtime.state['messages']:
            record=runtime.state['messages'].record(ident)
            mesh.require(type(record['local']) is bool and ident==mesh.digest(record['body']),
                         'BFT runtime message ID changed')
            raw=runtime.state['messages'].payload(ident)
            mesh.require(0<len(raw)<=wire.MAX_PAYLOAD, 'cold retained envelope exceeds payload bound')
            if expected and (len(expected)==MAX_BATCH or size+1+len(raw)>MAX_INPUT):
                authenticate(handle,expected)
                handle.seek(0);handle.truncate();handle.write(b'[');expected=[];size=2
            mesh.require(size+bool(expected)+len(raw)<=MAX_INPUT, 'cold Native batch input capacity')
            if expected:handle.write(b',');size+=1
            handle.write(raw);size+=len(raw);expected.append((ident,record['value']))
            del raw,record
        if expected:authenticate(handle,expected)
