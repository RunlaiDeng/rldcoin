"""Operation-local complete Native envelope authentication, before any sync."""
import hashlib
import os
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT = 'RLD-BFT-LIVE-NETWORK-INSPECTION-V1'
MAX_BATCH = 4
MAX_BYTES = 8*1024*1024
CAPACITY_REFUSAL = 'native rejected: regional candidate rejected: live network batch response exceeds bound'


def inspect(runtime, envelopes):
    """Return only after every bounded complete envelope passes Native checks.

    Output expansion may split read-only requests, never skip authentication.
    Results are local to this operation and are never retained as authority.
    """
    mesh.require(type(envelopes) is list and 0<len(envelopes)<=MAX_BATCH,
                 'live Native batch count exceeds bound')
    encoded=[wire.canonical(e) for e in envelopes]
    mesh.require(all(0<len(raw)<=wire.MAX_PAYLOAD for raw in encoded),
                 'live Native envelope exceeds payload bound')

    def authenticate(rows):
        raw=b'['+b','.join(rows)+b']'
        mesh.require(len(raw)<=MAX_BYTES,'live Native batch input capacity')
        started=time.monotonic();succeeded=False
        try:
            with tempfile.NamedTemporaryFile(dir=runtime.root,prefix='.native-live-',suffix='.json') as handle:
                handle.write(raw);handle.flush();os.fsync(handle.fileno())
                result=runtime.native.call('bft-network-inspect-batch','--file',handle.name)
            mesh.require(type(result) is dict and set(result)=={'format','currency','region',
                'request_sha256','results','verified','ledger_changed','signing_authority'}
                and len(wire.canonical(result))<=MAX_BYTES
                and result['format']==FORMAT and result['currency']==runtime.native.currency
                and result['region']==runtime.region
                and result['request_sha256']==hashlib.sha256(raw).hexdigest()
                and result['verified'] is True and result['ledger_changed'] is False
                and result['signing_authority'] is False and type(result['results']) is list
                and len(result['results'])==len(rows),'live Native batch response binding differs')
            for row in result['results']:
                mesh.require(type(row) is dict and set(row)=={'message_id','value','evidence','epochs'}
                    and type(row['evidence']) is dict and set(row['evidence'])=={'snapshots'}
                    and type(row['evidence']['snapshots']) is list and len(row['evidence']['snapshots'])<=64
                    and type(row['epochs']) is list and len(row['epochs'])<=16,
                    'live Native batch result shape differs')
                mesh.hex32(row['message_id'])
                if row['value'] is not None:mesh.hex32(row['value'])
            succeeded=True
            return result['results']
        except ValueError as error:
            if str(error)!=CAPACITY_REFUSAL or len(rows)==1:raise
            midpoint=len(rows)//2
            return authenticate(rows[:midpoint])+authenticate(rows[midpoint:])
        finally:
            observation=getattr(runtime,'observation',None)
            if observation is not None:observation.operation('bft-network-inspect-batch',started,succeeded)

    # The wire and expanded response bounds are independent. Authenticate all
    # segments before the caller can synchronize even the first envelope.
    results=[];pending=[];size=2
    for raw in encoded:
        if pending and size+1+len(raw)>MAX_BYTES:
            results.extend(authenticate(pending));pending=[];size=2
        size+=len(raw)+bool(pending);pending.append(raw)
    results.extend(authenticate(pending))
    mesh.require(len(results)==len(envelopes),'live Native complete result count differs')
    return results
