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
RECEIVE_FORMAT = 'RLD-BFT-ORIGIN-RECEIVE-V1'
ORIGIN_NETWORK = 'RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3'


def supported(runtime, envelopes):
    """Scheduling selection only. Native still checks every complete object.

    Select bounded origin envelopes with complete carried local evidence and
    no epoch bodies. Native reconstructs/authenticates every complete proof
    and refuses expanded response capacity before any history/value sync.
    Other inputs keep the existing read-only segmentation/sync path. A failed
    mutating call never falls back or retries through that path.
    """
    return (runtime.joint is None and runtime.format=='RLD-REGIONAL-BFT-ORIGIN-NODE-V2'
        and all(type(e) is dict and e.get('format')==ORIGIN_NETWORK
            and type(e.get('evidence')) is dict and set(e['evidence'])=={'snapshots'}
            and type(e['evidence']['snapshots']) is list
            and len(e['evidence']['snapshots'])<=64
            and type(e.get('body')) is dict and len(e['body'])==1
            and next(iter(e['body'])) in ('Signed','Submission','Finalized') for e in envelopes)
        and len(wire.canonical(envelopes))<=MAX_BYTES
        and all(len(wire.canonical(e))<=wire.MAX_PAYLOAD for e in envelopes))


def checked_rows(results, count):
    mesh.require(type(results) is list and len(results)==count,
                 'live Native complete result count differs')
    for row in results:
        mesh.require(type(row) is dict and set(row)=={'message_id','value','evidence','epochs'}
            and type(row['evidence']) is dict and set(row['evidence'])=={'snapshots'}
            and type(row['evidence']['snapshots']) is list and len(row['evidence']['snapshots'])<=64
            and type(row['epochs']) is list and len(row['epochs'])<=16,
            'live Native batch result shape differs')
        mesh.hex32(row['message_id'])
        if row['value'] is not None:mesh.hex32(row['value'])
    return results


def receive_origin(runtime, envelopes):
    """One separately observed head, one pinned Native lock/open, no signing."""
    mesh.require(type(envelopes) is list and 0<len(envelopes)<=MAX_BATCH
        and supported(runtime,envelopes),'origin receive unsupported batch')
    raw=wire.canonical(envelopes)
    head=runtime.native.call('history-head')
    mesh.require(type(head) is dict and head.get('currency')==runtime.native.currency
        and head.get('region')==runtime.region,'origin receive native head domain differs')
    mesh.hex32(head['history_head'])
    started=time.monotonic();succeeded=False
    try:
        with tempfile.NamedTemporaryFile(dir=runtime.root,prefix='.native-receive-',suffix='.json') as handle:
            handle.write(raw);handle.flush();os.fsync(handle.fileno())
            result=runtime.native.call('bft-origin-network-receive-batch','--file',handle.name,
                                      '--expected-head',head['history_head'])
        mesh.require(type(result) is dict and set(result)=={'format','currency','region',
            'request_sha256','results','history_head','context','verified','fixture_only','signing_authority'}
            and len(wire.canonical(result))<=MAX_BYTES and result['format']==RECEIVE_FORMAT
            and result['currency']==runtime.native.currency and result['region']==runtime.region
            and result['request_sha256']==hashlib.sha256(raw).hexdigest()
            and result['verified'] is True and result['fixture_only'] is True
            and result['signing_authority'] is False,'origin receive response binding differs')
        mesh.hex32(result['history_head'])
        context=result['context']
        mesh.require(type(context) is dict and set(context)=={'currency','region','epoch','previous',
            'parent_height','parent_block','parent_state'}
            and context['currency']==runtime.native.currency and context['region']==runtime.region
            and type(context['parent_height']) is int and 0<=context['parent_height']<2**64,
            'origin receive context binding differs')
        for name in ('epoch','parent_block','parent_state'):mesh.hex32(context[name])
        if context['previous'] is not None:mesh.hex32(context['previous'])
        bindings=result['results']
        mesh.require(type(bindings) is list and len(bindings)==len(envelopes)
            and all(type(row) is dict and set(row)=={'input_sha256','checked'}
                and row['input_sha256']==hashlib.sha256(wire.canonical(e)).hexdigest()
                for row,e in zip(bindings,envelopes)), 'origin receive ordered result binding differs')
        rows=checked_rows([row['checked'] for row in bindings],len(envelopes))
        # Full expanded local evidence comes only from this complete Native
        # authentication, never Python prefix reconstruction or a peer cache.
        mesh.require(all(row['epochs']==[] for row in rows),
                     'origin receive selected response shape differs')
        succeeded=True
        return rows,context
    finally:
        observation=getattr(runtime,'observation',None)
        if observation is not None:observation.operation('bft-origin-network-receive-batch',started,succeeded)


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
            checked_rows(result['results'],len(rows))
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
