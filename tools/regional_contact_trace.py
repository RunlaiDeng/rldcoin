"""Opt-in bounded live packet metadata; no evidence, state or authority cache.

The private status ring needs an independent collector. Eviction/rejection is
explicit; an incomplete trace cannot prove absence, waiting or delivery.
"""
from collections import deque
import math
import os
from pathlib import Path
import re
import subprocess
import threading
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT='RLD-GROUND-CONTACT-TRACE-V1'
MAX_EVENTS=128
MAX_EVENT_BYTES=1024
MAX_BYTES=192*1024
PUBLICATION_FORMAT='RLD-GROUND-CONTACT-TRACE-PUBLICATION-V1'
PUBLICATION_INTERVAL=.25
HEX=re.compile(r'[0-9a-f]{64}\Z')
COUNT_FIELDS={'class_step','first_pending','first_arrivals','offered','retry_count','selected'}
BOOL_FIELDS={'ordered','priority','newest','direct_waiting','direct_recent','direct_prepared','direct_selected','native_success'}
FIELDS={'packet_id','frame_id','envelope_id','nonce','attempt','failure_stage','error_class',
        'scope_id','direct_id','copy_after','frame_after','origin_turn','exchange_id','native_action','command_id'}|COUNT_FIELDS|BOOL_FIELDS
HEX_FIELDS={'packet_id','frame_id','envelope_id','nonce','scope_id','direct_id','copy_after','frame_after','exchange_id','command_id'}
STAGES={'source_enqueued','outgoing_prepared','prepare_start','prepare_selection','prepare_selected','prepare_retained',
        'contact_start','request_sent','peer_custody_authenticated',
        'spool_outgoing_published','spool_incoming_read','spool_incoming_custody',
        'reply_local_custody','outgoing_failed','contact_failed','request_authenticated','local_transport_custody',
        'destination_receipt_retained','inbound_refused','deferred_attempt','deferred_local_custody','deferred_input_queued','deferred_input_not_queued',
        'destination_receipt_observed','native_envelope_received','native_receive_selected',
        'native_receive_attempt','native_receive_refused','native_receive_queued',
        'spool_outgoing_write_started','spool_incoming_discovered','spool_incoming_read_started',
        'spool_incoming_bytes_read','spool_incoming_decode_started','spool_incoming_decoded',
        'native_head_started','native_head_returned','native_input_durable',
        'native_validate_call_started','native_validate_call_returned','native_validate_call_failed',
        'native_validation_bound','timeout_requested','timeout_retained','timeout_failed',
        'submission_scan_started','submission_input_read','submission_auth_started',
        'submission_retained','submission_retention_failed','submission_duplicate_seen',
        'submission_scan_finished','consensus_tick_started','consensus_tick_finished',
        'consensus_context_observed','proposal_requested','proposal_retained','proposal_failed',
        'native_call_started','native_call_finished','candidate_selection_started',
        'candidate_submission_seen','candidate_command_attempted','candidate_command_refused',
        'candidate_command_selected'}


def check_fields(stage,peer,fields):
    mesh.require(type(stage) is str and stage in STAGES
                 and (peer is None or type(peer) is str and HEX.fullmatch(peer) is not None)
                 and not set(fields)-FIELDS,'bounded trace stage and fields required')
    for key,value in fields.items():
        if key in HEX_FIELDS:mesh.require(type(value) is str and HEX.fullmatch(value) is not None,'trace digest')
        elif key=='attempt' or key in COUNT_FIELDS:mesh.require(type(value) is int and 0<=value<2**63,'trace count')
        elif key in BOOL_FIELDS:mesh.require(type(value) is bool,'trace boolean')
        else:mesh.require(type(value) is str and len(value)<=48 and value.replace('_','').isalnum(),'trace enum')


class ContactTrace:
    def __init__(self):
        self.lock=threading.Lock()
        self.events=deque(maxlen=MAX_EVENTS)
        self.sequence=self.evicted=self.rejected=0
        self.binding=None
        self.available=True

    def bind(self,network,node_id):
        binding=(mesh.hex32(network),mesh.hex32(node_id))
        with self.lock:
            mesh.require(self.binding is None or self.binding==binding,'trace binding cannot change')
            self.binding=binding

    def reject(self):
        with self.lock:
            if self.rejected<2**63-1:self.rejected+=1
            else:self.available=False

    def event(self,stage,peer=None,**fields):
        try:
            check_fields(stage,peer,fields)
            with self.lock:
                now=time.monotonic()
                if not math.isfinite(now):raise ValueError('trace clock')
                if self.binding is None or self.sequence>=2**63-1:
                    self.available=False;return
                row=dict(sequence=self.sequence+1,monotonic_seconds=now,stage=stage,peer=peer,**fields)
                if len(wire.canonical(row))>MAX_EVENT_BYTES:
                    self.rejected+=1;return
                self.sequence+=1
                if len(self.events)==MAX_EVENTS:self.evicted+=1
                self.events.append(row)
        except Exception:self.reject()

    def packet_rows(self,bundle):
        # Caller owns the bounded bundle for this operation only. These tuples
        # retain identifiers, never frames, signatures, mutable headers or keys.
        try:
            transits=bundle['body']['transits']
            mesh.require(type(transits) is list and len(transits)<=mesh.MAX_PACKET_BATCH,'trace transit bound')
            return tuple((mesh.digest(t['packet']),mesh.hex32(t['routing']['body']['frame_id'])) for t in transits)
        except Exception:
            self.reject();return ()

    def packets(self,stage,peer,rows,**fields):
        for packet_id,frame_id in rows:self.event(stage,peer,packet_id=packet_id,frame_id=frame_id,**fields)

    def native_received(self,packet_id,raw):
        self.native_stage('native_envelope_received',packet_id,raw)

    def native_stage(self,stage,packet_id,raw,**fields):
        """Selection/attempt/refusal are observations, never Native acceptance."""
        try:
            mesh.require(stage in {'native_envelope_received','native_receive_selected','native_receive_queued',
                                   'native_receive_attempt','native_receive_refused'},'native trace stage')
            header,_=wire.inspect_frame(raw)
            self.event(stage,packet_id=packet_id,envelope_id=header['export_id'],**fields)
        except Exception:self.reject()

    def snapshot(self):
        with self.lock:
            value=dict(format=FORMAT,binding=self.binding,sequence=self.sequence,evicted_events=self.evicted,
                       rejected_events=self.rejected,available=self.available,events=[dict(x) for x in self.events],
                       process_local_only=True,private_trace=True,authority=False,
                       physical_route_qualified=False,complete_collection_verified=False)
        if len(wire.canonical(value))>MAX_BYTES:
            return dict(format=FORMAT,available=False,authority=False,diagnostic='trace_capacity')
        return value


class TracePublisher:
    """Opt-in primitive telemetry, independent of Native/service tick waits.

    No node/keys/payloads/authority. The original ring still loses coverage on
    overflow; publishing more often cannot backfill events already evicted.
    """
    def __init__(self, trace, path):
        self.trace,self.path=trace,Path(path)
        self.pid=os.getpid();self.failure=None;self.stop_event=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True,name='contact-trace-publication')
        mesh.require(not self.path.exists() and not self.path.is_symlink(),
                     'old diagnostic publication cannot resume')
        self.publish()
        self.thread.start()

    def publish(self):
        value=dict(format=PUBLICATION_FORMAT,process_id=self.pid,
                   contact_trace=self.trace.snapshot(),publisher_failed=self.failure is not None)
        mesh.require(len(wire.canonical(value))<=MAX_BYTES,'trace publication byte capacity')
        mesh.atomic(self.path,value)

    def run(self):
        while not self.stop_event.wait(PUBLICATION_INTERVAL):
            try:self.publish()
            except BaseException as error:
                # A failed diagnostic never acknowledges or changes protocol
                # evidence. Future publications retain this failure, not a pass.
                self.failure=type(error).__name__
                with self.trace.lock:self.trace.available=False

    def close(self):
        self.stop_event.set()
        if self.thread.ident is not None:self.thread.join(timeout=3)
        mesh.require(not self.thread.is_alive(),'diagnostic publisher did not stop')
        self.publish()


class TraceCursor:
    """Explicit externally bound collection; restart/gaps never become coverage."""
    def __init__(self,network,node_id):
        self.binding=(mesh.hex32(network),mesh.hex32(node_id))
        self.sequence=self.rejected=0
        self.last_digest=None

    def drain(self,value):
        mesh.require(value['format']==FORMAT and tuple(value['binding'])==self.binding
            and value['available'] is True and value['authority'] is False
            and value['process_local_only'] is True and value['private_trace'] is True
            and value['physical_route_qualified'] is False and value['complete_collection_verified'] is False,
            'exact bounded trace scope required')
        sequence,evicted,rejected=(value[k] for k in ('sequence','evicted_events','rejected_events'))
        mesh.require(all(type(x) is int and 0<=x<2**63 for x in (sequence,evicted,rejected))
            and sequence>=self.sequence and rejected>=self.rejected,'trace restart or counters regressed')
        rows=value['events']
        mesh.require(type(rows) is list and len(rows)<=MAX_EVENTS and len(rows)+evicted==sequence,
                     'trace ring inventory differs')
        for index,row in enumerate(rows):
            mesh.require(set(row)<=FIELDS|{'sequence','monotonic_seconds','stage','peer'}
                and row['sequence']==evicted+index+1 and len(wire.canonical(row))<=MAX_EVENT_BYTES
                and type(row['monotonic_seconds']) in (int,float) and math.isfinite(row['monotonic_seconds'])
                and row['monotonic_seconds']>=0,'bounded exact trace event required')
            check_fields(row['stage'],row['peer'],{k:v for k,v in row.items() if k in FIELDS})
            if row['sequence']==self.sequence and self.last_digest is not None:
                mesh.require(mesh.digest(row)==self.last_digest,'retained trace event changed')
        earliest=rows[0]['sequence'] if rows else sequence+1
        missed=max(0,earliest-self.sequence-1)
        delta=[dict(row) for row in rows if row['sequence']>self.sequence]
        result=dict(events=delta,missed_events=missed,rejected_observations=rejected-self.rejected,
                    through_sequence=sequence,authority=False,
                    this_interval_complete=missed==0 and rejected==self.rejected)
        self.sequence,self.rejected=sequence,rejected
        if rows:self.last_digest=mesh.digest(rows[-1])
        return result


class TraceCollector:
    """Private independent status collection for one explicitly owned process.

    Cursor/OS identity and status association are telemetry, never native replay
    or independent freshness. A write failure propagates and leaves a partial log.
    """
    def __init__(self,recorder,process,status,network,node_id):
        self.recorder,self.process,self.status=recorder,process,Path(status)
        self.cursor=TraceCursor(network,node_id)

    def sample(self):
        from regional_ground_resources import process_read
        reason='producer_observation_unavailable'
        try:
            before=process_read(self.process.pid)
            reason='producer_identity_changed'
            mesh.require((before['start'],before['command_sha256'])==self.process.identity,'trace producer changed')
            reason='status_not_regular'
            mesh.require(not self.status.is_symlink() and self.status.is_file(),'regular trace status required')
            reason='status_read_unavailable'
            with self.status.open('rb') as stream:raw=stream.read(16*1024*1024+1)
            reason='status_capacity'
            mesh.require(len(raw)<=16*1024*1024,'trace status observation bound')
            reason='status_decode_invalid'
            value=wire.decode_json(raw)
            reason='status_pid_mismatch'
            mesh.require(type(value['process_id']) is int and value['process_id']==self.process.pid,
                         'trace status belongs to another process')
            reason='trace_missing'
            trace=value['contact_trace'];value=None;raw=None
            reason='producer_observation_unavailable'
            after=process_read(self.process.pid)
            reason='producer_identity_changed'
            mesh.require((after['start'],after['command_sha256'])==self.process.identity,'trace producer changed while reading')
            reason='trace_scope_invalid'
            result=dict(kind='contact_trace_delta',available=True,**self.cursor.drain(trace))
        except (OSError,ValueError,KeyError,TypeError,RecursionError,subprocess.SubprocessError):
            result=dict(kind='contact_trace_delta',available=False,reason=reason,
                        events=None,authority=False,this_interval_complete=False)
        # No I/O error can be relabeled successful or cause protocol recovery.
        self.recorder.write(result)
        return result
