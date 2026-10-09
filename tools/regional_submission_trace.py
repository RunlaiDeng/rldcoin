"""Explicit narrow ground diagnostic; never a complete transport trace.

The original 128-row/192-KiB producer and .25-second publication bounds remain.
Only the declared submission/context/proposal/native-call boundaries are counted.
Ordinary full-trace cursors and readers refuse this distinct profile.
"""
import interstellar_mesh as mesh
from regional_contact_trace import ContactTrace, TraceCursor, FORMAT as FULL_TRACE
from regional_contact_trace_shards import TraceShards, verify_shards

FORMAT='RLD-GROUND-SUBMISSION-STAGES-V1'
SHARDS='RLD-FOUR-CLI-SUBMISSION-STAGES-V1'
STAGES=frozenset({'submission_scan_started','submission_input_read','submission_auth_started',
    'submission_retained','submission_retention_failed','submission_duplicate_seen',
    'submission_scan_finished','consensus_tick_started','consensus_tick_finished',
    'consensus_context_observed','source_enqueued','timeout_requested','timeout_retained',
    'timeout_failed','proposal_requested','proposal_retained','proposal_failed',
    'native_call_started','native_call_finished'})


class SubmissionTrace(ContactTrace):
    def __init__(self):
        super().__init__();self.native_calls=0

    def event(self,stage,peer=None,**fields):
        if stage in STAGES:super().event(stage,peer,**fields)
        # Unselected transport stages are outside this explicit profile. They
        # cannot be reported as observed or as a missing complete transport log.

    def snapshot(self):
        value=super().snapshot();value['format']=FORMAT
        return value

    def _reject_safely(self):
        try:self.reject()
        except Exception:self.available=False

    def measure_native(self,action,operation):
        attempt=None
        try:
            with self.lock:
                mesh.require(self.native_calls<2**63-1,'diagnostic call counter exhausted')
                self.native_calls+=1;attempt=self.native_calls
            action=str(action).replace('-','_')
            self.event('native_call_started',attempt=attempt,native_action=action)
        except Exception:
            self._reject_safely()
        succeeded=False
        try:
            result=operation();succeeded=True;return result
        finally:
            try:
                if attempt is not None:self.event('native_call_finished',attempt=attempt,
                    native_action=action,native_success=succeeded)
            except Exception:self._reject_safely()


class SubmissionCursor(TraceCursor):
    def drain(self,value):
        mesh.require(value['format']==FORMAT,'exact narrow diagnostic profile required')
        mesh.require(all(r['stage'] in STAGES for r in value['events']),
                     'unselected stage cannot enter narrow coverage')
        # Reuse the exact bounded counters, clocks, bytes and immutable-row
        # checks only after the explicit narrow format/stage fences above.
        result=super().drain(dict(value,format=FULL_TRACE))
        return dict(result,diagnostic_profile=FORMAT,complete_transport_trace=False)


class SubmissionShards(TraceShards):
    def __init__(self,network,slots,**kwargs):
        super().__init__(network,slots,**kwargs)
        self.cursors={i:SubmissionCursor(network,node) for i,(_,node) in self.slots.items()}

    def _view(self):
        return dict(super()._view(),format=SHARDS)


def verify_submission_shards(path,snapshot,*,network,slots):
    return verify_shards(path,snapshot,network=network,slots=slots,expected_format=SHARDS)
