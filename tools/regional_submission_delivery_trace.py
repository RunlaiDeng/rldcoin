"""Explicit delivery/selection diagnostic, with no Native or value authority.

V1 submission archives remain distinct and unchanged. Each V2 event is a scalar
boundary; complete Native authentication and durable retention still run normally.
"""
import interstellar_mesh as mesh
from regional_contact_trace import ContactTrace, TraceCursor, FORMAT as FULL_TRACE
from regional_contact_trace_shards import TraceShards, verify_shards
from regional_submission_trace import SubmissionTrace, STAGES as V1_STAGES

FORMAT='RLD-GROUND-SUBMISSION-STAGES-V2'
SHARDS='RLD-FOUR-CLI-SUBMISSION-STAGES-V2'
STAGES=V1_STAGES|frozenset({'native_receive_selected','native_receive_attempt',
    'native_receive_refused','native_envelope_received','native_validation_bound',
    'candidate_selection_started','candidate_submission_seen',
    'candidate_command_attempted','candidate_command_refused','candidate_command_selected'})


class DeliveryTrace(SubmissionTrace):
    def event(self,stage,peer=None,**fields):
        if stage in STAGES:ContactTrace.event(self,stage,peer,**fields)

    def snapshot(self):
        return dict(super().snapshot(),format=FORMAT)


class DeliveryCursor(TraceCursor):
    def drain(self,value):
        mesh.require(value['format']==FORMAT,'exact delivery diagnostic profile required')
        mesh.require(all(r['stage'] in STAGES for r in value['events']),
                     'unselected stage cannot enter delivery coverage')
        return dict(super().drain(dict(value,format=FULL_TRACE)),
                    diagnostic_profile=FORMAT,complete_transport_trace=False)


class DeliveryShards(TraceShards):
    def __init__(self,network,slots,**kwargs):
        super().__init__(network,slots,**kwargs)
        self.cursors={i:DeliveryCursor(network,node) for i,(_,node) in self.slots.items()}

    def _view(self):
        return dict(super()._view(),format=SHARDS)


def verify_delivery_shards(path,snapshot,*,network,slots):
    return verify_shards(path,snapshot,network=network,slots=slots,expected_format=SHARDS)


def candidate_event(runtime,stage,context,*,ident=None,command=None):
    """Observe the actual retained-input scan; no cache or selection changes."""
    trace=getattr(runtime,'contact_trace',None)
    if not isinstance(trace,DeliveryTrace):return
    try:
        fields=dict(scope_id=mesh.digest(context),selected=context['parent_height'])
        if ident is not None:fields['envelope_id']=runtime.state['messages'].content(ident)
        if command is not None:fields['command_id']=mesh.digest(command)
        trace.event(stage,**fields)
    except Exception:
        try:trace.reject()
        except Exception:pass
