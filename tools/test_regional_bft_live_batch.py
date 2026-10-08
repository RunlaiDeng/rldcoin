"""Live batch I/O/refusal boundaries; fake Native grants no crypto qualification."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_transfer as wire
import regional_bft_live_batch as batch
from regional_bft_node import ORIGIN_RUNTIME_FORMAT,Runtime
from regional_bft_observation import Observation
import interstellar_mesh as mesh


class FakeNative:
    currency='1'*64
    def __init__(self):self.requests=[];self.change=None
    def call(self,action,flag,name):
        assert action=='bft-network-inspect-batch' and flag=='--file'
        path=Path(name);raw=path.read_bytes();assert not path.stat().st_mode & 0o077
        self.requests.append(raw);entries=wire.decode_json(raw)
        result=dict(format=batch.FORMAT,currency=self.currency,region='2'*64,
            request_sha256=hashlib.sha256(raw).hexdigest(),verified=True,ledger_changed=False,
            signing_authority=False,results=[dict(message_id=hashlib.sha256(wire.canonical(e)).hexdigest(),
                value=None,evidence={'snapshots':[]},epochs=[]) for e in entries])
        return self.change(result,entries) if self.change else result


class LiveBatchBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.native=FakeNative();self.runtime=SimpleNamespace(root=Path(self.temp.name),native=self.native,region='2'*64)
        self.envelopes=[dict(body={'test':n},evidence={'snapshots':[]}) for n in range(4)]
    def test_complete_ordered_request_and_private_file_removed(self):
        rows=batch.inspect(self.runtime,self.envelopes)
        self.assertEqual(wire.decode_json(self.native.requests[0]),self.envelopes)
        self.assertEqual([r['message_id'] for r in rows],[hashlib.sha256(wire.canonical(e)).hexdigest() for e in self.envelopes])
        self.assertEqual(list(self.runtime.root.iterdir()),[])
    def test_exact_expanded_capacity_refusal_splits_before_returning_all_results(self):
        def capacity(result,entries):
            if len(entries)>1:raise ValueError(batch.CAPACITY_REFUSAL)
            return result
        self.native.change=capacity
        rows=batch.inspect(self.runtime,self.envelopes)
        self.assertEqual(len(rows),4)
        self.assertEqual([len(wire.decode_json(raw)) for raw in self.native.requests],[4,2,1,1,2,1,1])
        self.assertEqual(list(self.runtime.root.iterdir()),[])
    def test_invalid_envelope_incident_unknown_binary_never_split_or_fallback(self):
        for reason in ('native rejected: invalid signature','native rejected: pending incident','unknown command'):
            self.native.requests=[]
            def reject(result,entries):raise ValueError(reason)
            self.native.change=reject
            with self.assertRaisesRegex(ValueError,reason):batch.inspect(self.runtime,self.envelopes)
            self.assertEqual(len(self.native.requests),1)
    def test_later_split_failure_returns_no_partial_results(self):
        def reject(result,entries):
            if len(entries)>1:raise ValueError(batch.CAPACITY_REFUSAL)
            if entries[0]['body']['test']==2:raise ValueError('native rejected: invalid later proof')
            return result
        self.native.change=reject
        with self.assertRaisesRegex(ValueError,'invalid later'):batch.inspect(self.runtime,self.envelopes)
        self.assertEqual(list(self.runtime.root.iterdir()),[])
    def test_response_binding_flags_shape_and_bounds_refuse_without_retry(self):
        changes=[{'request_sha256':'0'*64},{'currency':'0'*64},{'region':'0'*64},
            {'verified':1},{'ledger_changed':True},{'signing_authority':True},{'results':[]}]
        for fields in changes:
            self.native.requests=[];self.native.change=lambda r,e:{**r,**fields}
            with self.subTest(fields=fields),self.assertRaises(ValueError):batch.inspect(self.runtime,self.envelopes)
            self.assertEqual(len(self.native.requests),1)
    def test_count_payload_input_rotation_and_fsync_refusals(self):
        for entries in ([],self.envelopes*2):
            with self.assertRaises(ValueError):batch.inspect(self.runtime,entries)
        with patch.object(wire,'MAX_PAYLOAD',5),self.assertRaises(ValueError):batch.inspect(self.runtime,self.envelopes)
        with patch.object(batch.os,'fsync',side_effect=OSError('fsync')):
            with self.assertRaises(OSError):batch.inspect(self.runtime,self.envelopes)
        self.assertEqual(self.native.requests,[])
        budget=2+len(wire.canonical(self.envelopes[:2]))
        with patch.object(batch,'MAX_BYTES',budget+1000):
            # Larger bodies force request rotation below the four-frame bound.
            large=[dict(e,pad='x'*700) for e in self.envelopes]
            self.assertEqual(len(batch.inspect(self.runtime,large)),4)
        self.assertEqual([len(wire.decode_json(r)) for r in self.native.requests],[1,1,1,1])


class OriginReceiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.calls=[];self.change=None
        self.runtime=SimpleNamespace(root=Path(self.temp.name),region='2'*64,
            format=ORIGIN_RUNTIME_FORMAT,joint=None,native=self)
        self.currency='1'*64
        self.envelopes=[dict(format=batch.ORIGIN_NETWORK,currency=self.currency,
            region=self.runtime.region,origins=[],evidence={'snapshots':[]},
            body={'Submission':[n]}) for n in range(4)]
    def call(self,action,*args):
        self.calls.append(action)
        if action=='history-head':return dict(currency=self.currency,region=self.runtime.region,history_head='3'*64)
        self.assertEqual(action,'bft-origin-network-receive-batch')
        self.assertEqual(args[0],'--file');self.assertEqual(args[2:4],('--expected-head','3'*64))
        path=Path(args[1]);raw=path.read_bytes();self.assertFalse(path.stat().st_mode & 0o077)
        entries=wire.decode_json(raw)
        context=dict(currency=self.currency,region=self.runtime.region,epoch='4'*64,previous=None,
            parent_height=0,parent_block=self.runtime.region,parent_state='5'*64)
        result=dict(format=batch.RECEIVE_FORMAT,currency=self.currency,region=self.runtime.region,
            request_sha256=hashlib.sha256(raw).hexdigest(),history_head='6'*64,context=context,
            verified=True,fixture_only=True,signing_authority=False,results=[
                dict(input_sha256=hashlib.sha256(wire.canonical(e)).hexdigest(),checked=dict(
                    message_id='7'*64,value=None,evidence={'snapshots':[]},epochs=[])) for e in entries])
        return self.change(result) if self.change else result
    def test_single_head_and_pinned_receive_order_and_no_private_file_residue(self):
        rows,context=batch.receive_origin(self.runtime,self.envelopes)
        self.assertEqual(len(rows),4);self.assertEqual(context['parent_height'],0)
        self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])
        self.assertEqual(list(self.runtime.root.iterdir()),[])
    def test_current_runtime_selects_one_native_receive_before_retaining_any_body(self):
        self.runtime.state={'messages':{}}
        self.runtime.observation=Observation()
        retained=[]
        self.runtime.observe_origin_conflicts=lambda envelope:self.fail('current Runtime fell back to per-envelope conflict/replay')
        self.runtime._observe_context=lambda context:retained.append(('context',context))
        self.runtime._retain_checked=lambda envelope,verified,sync:retained.append(('retain',envelope,sync))
        raws=[wire.make_frame('regional-bft',self.runtime.region,self.runtime.region,
            mesh.digest(e),wire.canonical(e)) for e in self.envelopes]
        Runtime.receive_many(self.runtime,raws)
        self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])
        self.assertEqual([x[0] for x in retained],['context']+['retain']*4)
        self.assertEqual([x[1] for x in retained[1:]],self.envelopes)
        self.assertTrue(all(x[2] is False for x in retained[1:]))
    def test_old_runtime_versions_cannot_select_current_composed_receive(self):
        for version in ('RLD-REGIONAL-BFT-ORIGIN-NODE-V2','RLD-REGIONAL-BFT-ORIGIN-NODE-V3',
                        'RLD-REGIONAL-BFT-ORIGIN-NODE-V4','RLD-REGIONAL-BFT-ORIGIN-NODE-V5',
                        'RLD-REGIONAL-BFT-NODE-V1'):
            self.runtime.format=version
            self.assertFalse(batch.supported(self.runtime,self.envelopes))
            with self.assertRaises(ValueError):batch.receive_origin(self.runtime,self.envelopes)
        self.assertEqual(self.calls,[])
    def test_wrong_response_order_domain_flags_context_and_head_never_fallback(self):
        changes=[lambda r:{**r,'results':r['results'][::-1]},lambda r:{**r,'results':r['results'][:-1]},
            lambda r:{**r,'request_sha256':'0'*64},lambda r:{**r,'history_head':'wrong'},
            lambda r:{**r,'currency':'0'*64},lambda r:{**r,'verified':1},
            lambda r:{**r,'signing_authority':True},lambda r:{**r,'fixture_only':False},
            lambda r:{**r,'context':{**r['context'],'parent_height':True}},
            lambda r:{**r,'context':{**r['context'],'region':'0'*64}}]
        for change in changes:
            self.change=change;self.calls=[]
            with self.assertRaises(ValueError):batch.receive_origin(self.runtime,self.envelopes)
            self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])
            self.assertEqual(list(self.runtime.root.iterdir()),[])
    def test_mutation_refusal_response_loss_and_fsync_never_split_or_fallback(self):
        for error in (ValueError(batch.CAPACITY_REFUSAL),ValueError('invalid later'),OSError('response lost')):
            def reject(result):raise error
            self.change=reject;self.calls=[]
            with self.assertRaises(type(error)):batch.receive_origin(self.runtime,self.envelopes)
            self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])
        self.calls=[]
        with patch.object(batch.os,'fsync',side_effect=OSError('write failed')),self.assertRaises(OSError):
            batch.receive_origin(self.runtime,self.envelopes)
        self.assertEqual(self.calls,['history-head'])
    def test_unsupported_expansion_legacy_joint_capacity_and_count_do_not_call_native(self):
        for bad in ([],self.envelopes*2,[dict(self.envelopes[0],format='legacy')],
                    [dict(self.envelopes[0],evidence={'snapshots':[{}]*65})],
                    [dict(self.envelopes[0],evidence={'snapshots':[], 'extra':True})],
                    [dict(self.envelopes[0],body={'EpochSigned':{}})]):
            with self.assertRaises(ValueError):batch.receive_origin(self.runtime,bad)
        self.runtime.joint=object()
        self.assertFalse(batch.supported(self.runtime,self.envelopes));self.runtime.joint=None
        with patch.object(batch,'MAX_BYTES',1):self.assertFalse(batch.supported(self.runtime,self.envelopes))
        with patch.object(wire,'MAX_PAYLOAD',1):self.assertFalse(batch.supported(self.runtime,self.envelopes))
        self.assertEqual(self.calls,[])

    def test_nonempty_carried_proofs_preserve_exact_input_and_native_expanded_rows(self):
        carried={'prefix':{'checkpoint':'8'*64,'blocks':1},'snapshot':{'model_only':True}}
        self.envelopes[0]['evidence']['snapshots']=[carried]
        self.assertTrue(batch.supported(self.runtime,self.envelopes))
        expanded={'model_native_authenticated_complete_snapshot':True}
        self.change=lambda r:{**r,'results':[{**row,'checked':{**row['checked'],
            'evidence':{'snapshots':[expanded]}}} for row in r['results']]}
        rows,_=batch.receive_origin(self.runtime,self.envelopes)
        self.assertEqual(rows[0]['evidence']['snapshots'],[expanded])
        self.assertEqual(self.envelopes[0]['evidence']['snapshots'],[carried])
        self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])

    def test_nonempty_expansion_epoch_capacity_and_lost_response_never_split_or_fallback(self):
        self.envelopes[0]['evidence']['snapshots']=[{'model_only':True}]
        for change in [
            lambda r:{**r,'results':[{**row,'checked':{**row['checked'],
                'evidence':{'snapshots':[{}]*65}}} for row in r['results']]},
            lambda r:{**r,'results':[{**row,'checked':{**row['checked'],'epochs':[{}]}}
                                   for row in r['results']]},
            lambda r:{**r,'padding':'x'*(batch.MAX_BYTES+1)},
        ]:
            self.change=change;self.calls=[]
            with self.assertRaises(ValueError):batch.receive_origin(self.runtime,self.envelopes)
            self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])
            self.assertEqual(list(self.runtime.root.iterdir()),[])
        def reject(result):raise OSError('mutating complete response lost')
        self.change=reject;self.calls=[]
        with self.assertRaises(OSError):batch.receive_origin(self.runtime,self.envelopes)
        self.assertEqual(self.calls,['history-head','bft-origin-network-receive-batch'])


if __name__=='__main__':unittest.main()
