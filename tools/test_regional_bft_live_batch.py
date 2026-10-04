"""Live batch I/O/refusal boundaries; fake Native grants no crypto qualification."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_transfer as wire
import regional_bft_live_batch as batch


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


if __name__=='__main__':unittest.main()
