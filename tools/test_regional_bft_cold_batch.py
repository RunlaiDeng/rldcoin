"""Cold stream/response boundary tests; fake Native is not crypto qualification."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_cold_batch as batch
from regional_bft_retention import Messages


class FakeNative:
    currency='1'*64
    def __init__(self):self.requests=[];self.change=None
    def call(self, action, flag, name):
        if action!='bft-network-check-batch' or flag!='--file':raise AssertionError('cold-only Native query')
        path=Path(name);raw=path.read_bytes();self.requests.append(raw)
        assert not path.stat().st_mode & 0o077
        entries=wire.decode_json(raw)
        assert 0<len(entries)<=4 and len(raw)<=8*1024*1024
        result=dict(format=batch.FORMAT,currency=self.currency,region='2'*64,
                    request_sha256=hashlib.sha256(raw).hexdigest(),results=[
                        dict(message_id=mesh.digest(e['body']),value=None) for e in entries],
                    verified=True,ledger_changed=False,signing_authority=False)
        return self.change(result) if self.change else result


class ColdBatchBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.native=FakeNative();self.runtime=SimpleNamespace(root=Path(self.temp.name),native=self.native,
            region='2'*64,state={'messages':Messages()})
    def messages(self, count, size=0):
        messages=Messages()
        for n in range(count):
            e=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency='1'*64,region='2'*64,
                   body={'cold_boundary_fixture':n},evidence={'snapshots':[{'fixture':'x'*size}] if size else []})
            messages=messages.append(mesh.digest(e['body']),e,None,n%2==0)
        self.runtime.state['messages']=messages
        return {i:messages.payload(i) for i in messages}
    def test_streamed_ordered_complete_bytes_and_no_mutable_message_cache(self):
        before=self.messages(10)
        with patch.object(Messages,'__getitem__',side_effect=AssertionError('no decoded message cache')):
            batch.check_retained(self.runtime)
        self.assertEqual([len(wire.decode_json(r)) for r in self.native.requests],[4,4,2])
        carried=[wire.canonical(e) for raw in self.native.requests for e in wire.decode_json(raw)]
        self.assertEqual(carried,list(before.values()))
        self.assertEqual({i:self.runtime.state['messages'].payload(i) for i in before},before)
        self.assertFalse(list(Path(self.temp.name).iterdir()))
    def test_whole_envelope_input_budget_rotates_before_count_limit(self):
        before=self.messages(5,1500)
        with patch.object(batch,'MAX_INPUT',4096):batch.check_retained(self.runtime)
        self.assertEqual([len(wire.decode_json(r)) for r in self.native.requests],[2,2,1])
        self.assertTrue(all(len(r)<=4096 for r in self.native.requests))
        self.assertEqual({i:self.runtime.state['messages'].payload(i) for i in before},before)
    def test_bad_request_currency_region_flags_or_result_count_refuses_without_fallback(self):
        self.messages(2)
        changes=[lambda r:{**r,'request_sha256':'0'*64},lambda r:{**r,'currency':'f'*64},
                 lambda r:{**r,'region':'f'*64},lambda r:{**r,'verified':1},
                 lambda r:{**r,'ledger_changed':True},lambda r:{**r,'signing_authority':True},
                 lambda r:{**r,'results':r['results'][:-1]}]
        for change in changes:
            self.native.change=change
            with self.subTest(change=changes.index(change)),self.assertRaises(ValueError):
                batch.check_retained(self.runtime)
        self.assertEqual(len(self.native.requests),len(changes))
    def test_later_native_refusal_stops_before_recovery_signing_or_following_batches(self):
        before=self.messages(10)
        def refuse(result):
            if len(self.native.requests)==2:raise ValueError('actual Native refusal')
            return result
        self.native.change=refuse
        with self.assertRaisesRegex(ValueError,'Native refusal'):batch.check_retained(self.runtime)
        self.assertEqual(len(self.native.requests),2)
        self.assertEqual({i:self.runtime.state['messages'].payload(i) for i in before},before)
        self.assertFalse(list(Path(self.temp.name).iterdir()))
    def test_wrong_retained_value_and_bad_result_shape_refuse(self):
        self.messages(1)
        for change in (lambda r:{**r,'results':[{'message_id':'f'*64,'value':'f'*64}]},
                       lambda r:{**r,'results':[{'message_id':'f'*64,'value':None,'authority':True}]}):
            self.native.change=change
            with self.assertRaises(ValueError):batch.check_retained(self.runtime)
    def test_private_request_fsync_failure_never_calls_native(self):
        before=self.messages(1)
        with patch.object(batch.os,'fsync',side_effect=OSError('request fsync failed')):
            with self.assertRaises(OSError):batch.check_retained(self.runtime)
        self.assertEqual(self.native.requests,[])
        self.assertEqual(self.runtime.state['messages'].payload(next(iter(before))),next(iter(before.values())))
    def test_empty_retained_table_makes_no_native_query(self):
        batch.check_retained(self.runtime)
        self.assertEqual(self.native.requests,[])


if __name__=='__main__':unittest.main()
