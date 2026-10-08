"""Optional controller counters never substitute for native/custody checks."""
import ast
import copy
from pathlib import Path
import unittest
from types import SimpleNamespace
from regional_bft_sustained_campaign import transport_sample,consensus_sample

class TransportObservationTests(unittest.TestCase):
    def test_actual_selection_lock_unknown_preserves_null_counts_and_diagnostic(self):
        q=dict(transport=dict(progress_observation_available=False,diagnostic='mesh selection lock contention; retained evidence remains pending',tcp=None))
        before=copy.deepcopy(q);r=transport_sample(q)
        self.assertFalse(r['transport_observation_complete'])
        for k in ('active_transport_packets','archived_transport_records','tcp_local_lock_retries','tcp_local_lock_exhaustions'):self.assertIsNone(r[k])
        self.assertIn('lock contention',r['transport_diagnostic']);self.assertEqual(q,before)
    def test_known_counters_and_optional_tcp_are_independently_observed(self):
        for tcp in (None,{},dict(contacts=None),dict(contacts=dict(local_lock_retries=3,local_lock_exhaustions=0))):
            r=transport_sample(dict(transport=dict(active_messages=0,archived_records=32,tcp=tcp)))
            self.assertTrue(r['transport_observation_complete']);self.assertEqual(r['active_transport_packets'],0)
            self.assertEqual(r['tcp_local_lock_retries'],3 if tcp and isinstance(tcp.get('contacts'),dict) else None)
    def test_explicit_unknown_overrides_retained_old_counts(self):
        r=transport_sample(dict(transport=dict(active_messages=9,archived_records=100,progress_observation_available=False)))
        self.assertFalse(r['transport_observation_complete']);self.assertIsNone(r['active_transport_packets'])
    def test_absent_boolean_negative_and_untyped_counters_are_unknown(self):
        for observed in ({},{'transport':None},{'transport':[]},{'transport':{}},{'transport':dict(active_messages=True,archived_records=0)}, {'transport':dict(active_messages=-1,archived_records=2)}, {'transport':dict(active_messages=2,archived_records='3')}):
            r=transport_sample(observed);self.assertFalse(r['transport_observation_complete']);self.assertIsNone(r['active_transport_packets'])
    def test_unknown_transport_sample_still_calls_independent_audit_and_keeps_real_native_height(self):
        tree=ast.parse(Path(__file__).with_name('regional_bft_sustained_campaign.py').read_text())
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='sample')
        namespace=dict(consensus_sample=consensus_sample,transport_sample=transport_sample,time=SimpleNamespace(monotonic=lambda:10))
        exec(compile(ast.Module(body=[method],type_ignores=[]),'<exact-controller-sample>','exec'),namespace)
        q=dict(consensus=dict(height=13,round=2,retained_messages=120),transport=dict(progress_observation_available=False,diagnostic='lock'),errors=['lock'])
        audits=[];c=SimpleNamespace(processes={('earth',1):object()},observation=lambda key:q,samples=[],started=1,audit=lambda phase:audits.append(phase),contact_meters={})
        namespace['sample'](c,'phase');self.assertEqual(audits,['phase'])
        row=c.samples[0]['nodes'][0];self.assertEqual(row['height'],13);self.assertIsNone(row['active_transport_packets']);self.assertFalse(row['transport_observation_complete'])
if __name__=='__main__':unittest.main()
