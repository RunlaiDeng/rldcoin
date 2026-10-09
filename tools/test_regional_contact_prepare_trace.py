"""Exact operation-only selection telemetry; no Native or custody authority."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace, TraceCursor, MAX_EVENT_BYTES
import test_regional_bft_ordered_carriage as ordered_fixture


class PrepareTraceTests(unittest.TestCase):
    def test_all_new_fields_are_bounded_primitives_and_cursor_checks_them(self):
        trace=ContactTrace();trace.bind('a'*64,'b'*64)
        fields=dict(class_step=2**63-1,first_pending=32,first_arrivals=256,
            offered=2,retry_count=4,selected=4,ordered=True,priority=False,newest=True,
            direct_waiting=True,direct_recent=False,direct_prepared=False,direct_selected=False,
            scope_id='d'*64,frame_id='e'*64,direct_id='f'*64,copy_after='1'*64,
            frame_after='2'*64,origin_turn='forwarded_first')
        trace.event('prepare_selection','c'*64,**fields)
        snapshot=trace.snapshot();self.assertEqual(snapshot['rejected_events'],0)
        self.assertLessEqual(len(wire.canonical(snapshot['events'][0])),MAX_EVENT_BYTES)
        cursor=TraceCursor('a'*64,'b'*64)
        self.assertTrue(cursor.drain(snapshot)['this_interval_complete'])
        for bad in (dict(fields,ordered=1),dict(fields,selected=True),
                    dict(fields,direct_id={}),dict(fields,first_pending=2**63)):
            trace.event('prepare_selection','c'*64,**bad)
        self.assertEqual(trace.snapshot()['rejected_events'],4)
        self.assertFalse(cursor.drain(trace.snapshot())['this_interval_complete'])

    def test_selection_and_retained_events_bind_actual_bundle_and_retry(self):
        helper=ordered_fixture.OrderedCarriageTests()
        context,_,_,raws,frames=helper.signed_frames()
        with helper.retained_directory('rld-prepare-trace-') as directory:
            configs=helper.fixture(Path(directory),context['currency'])
            with mesh.Node(configs[0]) as node:
                peer=sorted(node.contacts)[0]
                for n in range(12):
                    raw=wire.make_frame('source-finality','1'*64,'2'*64,
                        wire.hashlib.sha256(str(n).encode()).hexdigest(),b'{"no_value":true}')
                    node.enqueue(raw,peer)
                target=node.enqueue(raws[-1],peer)
                node.set_carriage_priority(mesh.digest(context),frames,ordered_frames=True)
                trace=ContactTrace();trace.bind(context['currency'],node.id);node.contact_trace=trace
                first=node.first_carriage_plan(peer)
                bundle=node.prepare_exchange(peer)
                ids=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
                events=trace.snapshot()['events'];summary=next(x for x in events if x['stage']=='prepare_selection')
                self.assertEqual(summary['direct_id'],target)
                self.assertTrue(summary['direct_waiting']);self.assertFalse(summary['direct_prepared'])
                self.assertEqual(summary['direct_selected'],target in ids)
                self.assertTrue(summary['ordered']);self.assertTrue(summary['priority'])
                self.assertEqual(summary['first_pending'],len(first['pending']))
                self.assertEqual([x['packet_id'] for x in events if x['stage']=='prepare_selected'],list(ids))
                self.assertEqual([x['packet_id'] for x in events if x['stage']=='prepare_retained'],list(ids))
                self.assertEqual(events[0]['stage'],'prepare_start')
                self.assertFalse(node.receipts());self.assertEqual(trace.snapshot()['rejected_events'],0)
                before=copy.deepcopy(node.state)
                positions=copy.deepcopy(mesh._carriage_positions)
                node.prepare_exchange(peer,retry_packet_ids=ids)
                self.assertEqual(node.state,before);self.assertEqual(mesh._carriage_positions,positions)
                summary=[x for x in trace.snapshot()['events'] if x['stage']=='prepare_selection'][-1]
                self.assertEqual(summary['retry_count'],4);self.assertEqual(summary['offered'],0)
                self.assertFalse(summary['ordered']);self.assertNotIn('scope_id',summary)

    def test_fallible_commit_and_diagnostic_failure_never_change_authority(self):
        helper=ordered_fixture.OrderedCarriageTests()
        context,_,_,raws,frames=helper.signed_frames()
        with helper.retained_directory('rld-prepare-refusal-') as directory:
            configs=helper.fixture(Path(directory),context['currency'])
            with mesh.Node(configs[0]) as node:
                peer=sorted(node.contacts)[0];node.enqueue(raws[-1],peer)
                node.set_carriage_priority(mesh.digest(context),frames,ordered_frames=True)
                trace=ContactTrace();trace.bind(context['currency'],node.id);node.contact_trace=trace
                before=node.path.read_bytes();state=copy.deepcopy(node.state)
                with patch.object(mesh,'atomic',side_effect=OSError('preparation refused')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)
                self.assertIn('prepare_selection',[x['stage'] for x in trace.snapshot()['events']])
                self.assertNotIn('prepare_retained',[x['stage'] for x in trace.snapshot()['events']])
                with patch.object(trace,'event',side_effect=OSError('observation refused')):
                    bundle=node.prepare_exchange(peer)
                self.assertTrue(bundle['body']['transits']);self.assertGreater(trace.snapshot()['rejected_events'],0)
                self.assertFalse(node.receipts());node.validate_state()


if __name__=='__main__':unittest.main()
