"""Selection, unavailable Native status and full-byte retry are separate events.

The frame codec and actual Service tick run; mesh/Native custody and all OS
owners are models. No signing, Node constructors, Native processes or sockets.
"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Service, NativeRefusal
from regional_contact_trace import ContactTrace, TraceCursor
from regional_contact_trace_journal import TraceJournal, verify_journal


class ReceiveTraceTests(unittest.TestCase):
    def service(self, mode):
        service = Service.__new__(Service)
        service.region = 'b'*64
        network, node_id = 'a'*64, 'c'*64
        payload = wire.canonical(dict(format='RLD-REGIONAL-BFT-NETWORK-V2', currency=network,
                                      region=service.region, evidence={},
                                      body={'fixture_only': 'not-a-native-proof'}))
        raw = wire.make_frame('regional-bft', service.region, service.region,
                              mesh.digest(wire.decode_json(payload)), payload)
        packet_id = 'd'*64
        trace = ContactTrace(); trace.bind(network, node_id)
        service.contact_trace = trace
        service.bft_seen = set(); service.bft_individual_retry = False
        service.receive_after = {'novel': None, 'background': None}
        service.progress = {'cursor': 0}; service.miner = None
        service.carriage = None
        service.root = Path('/synthetic-not-opened'); service.path = service.root/'progress.json'
        failure = NativeRefusal('bft-network-inspect-batch', 1,
                                'regional candidate rejected: complete stream already locked')
        receive = Mock(side_effect=failure if mode == 'native-refused' else None)
        service.bft = SimpleNamespace(state={'messages': {}}, receive_many=receive, tick=lambda: {}, failed=False)
        native_status = dict(currency=network, region=service.region, contacts=[])

        def native_call(action):
            if action == 'contact-observation':
                if mode == 'status-unavailable': raise OSError('Native observation unavailable')
                return dict(format='RLD-NATIVE-CONTACT-OBSERVATION-V1',currency=network,region=service.region,
                    status=dict(native_status,source_http_required=False),outgoing=dict(currency=network,
                        region=service.region,offers=[],all_offers_require_native_contact_export_validation=True),
                    ledger_changed=False,signing_authority=False)
            if action == 'contact-outgoing': return {'offers': []}
            raise AssertionError('unexpected Native operation')

        service.native = SimpleNamespace(currency=network, call=native_call)
        service.tcp = SimpleNamespace(tick=lambda: {'errors': []})
        node = SimpleNamespace(id=node_id, network=network, state={'adverts': {}},
                               tick=lambda: {'errors': []},
                               summaries=lambda: {packet_id: dict(destination=node_id, kind='regional-bft',
                                                                export_id=wire.inspect_frame(raw)[0]['export_id'])},
                               receipts=lambda: {packet_id: {'modeled': True}}, transit=lambda _: {'modeled': True})
        service.selection_node = lambda: nullcontext(node)
        return service, trace, receive, packet_id, raw

    def test_real_tick_distinguishes_selection_status_gate_and_native_refusal(self):
        for mode, expected in (
                ('success', ['native_receive_selected', 'native_receive_attempt', 'native_envelope_received']),
                ('status-unavailable', ['native_receive_selected']),
                ('native-refused', ['native_receive_selected', 'native_receive_attempt', 'native_receive_refused']),
                ('bad-receipt', [])):
            with self.subTest(mode=mode):
                service, trace, receive, ident, raw = self.service(mode)
                with patch('regional_contact_node.mesh.transit_check', return_value=({}, raw, [])), \
                        patch('regional_contact_node.mesh.receipt_matches',
                              side_effect=ValueError('invalid receipt') if mode == 'bad-receipt' else None), \
                        patch('regional_contact_node.mesh.atomic'):
                    result = service.tick()
                events = trace.snapshot()['events']
                self.assertEqual([row['stage'] for row in events], expected)
                self.assertTrue(all(row['packet_id'] == ident and
                                    row['envelope_id'] == wire.inspect_frame(raw)[0]['export_id'] for row in events))
                if mode in ('success', 'native-refused'): receive.assert_called_once_with([raw])
                else: receive.assert_not_called()
                self.assertEqual(service.bft_seen, {ident} if mode == 'success' else set())
                self.assertFalse(result['transport_receipt_is_payment_authority'])
                if mode == 'native-refused':
                    self.assertTrue(result['deferred'])
                    self.assertEqual(events[-1]['error_class'], 'NativeRefusal')

    def test_same_original_complete_bytes_retried_before_received_hint(self):
        service, trace, receive, ident, raw = self.service('native-refused')
        errors, rejected, deferred = [], [], []
        service.receive_bft_batch([(ident, raw)], errors, rejected, deferred)
        self.assertNotIn(ident, service.bft_seen)
        receive.side_effect = None
        service.receive_bft_batch([(ident, raw)], [], [], [])
        self.assertEqual([call.args for call in receive.call_args_list], [([raw],), ([raw],)])
        self.assertEqual([row['stage'] for row in trace.snapshot()['events']],
                         ['native_receive_attempt', 'native_receive_refused',
                          'native_receive_attempt', 'native_envelope_received'])

    def test_bad_trace_input_is_explicit_and_never_retains_payload(self):
        _, trace, _, ident, raw = self.service('success')
        trace.native_stage('native_receive_attempt', ident, raw)
        trace.native_stage('native_receive_refused', ident, raw, error_class='NativeRefusal')
        cursor = TraceCursor('a'*64, 'c'*64)
        self.assertTrue(cursor.drain(trace.snapshot())['this_interval_complete'])
        trace.native_stage('native_receive_selected', ident, b'bad-frame')
        trace.native_stage('native_receive_attempt', ident, raw, private_key='never-retain')
        view = trace.snapshot()
        self.assertEqual(view['rejected_events'], 2)
        self.assertFalse(cursor.drain(view)['this_interval_complete'])
        self.assertNotIn('never-retain', str(view))
        self.assertNotIn('not-a-native-proof', str(view))

    def test_actual_new_stage_bytes_round_trip_through_closed_journal(self):
        _, trace, _, ident, raw = self.service('success')
        trace.native_stage('native_receive_selected', ident, raw)
        trace.native_stage('native_receive_attempt', ident, raw)
        trace.native_received(ident, raw)
        slots = {0: (100, 'c'*64), **{i: (100+i, format(i, '064x')) for i in range(1, 4)}}
        with tempfile.TemporaryDirectory(prefix='rld-receive-trace-',
                                         dir=Path(__file__).resolve().parents[1]/'tmp') as directory:
            path = Path(directory)/'events.jsonl'
            journal = TraceJournal('a'*64, slots, deadline=180, path=path)
            try:
                journal.sample(0, dict(process_id=100, contact_trace=trace.snapshot()), now=1)
                for i in range(1, 4):
                    empty = ContactTrace(); empty.bind('a'*64, slots[i][1])
                    journal.sample(i, dict(process_id=100+i, contact_trace=empty.snapshot()), now=1)
            finally:
                journal.close()
            readback = verify_journal(path, journal.snapshot(), network='a'*64, slots=slots)
            self.assertEqual(readback['events'], 3)
            self.assertEqual(readback['through_sequence'], {0: 3, 1: 0, 2: 0, 3: 0})
            self.assertFalse(readback['authority'])


if __name__ == '__main__':
    unittest.main()
