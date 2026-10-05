"""Actual bounded file writes versus the retained lifetime-row counterexample."""
import hashlib
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import interstellar_transfer as wire
from regional_contact_trace import ContactTrace, MAX_EVENTS
from regional_contact_trace_journal import TraceJournal, verify_journal
from regional_contact_trace_window import TraceWindow


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-trace-journal-', dir=Path(__file__).resolve().parents[1] / 'tmp')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'events.jsonl'
        self.network = 'a' * 64
        self.slots = {i: (100+i, format(i+1, '064x')) for i in range(4)}
        self.traces = {}
        for i, (_, node) in self.slots.items():
            trace = ContactTrace(); trace.bind(self.network, node)
            self.traces[i] = trace
        self.journal = TraceJournal(self.network, self.slots, deadline=180, path=self.path)
        self.addCleanup(self.journal.close)

    def status(self, slot):
        return dict(process_id=self.slots[slot][0], contact_trace=self.traces[slot].snapshot(),
                    native_observation={'private_key': 'never-retain', 'height': 999})

    def sample(self, slot):
        return self.journal.sample(slot, self.status(slot), now=1)

    def test_same_8193_complete_events_refuse_v1_and_persist_exactly_in_new_profile(self):
        old = TraceWindow(self.network, self.slots, deadline=180)
        expected = []
        for offset in range(0, 8193, MAX_EVENTS):
            slot = (offset // MAX_EVENTS) % 4
            for _ in range(min(MAX_EVENTS, 8193-offset)):
                self.traces[slot].event('contact_start', attempt=offset)
            status = self.status(slot)
            if offset < 8192:
                old.sample(slot, status, now=1)
            else:
                with self.assertRaisesRegex(ValueError, 'event capacity'):
                    old.sample(slot, status, now=1)
            delta = self.journal.sample(slot, status, now=1)
            expected.extend(dict(slot=slot, **row) for row in delta['events'])
            self.assertEqual(self.journal.events, [])
        self.journal.close()
        raw = self.path.read_bytes()
        actual = [wire.decode_json(row) for row in raw.splitlines()]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 8193)
        self.assertTrue(old.failed)
        view = self.journal.snapshot()
        self.assertFalse(view['failed'])
        self.assertTrue(all(view['intervals_complete'].values()))
        self.assertTrue(view['all_four_streams_observed'])
        self.assertEqual(view['canonical_event_bytes'], len(wire.canonical(actual)))
        self.assertEqual(view['journal_bytes'], len(raw))
        self.assertEqual(view['journal_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn(b'never-retain', raw)
        self.assertFalse(view['authority'])
        checked = verify_journal(self.path, view, network=self.network, slots=self.slots)
        self.assertEqual(checked['events'], 8193)
        self.assertTrue(checked['complete_collected_prefix'])
        self.assertFalse(checked['native_ledger_authority'])

    def test_same_aggregate_byte_bound_refuses_across_individually_small_batches(self):
        self.traces[0].event('contact_start')
        self.sample(0)
        first = self.path.read_bytes()
        self.traces[0].event('contact_start')
        with patch('regional_contact_trace_journal.MAX_WINDOW_BYTES', self.journal.canonical_bytes):
            with self.assertRaisesRegex(ValueError, 'byte capacity'):
                self.sample(0)
        self.assertEqual(self.path.read_bytes(), first)
        self.assertTrue(self.journal.failed)
        with self.assertRaisesRegex(ValueError, 'cannot resume'):
            self.sample(0)

    def test_partial_write_and_fsync_refusal_never_claim_complete_persistence(self):
        self.traces[0].event('contact_start')
        write = os.write
        with patch('regional_contact_trace_journal.os.write',
                   side_effect=lambda fd, data: write(fd, data[:7])):
            self.sample(0)
        self.assertEqual(self.journal.persisted_events, 1)
        self.traces[0].event('request_sent', nonce='d'*64)
        with patch('regional_contact_trace_journal.os.fsync', side_effect=OSError('diagnostic disk')):
            with self.assertRaises(OSError):
                self.sample(0)
        view = self.journal.snapshot()
        self.assertTrue(view['failed'])
        self.assertEqual(view['persisted_events'], 1)
        self.assertGreater(self.path.stat().st_size, view['journal_bytes'])
        with self.assertRaisesRegex(ValueError, 'cannot resume'):
            self.sample(0)

    def test_zero_progress_write_refuses(self):
        self.traces[0].event('contact_start')
        with patch('regional_contact_trace_journal.os.write', return_value=0):
            with self.assertRaisesRegex(ValueError, 'no progress'):
                self.sample(0)
        self.assertTrue(self.journal.failed)
        self.assertEqual(self.journal.persisted_events, 0)

    def test_existing_file_and_symlink_never_overwrite_old_trace(self):
        original = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            TraceJournal(self.network, self.slots, deadline=180, path=self.path)
        link = self.path.parent / 'link'
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            TraceJournal(self.network, self.slots, deadline=180, path=link)
        self.assertEqual(self.path.read_bytes(), original)

    def test_missing_gapped_and_duplicate_samples_are_never_repaired_by_disk(self):
        self.journal.sample(0, None, now=1)
        for _ in range(MAX_EVENTS+1):
            self.traces[0].event('contact_start')
        delta = self.sample(0)
        self.assertFalse(delta['this_interval_complete'])
        raw = self.path.read_bytes()
        self.sample(0)
        self.assertEqual(self.path.read_bytes(), raw)
        view = self.journal.snapshot()
        self.assertEqual(view['unknown'][0], 1)
        self.assertFalse(view['intervals_complete'][0])

    def test_closed_deadline_and_changed_owner_refuse(self):
        for mode in ('deadline', 'owner', 'closed'):
            path = self.path.parent / mode
            journal = TraceJournal(self.network, self.slots, deadline=180, path=path)
            try:
                status = self.status(0)
                now = 1
                if mode == 'deadline': now = 180
                if mode == 'owner': status['process_id'] = 999
                if mode == 'closed': journal.close()
                with self.assertRaises(ValueError):
                    journal.sample(0, status, now=now)
                self.assertEqual(journal.persisted_events, 0)
            finally:
                journal.close()

    def test_controller_hook_collects_actual_status_files_with_same_owner_validation(self):
        transport = []
        for i in range(4):
            directory = self.path.parent / str(i)
            directory.mkdir()
            self.traces[i].event('request_sent', nonce='d'*64)
            wire.write_new(directory / 'regional-contact-status.json', wire.canonical(self.status(i)))
            transport.append({'state': str(directory)})
        controller = SimpleNamespace(
            processes={('proxima', i): SimpleNamespace(pid=100+i, poll=lambda: None)
                       for i in range(4)},
            pins=[{'node_id': self.slots[i][1]} for i in range(4)],
            currency=self.network, deadline=180, transport=transport, remaining=lambda: 1)
        journal = TraceJournal.attach(controller, path=self.path.parent / 'hook.jsonl')
        try:
            with patch('regional_contact_trace_window.time.monotonic', return_value=1):
                journal.collect(controller)
            self.assertEqual(journal.persisted_events, 4)
            self.assertTrue(journal.snapshot()['all_four_streams_observed'])
            controller.processes['proxima', 0].poll = lambda: 1
            with self.assertRaisesRegex(ValueError, 'producer differs'):
                journal.collect(controller)
            self.assertTrue(journal.failed)
        finally:
            journal.close()

    def closed_four(self):
        for i in range(4):
            self.traces[i].event('contact_start')
            self.sample(i)
        self.journal.close()
        return self.journal.snapshot()

    def test_readback_requires_external_scope_owners_closed_success_and_original_bound(self):
        view = self.closed_four()
        for field, value in (('network', 'b'*64), ('closed', False), ('failed', True),
                             ('authority', True), ('canonical_byte_limit', 99999999),
                             ('slots', {i: (500+i, self.slots[i][1]) for i in range(4)})):
            bad = copy.deepcopy(view); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_journal(self.path, bad, network=self.network, slots=self.slots)
        loaded = wire.decode_json(wire.canonical(view))
        self.assertEqual(verify_journal(self.path, loaded, network=self.network,
                                       slots=self.slots)['events'], 4)

    def test_rehashed_missing_duplicate_reordered_or_noncanonical_rows_still_refuse(self):
        view = self.closed_four()
        original = self.path.read_bytes()
        rows = original.splitlines(keepends=True)
        # A claimant can recompute a diagnostic hash; continuity must separately
        # refuse malformed streams rather than granting authority from the hash.
        for mode in ('missing', 'removed-entire-stream', 'duplicate', 'wrong-sequence', 'noncanonical', 'partial'):
            changed = list(rows)
            if mode == 'missing':
                # Preserve a higher per-slot sequence after dropping its start.
                value = wire.decode_json(changed[0]); value['sequence'] = 2
                changed[0] = wire.canonical(value)+b'\n'
            if mode == 'removed-entire-stream': del changed[0]
            if mode == 'duplicate': changed.append(changed[0])
            if mode == 'wrong-sequence':
                value = wire.decode_json(changed[0]); value['sequence'] = True
                changed[0] = wire.canonical(value)+b'\n'
            if mode == 'noncanonical': changed[0] = b' '+changed[0]
            if mode == 'partial': changed[-1] = changed[-1][:-1]
            data = b''.join(changed); self.path.write_bytes(data)
            bad = copy.deepcopy(view)
            bad.update(journal_sha256=hashlib.sha256(data).hexdigest(), journal_bytes=len(data),
                       canonical_event_bytes=len(data)+1, persisted_events=len(changed))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify_journal(self.path, bad, network=self.network, slots=self.slots)
        self.path.write_bytes(original)

    def test_missing_samples_remain_unknown_and_a_declared_gap_refuses_complete_readback(self):
        self.journal.sample(0, None, now=1)
        view = self.closed_four()
        result = verify_journal(self.path, view, network=self.network, slots=self.slots)
        self.assertEqual(result['missing_status_samples'][0], 1)
        view['intervals_complete'][0] = False
        with self.assertRaisesRegex(ValueError, 'gaps cannot be repaired'):
            verify_journal(self.path, view, network=self.network, slots=self.slots)


if __name__ == '__main__':
    unittest.main()
