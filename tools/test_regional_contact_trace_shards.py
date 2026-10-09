"""Fresh synthetic diagnostic events only; no Native, socket, keys or value."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace, TracePublisher, MAX_EVENTS
import regional_contact_trace_shards as shards
from regional_contact_trace_window import MAX_WINDOW_BYTES
from regional_contact_trace_journal import TraceJournal


class ShardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-diagnostic-shards-',
                                                dir=Path(__file__).resolve().parents[1] / 'tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = 'a' * 64
        self.slots = {i: (100 + i, format(i + 1, '064x')) for i in range(4)}
        self.traces = {}
        for i, (_, node) in self.slots.items():
            trace = ContactTrace(); trace.bind(self.network, node); self.traces[i] = trace
        self.serial = 0

    def journal(self):
        path = self.root / f'journal-{self.serial}'; self.serial += 1
        result = shards.TraceShards(self.network, self.slots, deadline=180, path=path)
        self.addCleanup(result.close)
        return result

    def sample(self, journal, slot, count=1):
        for _ in range(count):
            self.traces[slot].event('outgoing_prepared', 'b' * 64,
                                    packet_id='c' * 64, frame_id='d' * 64,
                                    envelope_id='e' * 64, exchange_id='f' * 64)
        return journal.sample(slot, dict(process_id=self.slots[slot][0],
                              contact_trace=self.traces[slot].snapshot()), now=1)

    def sealed(self):
        result = self.journal()
        for i in range(4): self.sample(result, i, 2)
        result.close()
        return result, result.snapshot()

    def verify(self, journal, snapshot=None):
        return shards.verify_shards(journal.path, snapshot or journal.snapshot(),
                                    network=self.network, slots=self.slots)

    def test_actual_original_bound_crossing_retains_every_row_and_cold_streams(self):
        journal = self.journal()
        expected = hashlib.sha256(); count = 0
        tracemalloc.start()
        try:
            for turn in range(220):
                for i in range(4):
                    delta = self.sample(journal, i, 32)
                    for row in delta['events']:
                        expected.update(wire.canonical(dict(slot=i, **row)) + b'\n')
                    count += 32
            writer_peak = tracemalloc.get_traced_memory()[1]
        finally: tracemalloc.stop()
        journal.close(); snapshot = journal.snapshot()
        self.assertGreater(snapshot['journal_bytes'], MAX_WINDOW_BYTES)
        self.assertEqual(snapshot['persisted_events'], count)
        self.assertEqual(snapshot['journal_sha256'], expected.hexdigest())
        self.assertLessEqual(snapshot['maximum_resident_rows'], MAX_EVENTS)
        self.assertLess(writer_peak, 2 * 1024 * 1024)
        self.assertGreaterEqual(len(snapshot['parts']), 2)
        self.assertLessEqual(len(snapshot['parts']), 4)
        self.assertTrue(all(p['bytes'] <= MAX_WINDOW_BYTES for p in snapshot['parts']))
        tracemalloc.start()
        try:
            result = self.verify(journal, copy.deepcopy(snapshot))
            reader_peak = tracemalloc.get_traced_memory()[1]
        finally: tracemalloc.stop()
        self.assertLess(reader_peak, 2 * 1024 * 1024)
        self.assertEqual(result['events'], count)
        self.assertTrue(result['complete_collected_prefix'])
        self.assertFalse(result['native_ledger_authority'])
        self.assertEqual(MAX_WINDOW_BYTES, 8 * 1024 * 1024)
        print('diagnostic-shards', dict(events=count, bytes=snapshot['journal_bytes'],
                                        shards=len(snapshot['parts']), writer_peak=writer_peak,
                                        reader_peak=reader_peak), flush=True)

    def test_old_journal_still_refuses_original_aggregate_bound(self):
        path = self.root / 'old.jsonl'
        old = TraceJournal(self.network, self.slots, deadline=180, path=path)
        self.addCleanup(old.close)
        old.canonical_bytes = MAX_WINDOW_BYTES - 1
        with self.assertRaisesRegex(ValueError, 'byte capacity'): self.sample(old, 0)
        self.assertTrue(old.failed)

    def test_finite_shard_capacity_refuses_whole_batch_without_losing_old_files(self):
        journal = self.journal()
        with patch.object(shards, 'MAX_WINDOW_BYTES', 512), patch.object(shards, 'MAX_DIAGNOSTIC_BYTES', 2048):
            for i in range(4): self.sample(journal, i)
            before = {p.name:p.read_bytes() for p in journal.path.iterdir()}
            with self.assertRaisesRegex(ValueError, 'capacity'): self.sample(journal, 0)
            self.assertEqual({p.name:p.read_bytes() for p in journal.path.iterdir()}, before)
            self.assertTrue(journal.failed)
            with self.assertRaisesRegex(ValueError, 'cannot resume'): journal.sample(0, None, now=1)
        journal.close()
        with self.assertRaises(ValueError): self.verify(journal)

    def test_partial_write_and_fsync_failure_never_acknowledge_batch(self):
        for mode in ('partial', 'fsync', 'zero'):
            journal = self.journal(); real = os.write; calls = []
            def write(fd, data):
                calls.append(len(data))
                if mode == 'zero': return 0
                if len(calls) == 1: return real(fd, data[:7])
                raise OSError('injected diagnostic write failure')
            with patch.object(shards.os, 'fsync', side_effect=OSError('injected fsync')) if mode == 'fsync' else patch.object(shards.os, 'write', side_effect=write):
                with self.assertRaises((OSError, ValueError)): self.sample(journal, 0)
            self.assertTrue(journal.failed)
            self.assertEqual(journal.persisted_events, 0)
            self.assertEqual(journal.journal_bytes, 0)
            self.assertTrue(list(journal.path.iterdir()))
            journal.close()
            with self.assertRaises(ValueError): self.verify(journal)

    def test_corrupt_truncated_and_missing_files_refuse_exact_external_seal(self):
        journal, snapshot = self.sealed()
        path = journal.path / 'part-00.jsonl'; original = path.read_bytes()
        for bad in (original[:-1], original.replace(b'cccc', b'0000', 1)):
            path.write_bytes(bad)
            with self.assertRaises(ValueError): self.verify(journal, snapshot)
        path.write_bytes(original); path.rename(journal.path / 'unlisted.jsonl')
        with self.assertRaises(ValueError): self.verify(journal, snapshot)
        (journal.path / 'unlisted.jsonl').rename(path)
        self.verify(journal, snapshot)
        extra = journal.path / 'residue'; extra.write_bytes(b'preserve')
        with self.assertRaises(ValueError): self.verify(journal, snapshot)
        self.assertEqual(extra.read_bytes(), b'preserve')

    def test_rehashed_duplicate_row_cannot_become_contiguous_evidence(self):
        journal, snapshot = self.sealed(); path = journal.path / 'part-00.jsonl'
        rows = path.read_bytes().splitlines(keepends=True); rows[1] = rows[0]
        changed = b''.join(rows); path.write_bytes(changed)
        snapshot['parts'][0]['sha256'] = snapshot['journal_sha256'] = hashlib.sha256(changed).hexdigest()
        snapshot['parts'][0]['bytes'] = snapshot['journal_bytes'] = len(changed)
        snapshot['canonical_event_bytes'] = len(changed) + 1
        mesh.atomic(journal.path / 'manifest.json', {k:v for k,v in snapshot.items() if k != 'manifest_sha256'})
        snapshot['manifest_sha256'] = hashlib.sha256((journal.path / 'manifest.json').read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'sequence'): self.verify(journal, snapshot)

    def test_existing_interrupted_path_symlink_and_changed_owner_refuse(self):
        journal = self.journal(); before = list(journal.path.iterdir())
        with self.assertRaises(FileExistsError): shards.TraceShards(self.network, self.slots, deadline=180, path=journal.path)
        self.assertEqual(list(journal.path.iterdir()), before)
        link = self.root / 'link'; link.symlink_to(journal.path, target_is_directory=True)
        with self.assertRaises(ValueError): shards.TraceShards(self.network, self.slots, deadline=180, path=link)
        self.traces[0].event('contact_start')
        with self.assertRaisesRegex(ValueError, 'PID'): journal.sample(0, dict(process_id=999, contact_trace=self.traces[0].snapshot()), now=1)
        self.assertTrue(journal.failed)

    def test_gap_unknown_and_manifest_publication_failure_cannot_pass(self):
        journal = self.journal()
        journal.sample(0, None, now=1)
        self.assertEqual(journal.unknown[0], 1)
        for _ in range(MAX_EVENTS + 2): self.traces[0].event('contact_start')
        journal.sample(0, dict(process_id=100, contact_trace=self.traces[0].snapshot()), now=1)
        for i in (1,2,3): self.sample(journal, i)
        journal.close()
        with self.assertRaisesRegex(ValueError, 'gaps'): self.verify(journal)
        second = self.journal()
        with patch.object(shards.mesh, 'atomic', side_effect=OSError('seal publication refused')):
            with self.assertRaises(OSError): second.close()
        self.assertTrue(second.failed); self.assertIsNone(second.manifest_sha256)

    def test_independent_reader_uses_existing_pid_bound_publications(self):
        publishers=[];transport=[]
        for i in range(4):
            directory=self.root / f'producer-{i}';directory.mkdir()
            with patch('regional_contact_trace.os.getpid', return_value=100+i):
                publisher=TracePublisher(self.traces[i],directory/'regional-contact-trace-status.json')
            self.addCleanup(publisher.close);publishers.append(publisher);transport.append(dict(state=str(directory)))
        controller=SimpleNamespace(processes={('proxima',i):SimpleNamespace(pid=100+i,poll=lambda:None) for i in range(4)},
                                   pins=[dict(node_id=self.slots[i][1]) for i in range(4)],currency=self.network,
                                   deadline=time.monotonic()+10,transport=transport)
        journal=shards.TraceShards.attach(controller,path=self.root/'independent');journal.stop_collection()
        for i in range(4):
            self.traces[i].event('contact_start');publishers[i].publish()
        journal.read_once();journal.close()
        self.assertEqual(self.verify(journal)['events'],4)


if __name__ == '__main__': unittest.main()
