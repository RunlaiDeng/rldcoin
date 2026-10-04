"""Observation isolation, source pinning, unknowns and retained log failures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import regional_ground_resources as resources


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-resource-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / 'store'
        self.store.mkdir()
        (self.store / 'retained').write_bytes(b'exact complete evidence')
        self.log = self.root / 'samples.jsonl'
        self.binding = dict(source_set_sha256='a'*64, source_files=1,
                            binary_sha256='b'*64, sampler_sha256='c'*64)

    def recorder(self):
        value = resources.Recorder(self.log, self.binding, [],
                                   [resources.Storage('archive', self.store)], 1)
        self.addCleanup(value.close)
        return value

    def source(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'fixture.py').write_bytes(b'pinned bytes')
        rows = [{'path':'fixture.py', 'size_bytes':12,
                 'sha256':hashlib.sha256(b'pinned bytes').hexdigest()}]
        commitment = hashlib.sha256(resources.canonical(rows)).hexdigest()
        manifest = self.root / 'manifest.json'
        manifest.write_bytes(resources.canonical({'files':rows, 'source_set_sha256':commitment}))
        binary = self.root / 'binary'
        binary.write_bytes(b'exact binary')
        return manifest, source, binary, commitment, hashlib.sha256(b'exact binary').hexdigest()

    def test_source_full_bytes_and_expected_binary_are_pinned(self):
        args = self.source()
        binding = resources.source_binding(*args)
        self.assertEqual(binding['source_files'], 1)
        self.assertEqual(binding['source_set_sha256'], args[3])
        args[2].write_bytes(b'changed binary')
        with self.assertRaisesRegex(ValueError, 'binary bytes differ'):
            resources.source_binding(*args)

    def test_changed_source_refuses_even_with_unchanged_manifest(self):
        args = self.source()
        (args[1] / 'fixture.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'source bytes differ'):
            resources.source_binding(*args)

    def test_duplicate_traversal_and_symlink_sources_refuse(self):
        for kind in ('duplicate', 'traversal', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'source'
                source.mkdir()
                path = source / 'file'
                path.write_bytes(b'1')
                row = dict(path='file', size_bytes=1, sha256=hashlib.sha256(b'1').hexdigest())
                if kind == 'traversal':
                    row['path'] = '../file'
                elif kind == 'symlink':
                    path.unlink()
                    path.symlink_to(self.store / 'retained')
                rows = [row, row] if kind == 'duplicate' else [row]
                sha = hashlib.sha256(resources.canonical(rows)).hexdigest()
                manifest = root / 'manifest'
                manifest.write_bytes(resources.canonical(dict(files=rows, source_set_sha256=sha)))
                with self.assertRaises(ValueError):
                    resources.source_binding(manifest, source, path, sha, 'a'*64)

    def test_metadata_sampling_does_not_read_payloads_or_mutate_store(self):
        before = (self.store / 'retained').stat()
        store = resources.Storage('archive', self.store)
        with patch.object(Path, 'open', side_effect=AssertionError('payload must not open')):
            observed = store.sample()
        after = (self.store / 'retained').stat()
        self.assertTrue(observed['available'])
        self.assertEqual(observed['files'], 1)
        self.assertEqual(observed['logical_file_bytes'], before.st_size)
        self.assertEqual((before.st_mtime_ns, before.st_mode, before.st_size),
                         (after.st_mtime_ns, after.st_mode, after.st_size))
        self.assertFalse(observed['atomic_snapshot'])

    def test_storage_missing_replaced_symlink_and_scan_limit_return_unknown(self):
        for kind in ('missing', 'replaced', 'symlink', 'capacity'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'state'
                root.mkdir()
                (root / 'retained').write_bytes(b'1')
                store = resources.Storage('archive', root)
                if kind in ('missing', 'replaced'):
                    root.rename(root.with_name('old'))
                    if kind == 'replaced':
                        root.mkdir()
                elif kind == 'symlink':
                    (root / 'link').symlink_to(self.store)
                with patch.object(resources, 'MAX_ENTRIES', 0 if kind == 'capacity' else 4096):
                    observed = store.sample()
                self.assertFalse(observed['available'])
                self.assertIsNone(observed['files'])
                self.assertIsNone(observed['logical_file_bytes'])

    def test_process_disappearance_and_pid_identity_change_never_report_zero(self):
        first = dict(start='exact start', command_sha256='a'*64, cpu_seconds=3, rss_bytes=100)
        for later in (ValueError('missing'), dict(first, start='another start'),
                      dict(first, command_sha256='b'*64)):
            with self.subTest(later=later), patch.object(resources, 'process_read', side_effect=[first, later]):
                observed = resources.Process('earth0', 123).sample()
                self.assertFalse(observed['available'])
                self.assertIsNone(observed['rss_bytes'])
                self.assertIsNone(observed['cpu_lifetime_seconds'])

    def test_cpu_delta_is_one_core_and_discontinuity_resets_interval(self):
        first = dict(start='s', command_sha256='a'*64, cpu_seconds=3, rss_bytes=100)
        reads = [first, first, dict(first, cpu_seconds=5), ValueError('gone'), dict(first, cpu_seconds=8)]
        with patch.object(resources, 'process_read', side_effect=reads), \
             patch.object(resources.time, 'monotonic', side_effect=[1, 3, 5]):
            process = resources.Process('earth0', 123)
            self.assertIsNone(process.sample()['cpu_one_core_percent'])
            self.assertEqual(process.sample()['cpu_one_core_percent'], 100)
            self.assertFalse(process.sample()['available'])
            self.assertIsNone(process.sample()['cpu_one_core_percent'])

    def test_ps_private_argv_never_appears_in_returned_sample(self):
        result = subprocess.CompletedProcess([], 0, stdout='Sun Oct 4 12:30:00 2026 00:01.25 40 secret/private-key --password private\n')
        with patch.object(resources.subprocess, 'run', return_value=result):
            observed = resources.process_read(123)
        self.assertEqual(observed['cpu_seconds'], 1.25)
        self.assertEqual(observed['rss_bytes'], 40960)
        self.assertNotIn('secret', json.dumps(observed))
        self.assertNotIn('password', json.dumps(observed))

    def test_time_formats_and_nonfinite_cpu_refusal(self):
        self.assertEqual(resources.cpu_seconds('1-02:03:04.5'), 93784.5)
        self.assertEqual(resources.cpu_seconds('12:30'), 750)
        for invalid in ('NaN:00', '1', '-1:00'):
            with self.assertRaises(ValueError):
                resources.cpu_seconds(invalid)

    def test_log_is_exclusive_private_chained_and_has_no_native_authority(self):
        recorder = self.recorder()
        recorder.sample()
        recorder.close()
        lines = self.log.read_bytes().splitlines(keepends=True)
        header, sample = [json.loads(line) for line in lines]
        self.assertEqual(sample['predecessor_sha256'], hashlib.sha256(lines[0]).hexdigest())
        self.assertIsNone(sample['native_value_observation'])
        self.assertFalse(header['native_authority'])
        self.assertFalse(header['measured']['continuous_peaks'])
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            self.recorder()
        self.assertEqual(before, self.log.read_bytes())

    def test_output_inside_observed_state_and_duplicate_labels_refuse(self):
        store = resources.Storage('archive', self.store)
        with self.assertRaisesRegex(ValueError, 'inside observed storage'):
            resources.Recorder(self.store / 'log', self.binding, [], [store], 1)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            resources.Recorder(self.log, self.binding, [], [store, store], 1)
        self.assertFalse(self.log.exists())

    def test_fsync_failure_retains_partial_log_and_never_claims_terminal_success(self):
        recorder = self.recorder()
        with patch.object(resources.os, 'fsync', side_effect=OSError('write failed')):
            with self.assertRaises(OSError):
                recorder.sample()
        recorder.close()
        self.assertTrue(self.log.exists())
        self.assertNotIn(b'observation_completed', self.log.read_bytes())

    def test_record_limit_refuses_without_overwriting_prior_log(self):
        recorder = self.recorder()
        before = self.log.read_bytes()
        with patch.object(resources, 'MAX_RECORDS', 1), self.assertRaisesRegex(ValueError, 'record bound'):
            recorder.sample()
        self.assertEqual(before, self.log.read_bytes())

    def test_sampling_delay_is_explicit_and_missing_telemetry_stays_unknown(self):
        recorder = self.recorder()
        with patch.object(resources.time, 'monotonic', side_effect=[1, 4, 8, 9]):
            recorder.sample()
            recorder.sample()
        lines = [json.loads(line) for line in self.log.read_bytes().splitlines()]
        self.assertTrue(lines[1]['interval_overrun'])
        self.assertEqual(lines[2]['unsampled_gap_seconds'], 4)
        self.assertTrue(lines[2]['interval_overrun'])
        self.assertIsNone(lines[2]['native_value_observation'])

    def test_real_owned_child_process_and_actual_disk_sampling(self):
        process = subprocess.Popen(['sleep', '5'])
        self.addCleanup(lambda: process.wait() if process.poll() is not None else (process.terminate(), process.wait()))
        anchor = resources.Process('owned_test_child', process.pid)
        observed = anchor.sample()
        self.assertTrue(observed['available'])
        self.assertGreater(observed['rss_bytes'], 0)
        process.terminate()
        process.wait()
        self.assertFalse(anchor.sample()['available'])

    def test_optional_child_cpu_binds_helper_and_keeps_unknowns_and_bounds(self):
        from regional_ground_child_cpu import ExitedChildCpu
        first=dict(start='start',command_sha256='a'*64,cpu_seconds=1,rss_bytes=100)
        with patch.object(resources,'process_read',return_value=first):
            process=resources.Process('owned_parent',123)
        recorder=resources.Recorder(self.log,self.binding,[process],[],1,exited_child_cpu=True)
        self.addCleanup(recorder.close)
        unknown=dict(label='owned_parent',available=False,own_plus_exited_children_cpu_lifetime_seconds=None)
        with patch.object(resources,'process_read',return_value=first), \
             patch.object(ExitedChildCpu,'sample',return_value=unknown):
            recorder.sample()
        rows=[json.loads(line) for line in self.log.read_bytes().splitlines()]
        self.assertEqual(rows[0]['format'],resources.CHILD_CPU_FORMAT)
        self.assertEqual(rows[0]['observer_binding']['exited_child_cpu_sha256'],
                         resources.digest(Path(resources.__file__).with_name('regional_ground_child_cpu.py'))[0])
        self.assertFalse(rows[0]['measured']['child_process_tree'])
        self.assertEqual(rows[1]['own_plus_exited_child_cpu'],[unknown])
        before=self.log.read_bytes()
        recorder.processes.append(process)
        with self.assertRaisesRegex(ValueError,'registered sample scope'):recorder.sample()
        self.assertEqual(before,self.log.read_bytes())
        recorder.processes[:]=[resources.Process.__new__(resources.Process)]
        replacement=recorder.processes[0]
        replacement.label='owned_parent';replacement.pid=456;replacement.identity=process.identity;replacement.previous=None
        with patch.object(resources,'process_read',return_value=first), \
             self.assertRaisesRegex(ValueError,'another process anchor'):recorder.sample()
        self.assertEqual(before,self.log.read_bytes())

    def test_default_mode_does_not_load_child_backend_or_change_observation_scope(self):
        recorder=self.recorder()
        recorder.sample()
        rows=[json.loads(line) for line in self.log.read_bytes().splitlines()]
        self.assertEqual(rows[0]['format'],resources.FORMAT)
        self.assertFalse(rows[0]['measured']['own_plus_exited_child_cpu_requested'])
        self.assertNotIn('own_plus_exited_child_cpu',rows[1])
        self.assertEqual(rows[0]['observer_binding'],{})


if __name__ == '__main__':
    unittest.main()
