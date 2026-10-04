"""Actual syscall behavior and telemetry failures cannot relax persistence."""
import os
import tempfile
import unittest
from unittest.mock import patch

from regional_ground_fsync import FsyncMeter


class FsyncTests(unittest.TestCase):
    def test_real_file_and_directory_sync_restore_original_hook(self):
        original=os.fsync
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryFile(dir=root) as stream:
            stream.write(b'ground fixture');stream.flush()
            directory=os.open(root,os.O_RDONLY)
            try:
                meter=FsyncMeter()
                with meter.installed():
                    os.fsync(stream.fileno());os.fsync(directory)
            finally:os.close(directory)
        row=meter.snapshot()
        self.assertEqual(row['calls'],2)
        self.assertEqual(row['failed_calls'],0)
        self.assertIs(os.fsync,original)
        self.assertTrue(row['original_hook_restored'])
        self.assertFalse(row['custody_or_ledger_authority'])

    def test_original_failure_is_not_suppressed_or_retried(self):
        failure=OSError('test fsync refusal')
        with patch('regional_ground_fsync.os.fsync',side_effect=failure) as original:
            meter=FsyncMeter()
            with self.assertRaises(OSError) as caught:meter.call(123)
        self.assertIs(caught.exception,failure)
        original.assert_called_once_with(123)
        self.assertEqual(meter.snapshot()['failed_calls'],1)

    def test_clock_failure_and_counter_saturation_keep_syscall_and_unknown(self):
        for clock in ([RuntimeError('clock absent'),1],[2,1],[1,float('nan')]):
            with patch('regional_ground_fsync.os.fsync',return_value=None) as original:
                meter=FsyncMeter()
                with patch('regional_ground_fsync.time.monotonic',side_effect=clock):meter.call(1)
                original.assert_called_once_with(1)
                self.assertFalse(meter.snapshot()['available'])
                self.assertIsNone(meter.snapshot()['calls'])
        with patch('regional_ground_fsync.os.fsync',return_value=None) as original:
            meter=FsyncMeter(max_calls=1);meter.call(1);meter.call(1)
            self.assertEqual(original.call_count,2)
            self.assertFalse(meter.snapshot()['available'])

    def test_busy_telemetry_lock_never_blocks_actual_sync(self):
        with patch('regional_ground_fsync.os.fsync',return_value=None) as original:
            meter=FsyncMeter();meter.lock.acquire()
            try:meter.call(123)
            finally:meter.lock.release()
        original.assert_called_once_with(123)
        self.assertFalse(meter.snapshot()['available'])

    def test_nested_or_changed_hook_refuses_and_exception_restores(self):
        original=os.fsync;first=FsyncMeter();second=FsyncMeter()
        with self.assertRaisesRegex(RuntimeError,'caller failed'):
            with first.installed():
                with self.assertRaisesRegex(ValueError,'another fsync'):
                    with second.installed():pass
                raise RuntimeError('caller failed')
        self.assertIs(os.fsync,original)
        self.assertTrue(first.snapshot()['original_hook_restored'])
        with patch('regional_ground_fsync.os.fsync',return_value=None):
            with self.assertRaisesRegex(ValueError,'changed before'):
                with first.installed():pass

    def test_telemetry_exception_cannot_replace_original_syscall_error(self):
        failure=OSError('original syscall failed')
        with patch('regional_ground_fsync.os.fsync',side_effect=failure):
            meter=FsyncMeter()
            with patch('regional_ground_fsync.time.monotonic',side_effect=[1,RuntimeError('telemetry failed')]), \
                 self.assertRaises(OSError) as caught:meter.call(123)
        self.assertIs(caught.exception,failure)
        self.assertFalse(meter.snapshot()['available'])


if __name__=='__main__':unittest.main()
