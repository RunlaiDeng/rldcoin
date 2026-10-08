"""Fresh synthetic subprocesses only; no Native stores, keys or real value."""
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from bounded_process_observation import observe


class ProcessObservationTests(unittest.TestCase):
    def run_child(self, code, budget=2):
        root = tempfile.TemporaryDirectory(prefix='bounded-process-observation-')
        self.addCleanup(root.cleanup)
        path = Path(root.name)/'output.log'
        result = observe([sys.executable, '-c', code], output=path, budget_seconds=budget)
        return result, path

    def test_actual_success_resources_and_complete_output(self):
        result, path = self.run_child('print("original output", flush=True);sum(i*i for i in range(400000))')
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out or result.descendant_residue)
        self.assertTrue(result.owned_group_empty)
        self.assertGreater(result.user_cpu_seconds, 0)
        self.assertGreater(result.maximum_resident_bytes, 0)
        self.assertEqual(path.read_bytes(), b'original output\n')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_child_failure_is_not_an_observer_or_wrapper_exit(self):
        result, path = self.run_child('import sys;print("refused",flush=True);sys.exit(7)')
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.timed_out)
        self.assertTrue(result.owned_group_empty)
        self.assertEqual(path.read_bytes(), b'refused\n')

    def test_timeout_keeps_partial_output_and_cannot_become_a_zero_exit_pass(self):
        result, path = self.run_child('import signal,time,sys;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));print("retained",flush=True);time.sleep(30)', .1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.owned_group_empty)
        self.assertEqual(path.read_bytes(), b'retained\n')

    def test_ignoring_termination_still_stops_only_the_owned_group(self):
        result, path = self.run_child('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("retained",flush=True);time.sleep(30)', .1)
        self.assertTrue(result.timed_out)
        self.assertLess(result.returncode, 0)
        self.assertTrue(result.owned_group_empty)
        self.assertEqual(path.read_bytes(), b'retained\n')

    def test_invalid_budgets_and_existing_logs_refuse_before_launch(self):
        root = tempfile.TemporaryDirectory();self.addCleanup(root.cleanup)
        path = Path(root.name)/'output.log'
        for value in (0, -1, True, float('nan'), float('inf')):
            with self.assertRaises(ValueError):observe([sys.executable,'-c','raise AssertionError()'], output=path, budget_seconds=value)
        self.assertFalse(path.exists())
        path.write_bytes(b'retained old evidence')
        with self.assertRaises(FileExistsError):observe([sys.executable,'-c','raise AssertionError()'], output=path, budget_seconds=2)
        self.assertEqual(path.read_bytes(), b'retained old evidence')

    def test_parent_zero_exit_with_live_descendant_is_separate_residue(self):
        code = ('import subprocess,sys,time;'
                'subprocess.Popen([sys.executable,"-c","import time;print(\'descendant\',flush=True);time.sleep(30)"]);'
                'time.sleep(.05)')
        result, path = self.run_child(code)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.descendant_residue)
        self.assertTrue(result.owned_group_empty)
        self.assertIn(b'descendant', path.read_bytes())


if __name__ == '__main__':
    unittest.main()
