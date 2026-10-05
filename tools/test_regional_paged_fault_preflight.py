import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_paged_fault_preflight import HistoryOnly


class Tests(unittest.TestCase):
    def reader(self):
        reader = object.__new__(HistoryOnly)
        reader.project = Path('/pinned-project')
        reader.binary = Path('/pinned-cli')
        reader.ledger = Path('/pinned-ledger')
        reader.authority, reader.currency, reader.head = 'a'*64, 'b'*64, 'c'*64
        reader.deadline = time.monotonic() + 120
        return reader

    def test_only_exact_fixed_head_command_and_explicit_workdir(self):
        reader = self.reader()
        with patch('regional_paged_fault_preflight.subprocess.run') as run:
            for args in (('init',), ('history-head',), ('bft-status',), ('wallet-view',),
                         ('history-check', '--expected-head', 'd'*64)):
                with self.assertRaises(ValueError):
                    reader.call(*args)
            run.assert_not_called()
        def observed(args, **kwargs):
            self.assertEqual(args[-3:], ['history-check', '--expected-head', reader.head])
            self.assertEqual(kwargs['cwd'], reader.project)
            self.assertIsNone(kwargs['input'])
            self.assertLessEqual(kwargs['timeout'], 30)
            kwargs['stdout'].write(b'{"pinned":true}')
            return SimpleNamespace(returncode=0)
        with patch('regional_paged_fault_preflight.subprocess.run', side_effect=observed):
            self.assertEqual(reader.call('history-check', '--expected-head', reader.head),
                             {'pinned': True})

    def test_deadlines_and_native_refusals_never_retry(self):
        reader = self.reader()
        for deadline in (True, float('nan'), float('inf'), time.monotonic() - 1):
            reader.deadline = deadline
            with patch('regional_paged_fault_preflight.subprocess.run') as run:
                with self.assertRaises(ValueError):
                    reader.call('history-check', '--expected-head', reader.head)
                run.assert_not_called()
        reader = self.reader()
        for result in (SimpleNamespace(returncode=1), subprocess.TimeoutExpired('history-check', 30)):
            with patch('regional_paged_fault_preflight.subprocess.run',
                       **({'side_effect': result} if isinstance(result, Exception)
                          else {'return_value': result})) as run:
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    reader.call('history-check', '--expected-head', reader.head)
                self.assertEqual(run.call_count, 1)

    def test_strict_native_response_and_capacity(self):
        reader = self.reader()
        for data in (b'{"height":9,"height":7}', b'{"height":NaN}', b'x'*(8*1024*1024+1)):
            def reply(args, **kwargs):
                kwargs['stdout'].write(data)
                return SimpleNamespace(returncode=0)
            with patch('regional_paged_fault_preflight.subprocess.run', side_effect=reply):
                with self.assertRaises(ValueError):
                    reader.call('history-check', '--expected-head', reader.head)


if __name__ == '__main__':
    unittest.main()
