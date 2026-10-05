"""Candidate-selection counterexamples; every subprocess is intercepted.

No native store, signer, Runtime startup, socket, or owner request is opened.
The refusal language is bound separately to a retained actual Rust lock probe.
"""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from regional_bft_node import Runtime
from regional_contact_node import Native

BUSY = 'regional candidate rejected: lock acquisition failed because the operation would block'
IMPORT = {'Import': {'snapshot': '1' * 64, 'export': '2' * 64}}


class CandidateLockTests(unittest.TestCase):
    def exercise(self, refusals, incoming=None):
        calls = []
        runtime = Runtime.__new__(Runtime)
        runtime.joint = None
        runtime.miner = 'fixture-miner'
        runtime.state = {'messages': SimpleNamespace(bodies=lambda: [])}
        native = Native.__new__(Native)
        native.binary = Path('/intercepted-only-native')
        native.ledger = Path('/never-opened-native-store')
        native.authority = '3' * 64
        native.currency = '4' * 64
        runtime.native = native
        pending = copy.deepcopy(incoming if incoming is not None else [IMPORT])

        def run(argv, **kwargs):
            action = argv[7]
            if action == 'bft-pending-imports':
                answer = pending
            else:
                self.assertEqual(action, 'bft-candidate')
                commands = json.loads(Path(argv[9]).read_bytes())
                calls.append(commands)
                refusal = refusals.pop(0) if refusals else None
                if refusal is not None:
                    code, diagnostic = refusal
                    kwargs['stderr'].write(diagnostic.encode())
                    return SimpleNamespace(returncode=code)
                answer = {'commands': commands}
            kwargs['stdout'].write(json.dumps(answer).encode())
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory(prefix='rld-candidate-lock-model-') as directory:
            runtime.root = Path(directory)
            with patch('regional_contact_node.subprocess.run', side_effect=run):
                try:
                    result = runtime.candidate({'parent_height': 0})
                    return result, None, calls
                except ValueError as error:
                    return None, error, calls

    def test_busy_trial_cannot_authorize_empty_candidate(self):
        result, error, calls = self.exercise([(1, BUSY)])
        self.assertIsNone(result)
        self.assertEqual(str(error), 'native rejected: ' + BUSY)
        self.assertEqual(calls, [[IMPORT]])

    def test_busy_second_trial_cannot_authorize_partial_candidate(self):
        other = {'Import': {'snapshot': '5' * 64, 'export': '6' * 64}}
        result, error, calls = self.exercise([None, (1, BUSY)], [IMPORT, other])
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual(calls, [[IMPORT], [IMPORT, other]])

    def test_valid_import_keeps_complete_native_trial_and_final_check(self):
        result, error, calls = self.exercise([])
        self.assertIsNone(error)
        self.assertEqual(result, {'commands': [IMPORT]})
        self.assertEqual(calls, [[IMPORT], [IMPORT]])

    def test_stale_import_still_skips_without_rewriting_submission(self):
        result, error, calls = self.exercise([(1, 'regional candidate rejected: duplicate import')])
        self.assertIsNone(error)
        self.assertEqual(result, {'commands': []})
        self.assertEqual(calls, [[IMPORT], []])

    def test_complete_refusal_retained_beyond_display_limit(self):
        diagnostic = BUSY + ' ' * 2200 + 'bad proof'
        result, error, calls = self.exercise([(1, diagnostic), (1, diagnostic)])
        self.assertIsNone(result)
        self.assertEqual(error.diagnostic, diagnostic)
        self.assertEqual(error.exit_code, 1)
        self.assertEqual(error.command, 'bft-candidate')
        self.assertEqual(calls, [[IMPORT], []])

    def test_unknown_exit_cannot_be_classified_as_lock_busy(self):
        result, error, calls = self.exercise([(2, BUSY), (2, BUSY)])
        self.assertIsNone(result)
        self.assertEqual(error.exit_code, 2)
        self.assertEqual(calls, [[IMPORT], []])


if __name__ == '__main__':
    unittest.main()
