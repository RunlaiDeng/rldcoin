import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import review_publication_content as gate


class PublicationContentTests(unittest.TestCase):
    def selection(self, name, kind):
        return {'files': [name], 'content_classification': {
            name: {'kind': kind, 'purpose': 'Required public engineering interface.'}}}

    def test_missing_classification_and_prose_disguised_as_source_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'note.md').write_text('Native API input sizes and refusal semantics.\n')
            for selection in (['note.md'], self.selection('note.md', 'source')):
                with self.assertRaises(ValueError):
                    gate.review(d, selection)

    def test_renaming_does_not_make_run_journals_or_local_metadata_public(self):
        texts = ['V44 PASS17.195588秒/原120；封存数据。',
                 '下一单一主线：一次120秒复现实验，失败保留后切换诊断。',
                 'next diagnostic hypothesis: retry the same run.',
                 'task 11111111-2222-4333-8444-555555555555',
                 '/Users/operator/project/private',
                 'next stage actualbinary SHA256 ' + 'a' * 64 + ' controller hash ' + 'b' * 64,
                 'source SHA256 ' + 'c' * 64 + ' 进度通过',
                 'Measured cold read: 0.309571 seconds.']
        with tempfile.TemporaryDirectory() as d:
            for text in texts:
                with self.subTest(text=text):
                    Path(d, 'design.md').write_text(text)
                    with self.assertRaises(ValueError):
                        gate.review(d, self.selection('design.md', 'developer-documentation'))
            for value in ({'duration_seconds': 17.2}, {'message': texts[1]}):
                Path(d, 'example.json').write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    gate.review(d, self.selection('example.json', 'public-vector'))

    def test_normative_versions_standards_bounds_refusals_and_security_are_allowed(self):
        texts = ['RLD-WIRE-V1 MUST FAIL with unsupported-schema error before adoption.',
                 'FIPS203/204, RFC8032 and BIP340 identify standards; they do not authorize adoption.',
                 'Input bound32768 bytes. Exit0 accepts; exit1 refuses; exit2 unavailable.',
                 'TLS socket attempts have a 0.2-second lock bound and three-second socket bound.',
                 'macOS SDK rusage V1/Mach timebase returns cumulative CPU.',
                 'The next staged authority retains Reserved escrow.',
                 'Reject identity and mixed-order Ed25519 keys before checking both signatures.',
                 'The public vector digest is ' + 'a' * 64 + '; provenance is not current trust.']
        with tempfile.TemporaryDirectory() as d:
            for text in texts:
                with self.subTest(text=text):
                    Path(d, 'verify.md').write_text(text)
                    gate.review(d, self.selection('verify.md', 'developer-documentation'))
            Path(d, 'tool.py').write_text('report = {"duration_seconds": elapsed}\n')
            gate.review(d, self.selection('tool.py', 'source'))

    def test_private_artifact_paths_and_json_keys_always_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'vector.json').write_text(json.dumps({'seed': 'not-public'}))
            Path(d, 'private.py').write_text('-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n')
            with self.assertRaises(ValueError):
                gate.review(d, self.selection('private.py', 'source'))
            for name in ('tmp/renamed.rs', 'docs/operations/evidence/renamed.rs', 'AGENTS.md'):
                with self.assertRaises(ValueError):
                    gate.review(d, self.selection(name, 'source'))
            with self.assertRaises(ValueError):
                gate.review(d, self.selection('vector.json', 'public-vector'))

    def test_actual_publication_entry_refuses_before_staging_and_accepts_review_only(self):
        entry = Path(__file__).resolve().with_name('reviewed_publication.py')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            selection = root / 'selection.json'
            selection.write_text(json.dumps(self.selection('design.md', 'developer-documentation')))
            args = [sys.executable, '-B', str(entry), '--root', str(root),
                    '--selection', str(selection)]
            # Actual publish mode must fail at content admission before remote/Git mutation.
            Path(root, 'design.md').write_text('V44 PASS17.195588秒/原120')
            before = subprocess.check_output(['git', 'ls-files', '--stage'], cwd=root)
            result = subprocess.run(args, cwd=root, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'public prose', result.stderr)
            self.assertEqual(subprocess.check_output(['git', 'ls-files', '--stage'], cwd=root), before)
            self.assertFalse((root / '.git/refs/heads/main').exists())
            Path(root, 'design.md').write_text('RLD-WIRE-V1 MUST FAIL if schema is unknown.')
            result = subprocess.run(args + ['--review-only'], cwd=root, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(subprocess.check_output(['git', 'ls-files', '--stage'], cwd=root), before)


if __name__ == '__main__':
    unittest.main()
