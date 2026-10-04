"""Actual private native ledger image recovery; no signer or wallet migration."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from regional_contact_campaign import Campaign, public, save

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).parent / 'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


def digest_tree(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


class NativeHistoryArchiveTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='rld-native-image-cli-')).resolve()
        self.root = self.base / 'fixture'
        self.c = Campaign(BINARY, self.root)
        self.archive = self.base / 'private-archive'
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
        self.c.cleanup()
        # Keep failed private fixtures for diagnosis; never publish their bytes.
        result = self._outcome.result
        failed = any(test is self for test, _ in result.failures + result.errors)
        if not failed:
            shutil.rmtree(self.base)

    def command(self, target, *args, currency=None, authority=None):
        return [str(BINARY), '--dir', str(target), '--authority', authority or self.c.authority,
                '--currency', currency or self.c.currency, *map(str, args)]

    def invoke(self, target, *args, success=True, **kwargs):
        return self.c.invoke(self.command(target, *args, **kwargs), success=success)

    def head(self, name='earth'):
        return self.c.cli(name, 'history-head')['history_head']

    def seal(self, name='earth', head=None):
        return self.c.cli(name, 'history-archive', '--archive', self.archive,
                          '--expected-head', head or self.head(name))

    def restore(self, target, head, success=True, **kwargs):
        return self.invoke(target, 'history-restore', '--archive', self.archive,
                           '--expected-head', head, success=success, **kwargs)

    def test_full_certified_history_exact_restore_excludes_private_custody(self):
        for _ in range(20):
            self.c.mine('earth')
        self.c.certify('earth')
        source = self.root / 'earth'
        save(source / 'caller-retained-heads.json', {'private': 'never archived'})
        save(source / 'pending-review.json', {'private': 'never archived'})
        head = self.head()
        original = self.c.cli('earth', 'history-check', '--expected-head', head)
        status = self.c.cli('earth', 'status')
        before = digest_tree(self.root)
        sealed = self.seal(head=head)
        archived = digest_tree(self.archive)
        target = self.base / 'restored'
        restored = self.restore(target, head)
        self.assertEqual(restored['archive_commitment'], sealed['archive_commitment'])
        self.assertTrue(restored['complete_native_replay_verified'])
        self.assertFalse(restored['keys_restored'])
        self.assertFalse(restored['live_rld'])
        self.assertEqual(self.invoke(target, 'history-check', '--expected-head', head), original)
        self.assertEqual(self.invoke(target, 'status'), status)
        self.assertFalse((target / 'RESTORING').exists())
        self.assertFalse((target / 'caller-retained-heads.json').exists())
        self.assertFalse((target / 'pending-review.json').exists())
        self.assertEqual(digest_tree(self.root), before)
        self.assertEqual(digest_tree(self.archive), archived)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        for path in self.archive.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_stale_head_wrong_domain_and_existing_caller_state_refuse_without_copy(self):
        old_head = self.head()
        self.seal(head=old_head)
        self.c.mine('earth')
        latest_head = self.head()
        before = digest_tree(self.base)
        for target, kwargs, head in [
            (self.base / 'stale', {}, latest_head),
            (self.base / 'wrong-currency', {'currency': '00' * 32}, old_head),
            (self.base / 'wrong-authority', {'authority': public(2)}, old_head),
        ]:
            self.restore(target, head, success=False, **kwargs)
            self.assertFalse(target.exists())
        target = self.base / 'existing'
        target.mkdir(mode=0o700)
        save(target / 'pending-review.json', {'head': 'surviving caller head'})
        existing = digest_tree(target)
        self.restore(target, old_head, success=False)
        self.assertEqual(digest_tree(target), existing)
        self.assertEqual({k: v for k, v in digest_tree(self.base).items() if not k.startswith('existing/')}, before)

    def test_spent_original_import_tombstone_survives_fresh_target_replay(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        source = self.c.cli('earth', 'status')['ledger']
        coin = sorted(k for k, v in source['coins'].items()
                      if v['payment']['owner'] == public(10) and int(v['mature']) <= 5)[0]
        intent = self.c.intent('earth', [10], remote=('proxima', 11, 99, 1), fee=1, inputs=[coin])
        self.c.mine('earth', [intent['command']])
        self.c.certify('earth')
        eid = intent['export_or_transaction_id']
        frame_path = self.root / 'actual-frame.json'
        save(frame_path, self.c.cli('earth', 'contact-export', '--export', eid))
        self.c.cli('proxima', 'contact-apply', '--file', frame_path, '--miner', public(10))
        self.c.mine('proxima')
        self.c.mine('proxima')
        self.c.certify('proxima')
        spend = self.c.intent('proxima', [11], outputs=[(12, 98)])
        self.c.mine('proxima', [spend['command']])
        head = self.head('proxima')
        original = self.c.cli('proxima', 'status')
        self.assertFalse(any(v['payment']['owner'] == public(11) for v in original['ledger']['coins'].values()))
        self.seal('proxima', head)
        target = self.base / 'restored-spent-import'
        self.restore(target, head)
        self.assertEqual(self.invoke(target, 'status'), original)
        self.assertEqual(self.invoke(target, 'history-check', '--expected-head', head)['permanent_import_entries'], 1)
        commands = self.base / 'duplicate-import.json'
        save(commands, [{'Import': {'snapshot': original['ledger']['imports'][eid], 'export': eid}}])
        before = digest_tree(target)
        failure = self.invoke(target, 'mine', '--miner', public(10), '--commands', commands, success=False)
        self.assertIn('permanent import tombstone', failure['reason'])
        self.assertEqual(digest_tree(target), before)

    def test_actual_sigkill_retains_incomplete_image_and_blocks_every_entry(self):
        source = self.root / 'earth'
        # Unaccepted objects are retained, never promoted into native progress.
        # Enough bounded copy/fsync work to observe the real interruption marker.
        for n in range(2500):
            data = ('unaccepted residue %d' % n).encode()
            path = source / 'history' / (hashlib.sha256(data).hexdigest() + '.json')
            path.write_bytes(data)
            path.chmod(0o600)
        head = self.head()
        before = digest_tree(self.root)
        self.seal(head=head)
        archive_before = digest_tree(self.archive)
        target = self.base / 'interrupted'
        command = self.command(target, 'history-restore', '--archive', self.archive, '--expected-head', head)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        deadline = time.monotonic() + 30
        while not (target / 'RESTORING').exists():
            self.assertIsNone(child.poll(), 'restore completed before its interruption marker was observed')
            self.assertLess(time.monotonic(), deadline, 'restore marker was not observed')
            time.sleep(0.001)
        child.kill()
        child.communicate(timeout=10)
        self.assertLess(child.returncode, 0)
        self.assertTrue((target / 'RESTORING').is_file())
        interrupted = digest_tree(target)
        for action in [
            ['status'], ['history-head'], ['history-check', '--expected-head', head],
            ['init', '--bootstrap', self.root / 'bootstrap.json', '--region', 'earth'],
            ['contact-node'], ['wallet-app', '--wallet-dir', self.base / 'never-wallet',
                               '--head-dir', self.base / 'never-caller', '--owner', public(10)],
        ]:
            failure = self.invoke(target, *action, success=False)
            self.assertIn('restoration is incomplete', failure['reason'])
            self.assertEqual(digest_tree(target), interrupted)
        self.assertFalse((self.base / 'never-wallet').exists())
        self.assertFalse((self.base / 'never-caller').exists())
        self.restore(target, head, success=False)
        self.assertEqual(digest_tree(target), interrupted)
        self.assertEqual(digest_tree(self.root), before)
        self.assertEqual(digest_tree(self.archive), archive_before)

    def test_tampered_native_page_refuses_before_any_target_creation(self):
        self.c.mine('earth')
        head = self.head()
        self.seal(head=head)
        manifest = json.loads((self.archive / 'data/journal.json').read_bytes())
        path = self.archive / 'data/history' / (manifest['pages'][0]['hash'] + '.json')
        path.write_bytes(b'{}')
        before = digest_tree(self.archive)
        target = self.base / 'corrupt-target'
        self.restore(target, head, success=False)
        self.assertFalse(target.exists())
        self.assertEqual(digest_tree(self.archive), before)


if __name__ == '__main__':
    unittest.main()
