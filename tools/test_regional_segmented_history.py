"""Ordinary locked stores and signer/wallet agents across signed segments.

Public fixture monetary keys only; generated stores/archives stay private.
These finite tests exercise paged event journals, not full or BFT long history.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from regional_contact_campaign import Campaign, public, save
import interstellar_transfer as wire

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).parent / 'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class SegmentedCampaign(Campaign):
    def help(self, *args):
        if args == ('bootstrap',):
            args = ('bootstrap', '--segmented')
        return super().help(*args)


class NativeSegmentedTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='rld-segmented-cli-')).resolve()
        self.c = SegmentedCampaign(BINARY, self.base / 'fixture')

    def tearDown(self):
        self.c.cleanup()
        result = self._outcome.result
        if not any(test is self for test, _ in result.failures + result.errors):
            shutil.rmtree(self.base)

    def test_ordinary_store_real_payments_signer_wallet_contact_and_restore_past_old_event_limit(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        status = self.c.cli('earth', 'status')
        coin = sorted(k for k, c in status['ledger']['coins'].items() if c['payment']['amount'] == '100')[0]
        owner = 10
        for n in range(352):
            next_owner = 21 if owner == 20 else 20
            request = self.c.intent('earth', [owner], outputs=[(next_owner, 100)], inputs=[coin])
            self.assertGreater(int(request['command']['Spend']['intent']['valid_through']), n + 4)
            self.c.mine('earth', [request['command']])
            coin = hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:output\0' + wire.canonical([request['export_or_transaction_id'], 0])).hexdigest()
            if n == 0:
                self.assertIn(coin, self.c.cli('earth', 'status')['ledger']['coins'])
            owner = next_owner
            if (n + 1) % 128 == 0:
                self.c.certify('earth')
        self.c.certify('earth')
        self.assertEqual(self.c.cli('earth', 'status')['height'], 356)

        # A real persistent owner agent reviews/signs against historical native events.
        wallet = self.base / 'wallet'
        initial = self.c.cli('earth', 'wallet-init', '--wallet-dir', wallet, '--owner', public(owner))['wallet_head']
        key = self.base / 'owner-key.json'
        save(key, {'secret_key': (bytes([owner]) * 32).hex()})
        key.chmod(0o600)
        request_path = self.base / 'wallet-request.json'
        save(request_path, {'owner': public(owner), 'inputs': [coin], 'outputs': [{'owner': public(15), 'amount': '100'}],
                           'remote': None, 'fee': '0', 'valid_for_blocks': 8})
        review = self.c.cli('earth', 'wallet-prepare', '--wallet-dir', wallet, '--expected-wallet-head', initial, '--file', request_path)
        prepared = self.base / 'prepared.json'
        save(prepared, review)
        signed = self.c.cli('earth', 'wallet-sign', '--wallet-dir', wallet, '--expected-wallet-head', initial,
                            '--file', prepared, '--review', review['review_commitment'], '--key-file', key)
        self.c.mine('earth', signed['commands'])
        view = self.c.cli('earth', 'wallet-view', '--wallet-dir', wallet, '--expected-wallet-head', signed['wallet_head'])
        self.assertEqual(view['signed'][0]['state'], 'INCLUDED_IN_LOCAL_LEDGER')

        # Newly created post-256 value gets actual finality, then onward and return.
        self.c.certify('earth')
        payment = self.c.intent('earth', [15], remote=('proxima', 11, 100, 1))
        self.c.mine('earth', [payment['command']])
        self.c.certify('earth')
        frame = self.base / 'frame.json'
        save(frame, self.c.cli('earth', 'contact-export', '--export', payment['export_or_transaction_id']))
        self.c.cli('proxima', 'contact-apply', '--file', frame, '--miner', public(10))
        for _ in range(2):
            self.c.mine('proxima')
        self.c.certify('proxima')
        returned = self.c.intent('proxima', [11], remote=('earth', 13, 99, 1))
        self.c.mine('proxima', [returned['command']])
        self.c.certify('proxima')
        save(frame, self.c.cli('proxima', 'contact-export', '--export', returned['export_or_transaction_id']))
        self.c.cli('earth', 'contact-apply', '--file', frame, '--miner', public(10))
        for _ in range(2):
            self.c.mine('earth')
        self.c.certify('earth')
        before_retry = self.c.cli('earth', 'status')
        repeated = self.c.cli('earth', 'contact-apply', '--file', frame, '--miner', public(10))
        self.assertTrue(repeated['import_accepted'])
        self.assertEqual(self.c.cli('earth', 'status'), before_retry)
        duplicate = {'Import': {'snapshot': self.c.cli('proxima', 'status')['finality'], 'export': returned['export_or_transaction_id']}}
        refusal = self.c.mine('earth', [duplicate], success=False)
        self.assertIn('permanent import tombstone', refusal['reason'])
        status = self.c.cli('earth', 'status')
        self.assertEqual(status['height'], 361)
        self.assertEqual(sum(int(c['payment']['amount']) for c in status['ledger']['coins'].values() if c['payment']['owner'] == public(13)), 98)
        self.c.audit('past old event bound: paged ordinary native signed wallet export and return')

        observation = self.c.cli('earth', 'history-head')
        self.assertEqual(observation['format'], 'RLD-NATIVE-HISTORY-PAGED-EVENTS-V1')
        self.assertGreater(observation['sealed_event_pages'] * 16, 336)
        self.assertLess(observation['retained_tail_events'], 16)
        head = observation['history_head']
        image = self.base / 'image'
        restored = self.base / 'restored'
        self.c.cli('earth', 'history-archive', '--archive', image, '--expected-head', head)
        self.c.invoke([BINARY, '--dir', restored, '--authority', self.c.authority, '--currency', self.c.currency,
                       'history-restore', '--archive', image, '--expected-head', head])
        recovered = self.c.invoke([BINARY, '--dir', restored, '--authority', self.c.authority, '--currency', self.c.currency, 'status'])
        self.assertEqual(recovered, status)
        print(json.dumps({'format': 'RLD-NATIVE-PAGED-EVENTS-ORDINARY-STORE-SAMPLE-V1', 'fixture_only': True, 'live_rld': False,
                          'native_implementation': self.c.bootstrap['currency']['implementation'], 'height': 361,
                          'actual_signed_local_payments': 353, 'return_net': '98', 'cold_private_restore_equal': True, 'sealed_event_pages': observation['sealed_event_pages'],
                          'retained_tail_events': observation['retained_tail_events'],
                          'legacy_event_bounds_unchanged': True, 'snapshot_and_archive_bounds_unchanged': True, 'full_long_history_qualified': False}))
