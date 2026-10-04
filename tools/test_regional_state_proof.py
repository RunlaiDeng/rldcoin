"""Real native historical record proofs; never replace import/spend execution."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from regional_contact_campaign import Campaign, public, save

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).parent / 'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeStateProofTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='rld-state-proof-cli-')).resolve()
        self.root = self.base / 'fixture'
        self.c = Campaign(BINARY, self.root)

    def tearDown(self):
        self.c.cleanup()
        result = self._outcome.result
        if not any(test is self for test, _ in result.failures + result.errors):
            shutil.rmtree(self.base)

    def files(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob('*') if p.is_file()}

    def proof(self, region, checkpoint, collection, key):
        return self.c.cli(region, 'state-proof', '--checkpoint', checkpoint,
                          '--collection', collection, '--key', key)

    def check(self, region, checkpoint, collection, key, proof, success=True):
        path = self.base / 'proof.json'
        save(path, proof)
        return self.c.cli(region, 'state-proof-check', '--checkpoint', checkpoint,
                          '--collection', collection, '--key', key, '--file', path, success=success)

    def test_native_cold_query_binds_checkpoint_key_and_collection_without_mutation(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        status = self.c.cli('earth', 'status')
        sid = status['finality']
        key = next(iter(status['ledger']['coins']))
        before = self.files()
        proof = self.proof('earth', sid, 'coins', key)
        accepted = self.check('earth', sid, 'coins', key, proof)
        self.assertEqual(accepted['record']['record'], status['ledger']['coins'][key])
        self.assertTrue(accepted['native_certified_state_verified'])
        self.assertFalse(accepted['current_spendability_authorized'])
        self.assertFalse(accepted['ledger_changed'])
        absent = self.proof('earth', sid, 'imports', '00' * 32)
        self.assertIsNone(self.check('earth', sid, 'imports', '00' * 32, absent)['record'])
        for collection, wanted, candidate in [
            ('exports', key, proof), ('coins', '00' * 32, proof),
            ('coins', key, dict(proof, extra=True)),
        ]:
            self.check('earth', sid, collection, wanted, candidate, success=False)
        forged = copy.deepcopy(proof)
        forged['witness']['member']['value']['record']['payment']['amount'] = '999'
        self.check('earth', sid, 'coins', key, forged, success=False)
        self.check('proxima', sid, 'coins', key, proof, success=False)
        self.assertEqual(self.files(), before)

    def test_consumed_original_output_absence_and_permanent_import_survive_full_restore(self):
        for _ in range(4):
            self.c.mine('earth')
        self.c.certify('earth')
        ledger = self.c.cli('earth', 'status')['ledger']
        coin = sorted(k for k, c in ledger['coins'].items()
                      if c['payment']['owner'] == public(10) and int(c['mature']) <= 5)[0]
        intent = self.c.intent('earth', [10], remote=('proxima', 11, 99, 1), fee=1, inputs=[coin])
        self.c.mine('earth', [intent['command']])
        self.c.certify('earth')
        eid = intent['export_or_transaction_id']
        source = self.c.cli('earth', 'status')['finality']
        export = self.proof('earth', source, 'exports', eid)
        self.assertEqual(self.check('earth', source, 'exports', eid, export)['record']['record']['id'], eid)
        frame = self.base / 'frame.json'
        save(frame, self.c.cli('earth', 'contact-export', '--export', eid))
        self.c.cli('proxima', 'contact-apply', '--file', frame, '--miner', public(10))
        self.c.mine('proxima')
        self.c.mine('proxima')
        self.c.certify('proxima')
        original = self.c.cli('proxima', 'status')
        received = next(k for k, c in original['ledger']['coins'].items() if c['payment']['owner'] == public(11))
        old = self.proof('proxima', original['finality'], 'coins', received)
        spend = self.c.intent('proxima', [11], outputs=[(12, 98)])
        self.c.mine('proxima', [spend['command']])
        self.c.certify('proxima')
        latest = self.c.cli('proxima', 'status')
        sid = latest['finality']
        self.check('proxima', sid, 'coins', received, old, success=False)
        spent = self.proof('proxima', sid, 'coins', received)
        imported = self.proof('proxima', sid, 'imports', eid)
        self.assertIsNone(self.check('proxima', sid, 'coins', received, spent)['record'])
        self.assertEqual(self.check('proxima', sid, 'imports', eid, imported)['record']['record'], source)
        head = self.c.cli('proxima', 'history-head')['history_head']
        archive, target = self.base / 'private-image', self.base / 'restored'
        before = self.files()
        self.c.cli('proxima', 'history-archive', '--archive', archive, '--expected-head', head)
        self.c.invoke([str(BINARY), '--dir', str(target), '--authority', self.c.authority,
                       '--currency', self.c.currency, 'history-restore', '--archive', str(archive),
                       '--expected-head', head])
        for collection, key, proof in [('coins', received, spent), ('imports', eid, imported)]:
            path = self.base / 'restored-proof.json'
            save(path, proof)
            checked = self.c.invoke([str(BINARY), '--dir', str(target), '--authority', self.c.authority,
                                    '--currency', self.c.currency, 'state-proof-check', '--checkpoint', sid,
                                    '--collection', collection, '--key', key, '--file', str(path)])
            self.assertFalse(checked['ledger_changed'])
            self.assertTrue(checked['native_certified_state_verified'])
        self.assertEqual(self.files(), before)
        duplicate = {'Import': {'snapshot': source, 'export': eid}}
        self.assertIn('permanent import tombstone', self.c.mine('proxima', [duplicate], success=False)['reason'])
        self.assertEqual(self.c.cli('proxima', 'status'), latest)
        self.c.audit('state proofs retain spent original identity; native import still deduplicates')


if __name__ == '__main__':
    unittest.main()
