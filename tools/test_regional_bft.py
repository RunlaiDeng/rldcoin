"""Ground BFT integration uses fresh native processes, never a model ledger."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from regional_bft_campaign import Campaign
from regional_contact_campaign import public, save

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeBftTests(unittest.TestCase):
    def test_offline_leader_three_voters_catchup_and_certified_onward_payment(self):
        with tempfile.TemporaryDirectory(prefix='rld-bft-cli-') as temp:
            campaign = Campaign(BINARY, Path(temp)/'fixture')
            report = campaign.run()
            self.assertTrue(report['offline_initial_leader_progressed'])
            self.assertTrue(report['offline_replica_caught_up'])
            self.assertTrue(report['old_signer_backup_latest_head_rejected'])
            self.assertTrue(report['transport_alone_did_not_credit'])
            self.assertEqual(report['first_recipient']['expected']['net_amount'], '95')
            self.assertEqual(report['onward_recipient']['expected']['net_amount'], '93')
            self.assertEqual(report['remote_execution_earth_calls'], 0)
            self.assertGreaterEqual(report['expected_rejections'], 7)
            self.assertTrue(all(c['conserved'] for c in report['conservation_checks']))
            self.assertFalse(report['independent_operators_qualified'])
            self.assertFalse(report['autonomous_pacemaker_qualified'])
            self.assertFalse(report['bft_reconfiguration_implemented'])

    def test_legacy_signed_admission_cannot_enable_bft_cli(self):
        with tempfile.TemporaryDirectory(prefix='rld-bft-admission-') as temp:
            root = Path(temp).resolve()
            bootstrap = json.loads(subprocess.check_output([BINARY.with_name('contact-fixture'), 'bootstrap']))
            save(root/'bootstrap.json', bootstrap)
            base = [str(BINARY), '--dir', str(root/'node'), '--authority', public(1), '--currency', bootstrap['admissions'][0]['currency']]
            subprocess.run(base+['init', '--bootstrap', str(root/'bootstrap.json'), '--region', 'earth'], check=True, capture_output=True, timeout=30)
            before = (root/'node/journal.json').read_bytes()
            result = subprocess.run(base+['bft-context'], capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('has not authorized', result.stderr.decode())
            result = subprocess.run(base+['bft-candidate', '--miner', public(10)], capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root/'node/journal.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
