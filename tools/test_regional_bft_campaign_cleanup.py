"""Real controller-owned child cleanup; no native ledger, wallet or signing."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from regional_bft_network_campaign import Campaign
import regional_bft_role_payment_campaign as payment


class CampaignCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.c=Campaign.__new__(Campaign)
        self.c.processes={};self.c.logs=[(self.root/'child.log').open('w')]
        self.addCleanup(self.close_remaining)

    def close_remaining(self):
        for process in self.c.processes.values():
            if process.poll() is None:process.kill()
            process.wait(timeout=5)
        for log in self.c.logs:log.close()

    def live(self, index):
        code="import signal,sys,time\nsignal.signal(signal.SIGTERM,lambda *_:sys.exit(0))\nprint('ready',flush=True)\nwhile True:time.sleep(0.1)"
        process=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,text=True)
        self.c.processes[index]=process
        self.assertEqual(process.stdout.readline(),'ready\n')
        self.addCleanup(process.stdout.close)
        return process

    def failed(self, index):
        process=subprocess.Popen([sys.executable,'-c','raise SystemExit(7)'])
        self.c.processes[index]=process;self.assertEqual(process.wait(timeout=5),7)
        return process

    def test_one_failed_child_does_not_leave_other_real_children_or_logs_open(self):
        failed=self.failed(0);others=[self.live(n) for n in (1,2)]
        with self.assertRaisesRegex(ValueError,'owned process cleanup failed'):self.c.cleanup()
        self.assertEqual(failed.returncode,7)
        self.assertTrue(all(p.poll()==0 for p in others))
        self.assertEqual(self.c.processes,{})
        self.assertTrue(all(log.closed for log in self.c.logs))

    def test_failed_wait_keeps_process_ownership_and_never_claims_stop(self):
        process=Mock();process.poll.return_value=None
        process.wait.side_effect=[subprocess.TimeoutExpired('fixture',30),subprocess.TimeoutExpired('fixture',10)]
        self.c.processes[0]=process
        with self.assertRaises(subprocess.TimeoutExpired):self.c.stop(0)
        self.assertIs(self.c.processes[0],process)
        process.terminate.assert_called_once();process.kill.assert_called_once()
        self.c.processes.clear()

    def configure_main(self, result=None, failure=None):
        self.c.currency='a'*64;self.c.implementation='b'*64
        self.c.controller_authority_calls=0;self.c.observations=[];self.c.payments=[]
        self.c.inspection_anchors_sha256='c'*64
        self.c.run=Mock(return_value=result,side_effect=failure)
        return self.root/'report.json'

    def main(self, report):
        with patch.object(payment,'Campaign',return_value=self.c),patch.object(sys,'argv',
                ['fixture','--binary','/unused/native','--root',str(self.root),'--report',str(report)]):
            payment.main()

    def test_original_failure_is_reported_after_real_child_cleanup_failure(self):
        report=self.configure_main(failure=ValueError('original startup rejected'))
        self.failed(0);other=self.live(1)
        with self.assertRaisesRegex(ValueError,'original startup rejected'):self.main(report)
        value=json.loads(report.read_text())
        self.assertEqual(value['failure'],'ValueError: original startup rejected')
        self.assertIn('owned process cleanup failed',value['cleanup_failure'])
        self.assertFalse(value['completed']);self.assertFalse(value['owned_process_shutdown_clean'])
        self.assertTrue(value['owned_process_cleanup_verified']);self.assertEqual(other.poll(),0)

    def test_success_result_cannot_survive_unclean_real_child_shutdown(self):
        report=self.configure_main(result=dict(completed=True,fixture_only=True,live_rld=False))
        self.failed(0);other=self.live(1)
        with self.assertRaisesRegex(ValueError,'owned process cleanup failed'):self.main(report)
        value=json.loads(report.read_text())
        self.assertFalse(value['completed']);self.assertEqual(value['failure'],value['cleanup_failure'])
        self.assertFalse(value['owned_process_shutdown_clean']);self.assertEqual(other.poll(),0)

    def test_phase_cleanup_failure_stays_unclean_after_an_empty_final_cleanup(self):
        report=self.configure_main()
        self.c.run.side_effect=self.c.cleanup
        self.failed(0);other=self.live(1)
        with self.assertRaisesRegex(ValueError,'owned process cleanup failed'):self.main(report)
        value=json.loads(report.read_text())
        self.assertFalse(value['completed']);self.assertFalse(value['owned_process_shutdown_clean'])
        self.assertTrue(value['owned_process_cleanup_verified']);self.assertEqual(other.poll(),0)

    def test_caught_earlier_cleanup_failure_cannot_turn_a_later_result_successful(self):
        report=self.configure_main(result=dict(completed=True,fixture_only=True,live_rld=False))
        self.failed(0);other=self.live(1)
        with self.assertRaises(ValueError):self.c.cleanup()
        with self.assertRaisesRegex(ValueError,'earlier owned process shutdown was unclean'):self.main(report)
        value=json.loads(report.read_text())
        self.assertFalse(value['completed']);self.assertFalse(value['owned_process_shutdown_clean'])
        self.assertEqual(value['failure'],value['cleanup_failure']);self.assertEqual(other.poll(),0)


if __name__=='__main__':unittest.main()
