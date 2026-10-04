"""Actual owned child shutdown and terminal reporting at both cycle entrypoints."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

import regional_bft_multiregion_campaign as cycle
import regional_bft_joint_cycle_campaign as joint
from regional_campaign_terminal import execute


class MultiregionCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.children=[];self.logs=[]
        self.addCleanup(self.close)

    def close(self):
        for p in self.children:
            if p.poll() is None:p.kill()
            p.wait(timeout=5)
            if p.stdout:p.stdout.close()
        for log in self.logs:log.close()

    def children_for(self, failed):
        processes={}
        for n in range(3):
            if failed and n==0:
                p=subprocess.Popen([sys.executable,'-c','raise SystemExit(7)']);self.assertEqual(p.wait(timeout=5),7)
            else:
                code="import signal,sys,time\nsignal.signal(signal.SIGTERM,lambda *_:sys.exit(0))\nprint('ready',flush=True)\nwhile True:time.sleep(0.1)"
                p=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,text=True)
                self.assertEqual(p.stdout.readline(),'ready\n')
            self.children.append(p);processes[('earth',n)]=p
        return processes

    def main(self,module,failed=False,stage_failure=False,caught_failure=False):
        path=self.root/f'{module.__name__}-{len(self.logs)}.json';processes=self.children_for(failed)
        log=(self.root/f'children-{len(self.logs)}.log').open('w');self.logs.append(log)
        def initialize(c,binary,root):
            c.processes=processes;c.logs=[log];c.currency='a'*64;c.implementation='b'*64
            c.observations=[];c.checks=[];c.starts=3
        def run(c):
            if stage_failure:raise ValueError('original stage refused')
            if caught_failure:
                try:c.cleanup()
                except ValueError:pass
            return dict(completed=True,conservation_checks=[])
        with patch.object(module.Campaign,'__init__',initialize),patch.object(module.Campaign,'run',run),patch.object(sys,'argv',
                ['cycle','--binary','/unused/native','--root',str(self.root/'fixture'),'--report',str(path)]):
            if failed or stage_failure:
                with self.assertRaisesRegex(ValueError,'original stage refused' if stage_failure else 'owned process'):
                    module.main()
            else:module.main()
        return json.loads(path.read_text()),processes,log

    def test_both_entrypoints_preserve_primary_failure_and_cleanup_error(self):
        for module in (cycle,joint):
            with self.subTest(module=module.__name__):
                q,processes,log=self.main(module,failed=True,stage_failure=True)
                self.assertEqual(q['failure'],'ValueError: original stage refused')
                self.assertIn('owned process cleanup failed',q['cleanup_failure'])
                self.assertFalse(q['completed']);self.assertFalse(q['owned_process_shutdown_clean'])
                self.assertTrue(q['owned_process_cleanup_verified']);self.assertEqual(processes,{})
                self.assertTrue(log.closed)

    def test_both_entrypoints_forbid_success_with_unclean_real_child(self):
        for module in (cycle,joint):
            with self.subTest(module=module.__name__):
                q,processes,log=self.main(module,failed=True)
                self.assertFalse(q['completed']);self.assertEqual(q['failure'],q['cleanup_failure'])
                self.assertTrue(q['owned_process_cleanup_verified']);self.assertEqual(processes,{})
                self.assertTrue(log.closed)

    def test_caught_phase_shutdown_error_cannot_be_cleared_by_empty_final_cleanup(self):
        q,processes,_=self.main(cycle,failed=True,caught_failure=True)
        self.assertFalse(q['completed']);self.assertFalse(q['owned_process_shutdown_clean'])
        self.assertIn('earlier owned process shutdown',q['failure']);self.assertEqual(processes,{})

    def test_success_is_reported_only_after_all_actual_children_stop_cleanly(self):
        q,processes,log=self.main(cycle)
        self.assertTrue(q['completed']);self.assertIsNone(q['failure'])
        self.assertTrue(q['owned_process_cleanup_verified']);self.assertTrue(q['owned_process_shutdown_clean'])
        self.assertEqual(processes,{});self.assertTrue(log.closed)
        self.assertTrue(all(p.poll()==0 for p in self.children))

    def test_failed_wait_preserves_tuple_key_ownership(self):
        c=cycle.Campaign.__new__(cycle.Campaign);p=Mock();p.poll.return_value=None
        p.wait.side_effect=[subprocess.TimeoutExpired('fixture',30),subprocess.TimeoutExpired('fixture',10)]
        c.processes={('proxima',2):p};c.logs=[]
        with self.assertRaisesRegex(ValueError,'owned process cleanup failed'):c.cleanup()
        self.assertIs(c.processes['proxima',2],p);self.assertTrue(c._unclean_shutdown)

    def test_existing_report_refuses_before_any_fixture_initialization(self):
        p=self.root/'retained-report.json';p.write_text('exact old report')
        args=Mock(report=p,root=self.root/'fixture',binary='/unused/native')
        with patch.object(cycle.Campaign,'__init__') as initialize:
            with self.assertRaisesRegex(ValueError,'already exists'):execute(cycle.Campaign,args,'fixture',Path(__file__))
            initialize.assert_not_called()
        self.assertEqual(p.read_text(),'exact old report')

    def test_constructor_failure_still_writes_original_failure_and_cleanup(self):
        processes=self.children_for(False)
        class Broken(cycle.Campaign):
            def __init__(c,*args):
                c.processes=processes;c.logs=[]
                raise ValueError('original fixture initialization refused')
        p=self.root/'constructor-report.json';args=Mock(report=p,root=self.root/'fixture',binary='/unused/native')
        with self.assertRaisesRegex(ValueError,'original fixture initialization refused'):
            execute(Broken,args,'fixture',Path(__file__))
        q=json.loads(p.read_text());self.assertFalse(q['completed'])
        self.assertEqual(q['failure'],'ValueError: original fixture initialization refused')
        self.assertTrue(q['owned_process_cleanup_verified']);self.assertTrue(q['owned_process_shutdown_clean'])
        self.assertEqual(processes,{})

    def test_incomplete_ownership_observation_cannot_produce_completed(self):
        class Unobserved:
            def __init__(c,*args):pass
            def run(c):return dict(completed=True)
        p=self.root/'unverified-report.json';args=Mock(report=p,root=self.root/'fixture',binary='/unused/native')
        with self.assertRaisesRegex(ValueError,'cleanup is unverified'):
            execute(Unobserved,args,'fixture',Path(__file__))
        q=json.loads(p.read_text());self.assertFalse(q['completed'])
        self.assertIsNone(q['owned_process_cleanup_verified']);self.assertIsNone(q['owned_process_shutdown_clean'])


if __name__=='__main__':unittest.main()
