"""Controller launch mechanics only; mock readiness grants no native authority."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from regional_bft_role_missing_leader_campaign import Campaign
from regional_bft_network_campaign import COLD_START_OBSERVATION_SECONDS

class GroupStartTests(unittest.TestCase):
    def fixture(self,root):
        c=object.__new__(Campaign);c.root=Path(root);c.binary=Path('/fixture/binary');c.currency='a'*64
        c.processes={};c.logs=[];c.starts=0;c.ports={n:10000+n for n in range(5)}
        c.node=lambda region,n:c.root/f'{region}-{n}'
        c.observation=lambda n:dict(native_observation_available=True)
        self.addCleanup(lambda:[f.close() for f in c.logs])
        return c
    def test_all_four_launch_before_any_readiness_wait_and_exact_normal_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            c=self.fixture(d);calls=[]
            def launch(args,**kw):
                calls.append(args);return object()
            def wait(check,label,bound):
                self.assertEqual(set(c.processes),{1,2,3,4});self.assertTrue(check())
                self.assertEqual(bound,COLD_START_OBSERVATION_SECONDS)
            c.wait=wait
            with patch('regional_bft_role_missing_leader_campaign.subprocess.Popen',side_effect=launch):c.start_group((1,2,3,4))
            self.assertEqual(c.starts,4);self.assertEqual(len(calls),4)
            for n,args in zip((1,2,3,4),calls):
                self.assertEqual(args[0],str(c.binary));self.assertEqual(args[args.index('--dir')+1],str(c.root/f'earth-{n}'))
                self.assertIn('--bft-config',args);self.assertIn('--mesh-config',args)
                self.assertEqual(args[-2:],['--interval','0.25'])
    def test_second_launch_failure_retains_first_owned_process_and_open_logs(self):
        with tempfile.TemporaryDirectory() as d:
            c=self.fixture(d);owned=object();c.wait=lambda *a:self.fail('wait before all launches')
            with patch('regional_bft_role_missing_leader_campaign.subprocess.Popen',side_effect=[owned,OSError('launch failed')]):
                with self.assertRaises(OSError):c.start_group((1,2,3,4))
            self.assertEqual(c.processes,{1:owned});self.assertEqual(c.starts,1)
            self.assertEqual(len(c.logs),2);self.assertTrue(all(not f.closed for f in c.logs))
    def test_readiness_failure_retains_every_owned_process(self):
        with tempfile.TemporaryDirectory() as d:
            c=self.fixture(d);c.wait=lambda *a:(_ for _ in ()).throw(ValueError('native readiness unknown'))
            with patch('regional_bft_role_missing_leader_campaign.subprocess.Popen',side_effect=lambda *a,**kw:object()):
                with self.assertRaises(ValueError):c.start_group(range(5))
            self.assertEqual(set(c.processes),set(range(5)));self.assertEqual(c.starts,5)
    def test_duplicate_existing_bool_and_foreign_slots_refuse_before_launch(self):
        for group in ((1,1),(True,),(5,),(-1,),(2,)):
            with self.subTest(group=group),tempfile.TemporaryDirectory() as d:
                c=self.fixture(d);c.processes[2]=object();c.wait=lambda *a:self.fail('wait')
                with patch('regional_bft_role_missing_leader_campaign.subprocess.Popen',side_effect=AssertionError('launch')):
                    with self.assertRaises(ValueError):c.start_group(group)
                self.assertEqual(set(c.processes),{2});self.assertEqual(c.starts,0);self.assertFalse(c.logs)
if __name__=='__main__':unittest.main()
