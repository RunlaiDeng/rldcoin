"""OS observation scope and real reaped CPU child; no Native qualification."""
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import sys
import unittest
from unittest.mock import patch

from regional_ground_resources import Process
from regional_ground_child_cpu import ExitedChildCpu


class ChildCpuTests(unittest.TestCase):
    def anchor(self):
        process=Process.__new__(Process);process.label='owned_test';process.pid=123
        process.identity=('start','a'*64)
        return process

    def test_matching_parent_delta_and_exited_cpu_preserve_scope(self):
        own=dict(start='start',command_sha256='a'*64,cpu_seconds=1)
        first=dict(own,cpu_seconds=3,process_start_abstime=100,exited_children_cpu_seconds=2)
        second=dict(first,cpu_seconds=5,exited_children_cpu_seconds=4)
        with patch('regional_ground_child_cpu.process_read',return_value=own), \
             patch('regional_ground_child_cpu.inclusive_read',side_effect=[first,second]), \
             patch('regional_ground_child_cpu.time.monotonic',side_effect=[0,1,2,3]):
            observer=ExitedChildCpu(self.anchor());a=observer.sample();b=observer.sample()
        self.assertIsNone(a['own_plus_exited_children_one_core_percent'])
        self.assertEqual(b['own_plus_exited_children_one_core_percent'],100)
        self.assertEqual(b['non_atomic_exited_children_estimate_seconds'],4)
        self.assertFalse(b['Native_command_census_verified'])
        self.assertFalse(b['observation_includes_all_live_child_cpu'])

    def test_pid_change_unavailable_and_counter_regression_return_unknown(self):
        own=dict(start='start',command_sha256='a'*64,cpu_seconds=1)
        combined=dict(own,process_start_abstime=100,exited_children_cpu_seconds=0)
        for later in (dict(combined,start='other'),dict(combined,command_sha256='b'*64),dict(combined,cpu_seconds=0),ValueError('missing')):
            with patch('regional_ground_child_cpu.process_read',return_value=own), \
                 patch('regional_ground_child_cpu.inclusive_read',side_effect=[later]):
                row=ExitedChildCpu(self.anchor()).sample()
            self.assertFalse(row['available'])
            self.assertIsNone(row['own_plus_exited_children_cpu_lifetime_seconds'])

    def test_kernel_start_and_exited_counter_changes_remain_unknown(self):
        own=dict(start='start',command_sha256='a'*64,cpu_seconds=1)
        first=dict(own,cpu_seconds=3,process_start_abstime=100,exited_children_cpu_seconds=2)
        for changed in (dict(first,process_start_abstime=101),
                        dict(first,cpu_seconds=4,exited_children_cpu_seconds=1)):
            with patch('regional_ground_child_cpu.process_read',return_value=own), \
                 patch('regional_ground_child_cpu.inclusive_read',side_effect=[first,changed,first]):
                observer=ExitedChildCpu(self.anchor())
                self.assertTrue(observer.sample()['available'])
                self.assertFalse(observer.sample()['available'])
                again=observer.sample()
                self.assertTrue(again['available'])
                self.assertIsNone(again['own_plus_exited_children_one_core_percent'])

    def test_anchor_fields_are_retained_and_never_adopt_mutated_process(self):
        anchor=self.anchor();observer=ExitedChildCpu(anchor);anchor.pid=456;anchor.label='changed'
        with patch('regional_ground_child_cpu.process_read',side_effect=ValueError('absent')) as read:
            row=observer.sample()
        read.assert_called_once_with(123)
        self.assertEqual(row['label'],'owned_test')

    @unittest.skipUnless(platform.system()=='Darwin','backend verified on macOS only')
    def test_real_owned_parent_reaps_cpu_child_and_os_retains_its_time(self):
        child_code='import time\nstart=time.process_time()\nwhile time.process_time()-start<0.3: pass\n'
        parent_code='import subprocess,sys\nsubprocess.run([sys.executable,"-B","-c",'+repr(child_code)+'],check=True)\nprint("child_reaped",flush=True)\nsys.stdin.readline()\n'
        parent=subprocess.Popen([sys.executable,'-B','-c',parent_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([parent.stdout],[],[],3)[0])
            self.assertEqual(parent.stdout.readline().strip(),'child_reaped')
            observer=ExitedChildCpu(Process('owned_parent',parent.pid))
            row=observer.sample()
            self.assertTrue(row['available'])
            self.assertGreaterEqual(row['non_atomic_exited_children_estimate_seconds'],0.25)
            self.assertFalse(row['live_child_rss_measured'])
        finally:
            if parent.poll() is None:
                parent.stdin.write('\n');parent.stdin.flush()
            parent.wait(timeout=3);parent.stdin.close();parent.stdout.close()


if __name__=='__main__':unittest.main()
