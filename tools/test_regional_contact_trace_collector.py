"""Producer association, log failure and gaps cannot masquerade as delivery."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from regional_contact_trace import ContactTrace,TraceCollector,MAX_EVENTS
from regional_ground_resources import Process,Recorder,canonical


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.status=self.root/'status.json';self.log=self.root/'trace.jsonl'
        self.process=Process('owned_test_producer',os.getpid())
        binding=dict(source_set_sha256='a'*64,source_files=1,binary_sha256='b'*64,sampler_sha256='c'*64)
        self.recorder=Recorder(self.log,binding,[self.process],[],1);self.addCleanup(self.recorder.close)
        self.trace=ContactTrace();self.trace.bind('a'*64,'b'*64)
        self.collector=TraceCollector(self.recorder,self.process,self.status,'a'*64,'b'*64)

    def publish(self,pid=None):
        self.status.write_bytes(canonical(dict(process_id=os.getpid() if pid is None else pid,
            contact_trace=self.trace.snapshot(),native_observation={'private_key':'must_not_retain'})))

    def test_exact_producer_metadata_only_in_private_chained_log(self):
        self.trace.event('source_enqueued','c'*64,packet_id='d'*64,envelope_id='e'*64)
        self.publish();first=self.collector.sample();second=self.collector.sample()
        self.assertEqual(len(first['events']),1);self.assertEqual(second['events'],[])
        self.assertNotIn('must_not_retain',self.log.read_text())
        self.assertEqual(self.log.stat().st_mode&0o777,0o600)
        self.assertFalse(first['authority'])

    def test_missing_changed_producer_and_status_pid_are_unknown(self):
        self.assertEqual(self.collector.sample()['reason'],'status_not_regular')
        self.publish(pid=os.getpid()+1)
        self.assertEqual(self.collector.sample()['reason'],'status_pid_mismatch')
        self.publish()
        with patch('regional_ground_resources.process_read',return_value=dict(start='changed',command_sha256='f'*64)):
            self.assertEqual(self.collector.sample()['reason'],'producer_identity_changed')

    def test_evicted_live_observations_are_explicit_and_restart_cannot_adopt_cursor(self):
        for _ in range(MAX_EVENTS+2):self.trace.event('contact_start')
        self.publish();row=self.collector.sample()
        self.assertEqual(row['missed_events'],2);self.assertFalse(row['this_interval_complete'])
        self.trace=ContactTrace();self.trace.bind('a'*64,'b'*64);self.publish()
        self.assertFalse(self.collector.sample()['available'])

    def test_process_observation_timeout_is_unknown(self):
        import subprocess
        with patch('regional_ground_resources.process_read',side_effect=subprocess.TimeoutExpired('ps',2)):
            self.assertEqual(self.collector.sample()['reason'],'producer_observation_unavailable')

    def test_log_fsync_failure_retains_partial_without_recovery_or_success(self):
        self.publish()
        with patch('regional_ground_resources.os.fsync',side_effect=OSError('observer sync failed')):
            with self.assertRaises(OSError):self.collector.sample()
        self.assertTrue(self.log.exists())
        self.assertNotIn('observation_completed',self.log.read_text())


if __name__=='__main__':unittest.main()
