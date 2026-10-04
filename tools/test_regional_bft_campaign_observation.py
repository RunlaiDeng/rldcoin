"""Controller telemetry failures never invent progress or mask a deadline.

Only process/time observation is simulated. No ledger or cryptographic
authorization is constructed by these tests.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import interstellar_mesh as mesh
from regional_bft_network_campaign import Campaign
from regional_bft_multiregion_campaign import Campaign as MultiregionCampaign


class CampaignObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-observation-')
        self.c=Campaign.__new__(Campaign)
        self.c.root=Path(self.temp.name)
        (self.c.root/'mesh-0').mkdir()
        self.c.processes={0:Mock(pid=100)}
        self.c.processes[0].poll.return_value=None
        self.c.observations=[]

    def tearDown(self):self.temp.cleanup()

    def save(self,value):mesh.atomic(self.c.root/'mesh-0/regional-contact-status.json',value)

    def timeout(self):
        with patch('regional_bft_network_campaign.time.monotonic',side_effect=[0,0,2]), \
             patch('regional_bft_network_campaign.time.sleep'), \
             self.assertRaisesRegex(ValueError,'bounded ground observation deadline: cold start') as caught:
            self.c.wait(lambda:self.c.observation(0)['native_observation_available'],'cold start',1)
        return json.loads(str(caught.exception).split('cold start ',1)[1])['0']

    def test_stale_pid_keeps_actual_deadline_and_unknown_observation(self):
        self.save(dict(process_id=99,native_observation_available=True,consensus=dict(height=999),errors=[]))
        row=self.timeout()
        self.assertFalse(row['observation_available'])
        self.assertIn('previous process',row['diagnostic'])
        self.assertNotIn('height',row)
        self.assertEqual(self.c.observations,[])

    def test_absent_status_keeps_deadline_without_fabricating_progress(self):
        row=self.timeout()
        self.assertFalse(row['observation_available'])
        self.assertNotIn('height',row)

    def test_current_unknown_native_telemetry_is_not_height_zero(self):
        self.save(dict(process_id=100,native_observation_available=False,errors=['native lock contention']))
        self.assertFalse(self.c.reached((0,),0))
        row=self.timeout()
        self.assertTrue(row['observation_available'])
        self.assertFalse(row['native_observation_available'])
        self.assertEqual(row['errors'],['native lock contention'])
        self.assertNotIn('height',row)

    def test_current_height_observation_records_success_with_its_bound(self):
        self.save(dict(process_id=100,native_observation_available=True,consensus=dict(height=11)))
        with patch('regional_bft_network_campaign.time.monotonic',side_effect=[0,0,0.25]):
            self.c.wait(lambda:self.c.reached((0,),11),'height eleven',1)
        self.assertEqual(self.c.observations,[dict(phase='height eleven',elapsed_seconds=0.25,observation_bound_seconds=1)])

    def test_exited_process_is_reported_without_waiting_for_a_deadline(self):
        self.c.processes[0].poll.return_value=7
        with self.assertRaisesRegex(ValueError,'autonomous node exited: 0'):
            self.c.wait(lambda:True,'startup',1)
        self.assertEqual(self.c.observations,[])


class MultiregionObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-multiregion-observation-')
        self.addCleanup(self.temp.cleanup)
        self.c=MultiregionCampaign.__new__(MultiregionCampaign)
        self.c.root=Path(self.temp.name)
        self.c.processes={('earth',n):Mock(pid=100+n) for n in range(4)}
        for process in self.c.processes.values():process.poll.return_value=None
        self.c.observations=[];self.c.calls=0;self.c.starts=4
        self.c.currency='a'*64;self.c.implementation='b'*64
        for n in range(4):
            (self.c.root/f'mesh-earth-{n}').mkdir()
            self.save(n,dict(process_id=100+n,native_observation_available=True,
                             consensus=dict(height=0),errors=[]))

    def save(self,n,value):
        mesh.atomic(self.c.root/f'mesh-earth-{n}/regional-contact-status.json',value)

    def timeout(self):
        with patch('regional_bft_multiregion_campaign.time.monotonic',side_effect=[0,0,2]), \
             patch('regional_bft_multiregion_campaign.time.sleep'), \
             self.assertRaisesRegex(ValueError,'bounded ground observation deadline: genesis pause') as caught:
            self.c.wait(lambda:self.c.reached_region('earth',0),'genesis pause',1)
        return json.loads(str(caught.exception).split('genesis pause ',1)[1])

    def test_unknown_or_boolean_height_cannot_pass_three_region_genesis_pause(self):
        self.save(2,dict(process_id=102,native_observation_available=False,
                         errors=['native lock contention']))
        self.assertFalse(self.c.reached_region('earth',0))
        diagnostic=self.timeout()["('earth', 2)"]
        self.assertTrue(diagnostic['observation_available'])
        self.assertFalse(diagnostic['native_observation_available'])
        self.assertNotIn('height',diagnostic)
        self.assertEqual(self.c.observations,[])
        self.save(2,dict(process_id=102,native_observation_available=True,consensus=dict(height=False)))
        self.assertFalse(self.c.reached_region('earth',0))

    def test_stale_replica_pid_cannot_replace_the_real_multiregion_deadline(self):
        self.save(1,dict(process_id=99,native_observation_available=True,consensus=dict(height=0)))
        diagnostic=self.timeout()["('earth', 1)"]
        self.assertFalse(diagnostic['observation_available'])
        self.assertIn('previous process',diagnostic['diagnostic'])
        self.assertNotIn('height',diagnostic)
        self.assertEqual(self.c.observations,[])

    def test_all_four_actual_zero_observations_pass_the_explicit_height_gate(self):
        with patch('regional_bft_multiregion_campaign.time.monotonic',side_effect=[0,0,0.25]):
            self.c.wait(lambda:self.c.reached_region('earth',0),'genesis pause',1)
        self.assertEqual(self.c.observations,[dict(phase='genesis pause',elapsed_seconds=0.25,observation_bound_seconds=1)])


if __name__=='__main__':unittest.main()
