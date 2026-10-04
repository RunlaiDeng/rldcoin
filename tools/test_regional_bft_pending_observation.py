"""Unknown optional telemetry cannot authorize a pending-evidence stage."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import interstellar_mesh as mesh
from regional_bft_multiregion_campaign import Campaign


class PendingObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='rld-pending-observation-')
        self.addCleanup(temporary.cleanup)
        self.campaign = Campaign.__new__(Campaign)
        self.campaign.root = Path(temporary.name)
        self.campaign.processes = {('andromeda', n): Mock(pid=100 + n) for n in range(4)}
        for process in self.campaign.processes.values():
            process.poll.return_value = None
        self.campaign.observations = []
        self.campaign.progress = Mock()
        for method in ('cli', 'invoke', 'sign', 'audit'):
            setattr(self.campaign, method, Mock(side_effect=AssertionError('Native/signature call forbidden')))
        self.export = 'a' * 64
        self.values = {}
        for replica in range(4):
            self.campaign.mesh_root(('andromeda', replica)).mkdir()
            self.save(replica, self.available(replica))

    def available(self, replica):
        return dict(process_id=100 + replica, native_observation_available=True,
                    native_observation={'contacts': [dict(export=self.export,
                        evidence_verified=True, import_accepted=False)]}, errors=[])

    def save(self, replica, value):
        self.values[replica] = copy.deepcopy(value)
        path = self.campaign.mesh_root(('andromeda', replica)) / 'regional-contact-status.json'
        mesh.atomic(path, value)

    def bytes(self):
        return {str(path): path.read_bytes()
                for path in self.campaign.root.rglob('*') if path.is_file()}

    def assert_no_authority_calls(self):
        for method in ('cli', 'invoke', 'sign', 'audit'):
            getattr(self.campaign, method).assert_not_called()

    def test_none_is_unknown_for_each_replica_without_height_or_credit(self):
        for replica in range(4):
            with self.subTest(replica=replica):
                unavailable = dict(process_id=100 + replica, native_observation_available=False,
                                   native_observation=None, errors=['native lock contention'])
                self.save(replica, unavailable)
                before = self.bytes()
                self.assertFalse(self.campaign.pending('andromeda', self.export))
                self.assertEqual(self.bytes(), before)
                self.assertNotIn('height', unavailable)
                self.assertEqual(self.campaign.observations, [])
                self.assert_no_authority_calls()
                self.save(replica, self.available(replica))

    def test_available_flag_cannot_turn_none_into_a_pending_record(self):
        self.save(2, dict(process_id=102, native_observation_available=True,
                          native_observation=None, errors=[]))
        self.assertFalse(self.campaign.pending('andromeda', self.export))
        self.assert_no_authority_calls()

    def test_unavailable_dictionary_cannot_authorize_a_stage(self):
        for flag in (False, None, 1, 'true'):
            with self.subTest(flag=flag):
                value = self.available(3)
                value['native_observation_available'] = flag
                self.save(3, value)
                self.assertFalse(self.campaign.pending('andromeda', self.export))
        value = self.available(3)
        del value['native_observation_available']
        self.save(3, value)
        self.assertFalse(self.campaign.pending('andromeda', self.export))
        self.assert_no_authority_calls()

    def test_all_four_current_available_verified_unimported_records_pass(self):
        self.assertTrue(self.campaign.pending('andromeda', self.export))
        self.assertEqual(self.campaign.observations, [])
        self.assert_no_authority_calls()

    def test_exact_export_and_all_original_record_predicates_remain_required(self):
        bad_records = [[], [dict(export='b' * 64, evidence_verified=True, import_accepted=False)],
                       [dict(export=self.export, evidence_verified=False, import_accepted=False)],
                       [dict(export=self.export, evidence_verified=True, import_accepted=True)],
                       [dict(export=self.export, evidence_verified=True, import_accepted=False),
                        dict(export=self.export, evidence_verified=False, import_accepted=False)]]
        for records in bad_records:
            with self.subTest(records=records):
                value = self.available(3)
                value['native_observation']['contacts'] = records
                self.save(3, value)
                self.assertFalse(self.campaign.pending('andromeda', self.export))
        self.assert_no_authority_calls()

    def test_later_available_observation_completes_same_original_wait(self):
        self.save(2, dict(process_id=102, native_observation_available=False,
                          native_observation=None, errors=['native lock contention']))
        def available_after_first_unknown(delay):
            self.assertEqual(delay, 0.2)
            self.assertEqual(self.campaign.observations, [])
            self.save(2, self.available(2))
        with patch('regional_bft_multiregion_campaign.time.monotonic', side_effect=[0, 0, 0.2, 0.25]), \
             patch('regional_bft_multiregion_campaign.time.sleep', side_effect=available_after_first_unknown) as sleep:
            result = self.campaign.wait(lambda: self.campaign.pending('andromeda', self.export),
                                        'original pending export', 600)
        self.assertTrue(result)
        sleep.assert_called_once_with(0.2)
        self.assertEqual(self.campaign.observations, [dict(phase='original pending export',
            elapsed_seconds=0.25, observation_bound_seconds=600)])
        self.campaign.progress.assert_any_call('waiting: original pending export')
        self.campaign.progress.assert_any_call('verified: original pending export')
        self.assert_no_authority_calls()

    def test_persistent_unknown_reaches_original_deadline_with_no_fabricated_height(self):
        self.save(2, dict(process_id=102, native_observation_available=False,
                          native_observation=None, errors=['native lock contention']))
        before = self.bytes()
        with patch('regional_bft_multiregion_campaign.time.monotonic', side_effect=[0, 0, 601]), \
             patch('regional_bft_multiregion_campaign.time.sleep'), \
             self.assertRaisesRegex(ValueError, 'bounded ground observation deadline: pending export ') as caught:
            self.campaign.wait(lambda: self.campaign.pending('andromeda', self.export), 'pending export', 600)
        diagnostic = json.loads(str(caught.exception).split('pending export ', 1)[1])["('andromeda', 2)"]
        self.assertTrue(diagnostic['observation_available'])
        self.assertFalse(diagnostic['native_observation_available'])
        self.assertNotIn('height', diagnostic)
        self.assertEqual(self.campaign.observations, [])
        self.assertEqual(self.bytes(), before)
        self.assert_no_authority_calls()

    def test_previous_process_observation_still_refuses(self):
        value = self.available(2)
        value['process_id'] = 99
        self.save(2, value)
        with self.assertRaisesRegex(ValueError, 'observation belongs to previous process'):
            self.campaign.pending('andromeda', self.export)
        self.assertEqual(self.campaign.observations, [])
        self.assert_no_authority_calls()


if __name__ == '__main__':
    unittest.main()
