"""Observation scheduling counterexamples; mocks grant no Native authority."""
import unittest
from unittest.mock import Mock, patch

from regional_native_receipt_probe import NativeReplicaReceiptProbe


class ReplicaReceiptProbeTests(unittest.TestCase):
    def attempt(self, probe, now, read, accepts=lambda value:bool(value)):
        with patch('regional_native_receipt_probe.time.monotonic', return_value=now):
            return probe.attempt(read, accepts)

    def test_fixed_immature_replica_does_not_hide_other_observed_mature_replica(self):
        probe=NativeReplicaReceiptProbe()
        read=Mock(side_effect=lambda replica:False if replica==1 else {'observed':replica})
        self.assertIs(self.attempt(probe,1,read),False)
        self.assertIs(self.attempt(probe,2,read),False)
        self.assertEqual(self.attempt(probe,3,read),{'observed':2})
        self.assertEqual([call.args[0] for call in read.call_args_list],[1,2])
        self.assertEqual(probe.attempts,2)

    def test_each_actual_read_rotates_and_throttled_attempt_does_not_rotate(self):
        probe=NativeReplicaReceiptProbe();read=Mock(return_value=False)
        for now in range(1,17):self.attempt(probe,now,read)
        self.assertEqual([call.args[0] for call in read.call_args_list],[1,2,3,0]*2)
        self.assertEqual(set(vars(probe)),{'next_read','attempts','next_replica'})

    def test_busy_native_failure_advances_without_inventing_authority(self):
        probe=NativeReplicaReceiptProbe();read=Mock(side_effect=[ValueError('native lock refusal'),{'observed':2}])
        with self.assertRaisesRegex(ValueError,'native lock refusal'):self.attempt(probe,1,read)
        self.assertIs(self.attempt(probe,2,read),False)
        self.assertEqual(self.attempt(probe,3,read),{'observed':2})
        self.assertEqual([call.args[0] for call in read.call_args_list],[1,2])

    def test_success_is_never_reused_by_skip_or_invalid_later_read(self):
        probe=NativeReplicaReceiptProbe();read=Mock(side_effect=[{'fresh':True},False])
        self.assertEqual(self.attempt(probe,1,read),{'fresh':True})
        self.assertIs(self.attempt(probe,2,read),False)
        self.assertIs(self.attempt(probe,3,read),False)
        self.assertEqual(read.call_count,2)

    def test_wrong_expected_quarantine_and_missing_finality_do_not_pass(self):
        expected={'payment':'exact'}
        good=dict(expected=expected,original_output_spendable_now=True,local_finality_covers_import=True,quarantined=False)
        accepts=lambda value:value['expected']==expected and value['original_output_spendable_now'] and value['local_finality_covers_import'] and not value['quarantined']
        for field,value in [('expected',{'payment':'other'}),('quarantined',True),('local_finality_covers_import',False),('original_output_spendable_now',False)]:
            with self.subTest(field=field):
                probe=NativeReplicaReceiptProbe();read=Mock(return_value=dict(good,**{field:value}))
                for now in (1,3,5,7):self.assertIs(self.attempt(probe,now,read,accepts),False)
                self.assertEqual(read.call_count,4)

    def test_new_observer_after_restart_has_no_previous_receipt(self):
        first=NativeReplicaReceiptProbe();self.attempt(first,1,lambda replica:True)
        second=NativeReplicaReceiptProbe();read=Mock(return_value=False)
        self.assertIs(self.attempt(second,1,read),False)
        read.assert_called_once_with(1)


if __name__=='__main__':unittest.main()
