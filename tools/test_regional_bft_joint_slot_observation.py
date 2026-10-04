"""Optional telemetry is unknown; it never authenticates an epoch or signer."""
import unittest
from regional_bft_joint_cycle_campaign import observe_joint_slot

class JointSlotObservationTests(unittest.TestCase):
    def test_known_new_slot_reports_new(self):
        self.assertEqual(observe_joint_slot(dict(consensus=dict(joint_active_slot='new',height=7))),'new')
    def test_explicit_native_lock_unknown_is_retained_without_fabricated_slot(self):
        q=dict(consensus=dict(progress_observation_available=False,diagnostic='native OS lock contention'))
        self.assertIsNone(observe_joint_slot(q));self.assertNotIn('joint_active_slot',q['consensus'])
    def test_wrong_known_slot_refuses_even_with_unknown_flag(self):
        for slot in ('old',None,2):
            with self.assertRaises(ValueError):observe_joint_slot(dict(consensus=dict(joint_active_slot=slot,progress_observation_available=False,diagnostic='lock')))
    def test_absent_untyped_or_unsupported_telemetry_refuses(self):
        for q in ({},{'consensus':None},{'consensus':{}},{'consensus':{'progress_observation_available':True,'diagnostic':'lock'}}, {'consensus':{'progress_observation_available':False,'diagnostic':''}}, {'consensus':{'progress_observation_available':False,'diagnostic':'x'*257}}, {'consensus':{'progress_observation_available':False,'diagnostic':'lock','height':0}}, {'consensus':{'progress_observation_available':False,'diagnostic':'lock','round':0}}):
            with self.subTest(q=q),self.assertRaises(ValueError):observe_joint_slot(q)
if __name__=='__main__':unittest.main()
