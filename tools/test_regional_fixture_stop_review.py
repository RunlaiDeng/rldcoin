import copy
import unittest
from regional_fixture_stop_review import receiving_stop_ready


class ReceivingStopReview(unittest.TestCase):
    def setUp(self):
        self.export = 'a' * 64
        destination = dict(errors=['TCP peer refused custody; retain queued evidence'],
                           rejected=[], consensus=dict(height=10, caller_head_pending=False),
                           native_observation_available=True,
                           native_observation=dict(contacts=[dict(export=self.export,
                               import_accepted=True, original_recipient_output_spendable_now=True,
                               quarantined=False)]))
        source = dict(errors=[], rejected=[], consensus=dict(height=9,
                      caller_head_pending=False, autonomous_signing_enabled=False,
                      explicit_stop_height_reached=True))
        self.rows = [source] + [copy.deepcopy(destination) for _ in range(4)]

    def test_retry_does_not_require_global_silence(self):
        self.assertTrue(receiving_stop_ready(self.rows, self.export, 9))
        self.assertFalse(all(not row['errors'] for row in self.rows))

    def test_unknown_pending_immature_wrong_identity_or_quarantine_never_ready(self):
        for mutation in ('unknown', 'pending', 'immature', 'wrong_export', 'quarantine',
                         'native_busy', 'source_votes', 'missing_value'):
            rows = copy.deepcopy(self.rows)
            if mutation == 'unknown': rows[1]['consensus'].pop('height')
            elif mutation == 'pending': rows[1]['consensus']['caller_head_pending'] = True
            elif mutation == 'immature': rows[1]['native_observation']['contacts'][0]['original_recipient_output_spendable_now'] = False
            elif mutation == 'wrong_export': rows[1]['native_observation']['contacts'][0]['export'] = 'b' * 64
            elif mutation == 'quarantine': rows[1]['native_observation']['contacts'][0]['quarantined'] = True
            elif mutation == 'native_busy': rows[1]['errors'] = ['native rejected: complete stream already locked']
            elif mutation == 'source_votes': rows[0]['consensus']['autonomous_signing_enabled'] = True
            elif mutation == 'missing_value': rows[1]['native_observation_available'] = False
            with self.subTest(mutation=mutation):
                self.assertFalse(receiving_stop_ready(rows, self.export, 9))

    def test_native_or_unexpected_error_is_never_a_transport_retry(self):
        for error in ('native rejected: ', 'native rejected: invalid proof Connection refused',
                      'native rejected: broken owner', 'unexpected failure'):
            rows = copy.deepcopy(self.rows)
            rows[1]['errors'] = [error]
            with self.subTest(error=error), self.assertRaises(ValueError):
                receiving_stop_ready(rows, self.export, 9)
        rows = copy.deepcopy(self.rows)
        rows[1]['rejected'] = ['bad complete envelope']
        with self.assertRaises(ValueError):
            receiving_stop_ready(rows, self.export, 9)


if __name__ == '__main__':
    unittest.main()
