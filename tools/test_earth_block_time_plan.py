import unittest

import earth_block_time_plan as plan


class BlockTimePlanTests(unittest.TestCase):
    def test_one_millisecond_has_exact_consequences(self):
        result = plan.compare(1)
        values = result['parameters']
        self.assertEqual(values['contest_window']['unchanged_count_target_duration_ms'], 2016)
        self.assertEqual(values['emission_era']['unchanged_count_target_duration_ms'], 200_000)
        self.assertEqual(values['contest_window']['count_to_preserve_at_least_current_target_duration'], 1_209_600_000)
        self.assertFalse(result['production_interval_selected'])
        self.assertFalse(result['production_changed'])

    def test_rounding_never_shortens_existing_time_target(self):
        for interval in (1, 7, 1000, 10_000, 600_000, 86_400_000):
            result = plan.compare(interval)
            for parameter in result['parameters'].values():
                baseline = parameter['current_target_duration_ms']
                count = parameter['count_to_preserve_at_least_current_target_duration']
                self.assertGreaterEqual(count * interval, baseline)
                self.assertLess((count - 1) * interval, baseline)

    def test_invalid_or_fractional_intervals_rejected(self):
        for interval in (0, -1, 86_400_001, True, 1.0, '1'):
            with self.assertRaises(ValueError):
                plan.compare(interval)


if __name__ == '__main__':
    unittest.main()
