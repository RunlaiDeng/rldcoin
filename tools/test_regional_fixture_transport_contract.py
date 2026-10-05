"""Regression for the return driver's accidental height/timeout substitution."""
import unittest
from regional_fixture_transport_contract import verify_original_limits


class OriginalTransportContract(unittest.TestCase):
    def setUp(self):
        self.observed = dict(inbound_workers=2, local_attempt_seconds=3.0,
                             local_lock_wait_seconds=0.2)

    def test_original_observation_survives_height_change(self):
        for native_height in (3, 6, 8, 28):
            observation = dict(height=native_height, limits=dict(self.observed))
            verify_original_limits(observation["limits"])
        self.assertNotEqual(self.observed["local_attempt_seconds"], 6.0)

    def test_changed_or_missing_limits_refuse(self):
        for name, value in (("inbound_workers", 3), ("inbound_workers", True),
                            ("local_attempt_seconds", 6.0),
                            ("local_attempt_seconds", "3.0"),
                            ("local_attempt_seconds", float("nan")),
                            ("local_lock_wait_seconds", 0.5)):
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    verify_original_limits(dict(self.observed, **{name: value}))
        for name in self.observed:
            missing = dict(self.observed)
            del missing[name]
            with self.subTest(missing=name):
                with self.assertRaises(ValueError):
                    verify_original_limits(missing)
        with self.assertRaises(ValueError):
            verify_original_limits(None)


if __name__ == "__main__":
    unittest.main()
