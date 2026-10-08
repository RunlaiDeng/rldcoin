"""Stop scheduling grants no receipt authority; no Native or socket is run."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from regional_paged_fault_driver import Driver, NativeReadBusy, mature_contact_stop_hint
from regional_paged_fault_launch import PHASES, SLOTS
from test_regional_paged_fault_driver import Model, PROJECT, Relay


def expected():
    return dict(currency='1' * 64, source='2' * 64, destination='3' * 64,
                export='5' * 64, recipient='6' * 64, net_amount='9')


def hint():
    e = expected()
    contact = dict(source=e['source'], destination=e['destination'], export=e['export'],
                   local_height=14, import_height=12, recipient_mature_height=14,
                   evidence_verified=True, import_accepted=True, quarantined=False,
                   original_recipient_output_spendable_now=True,
                   original_recipient_output_remaining='9')
    return dict(native_observation_available=True, native_observation=dict(
        currency=e['currency'], region=e['destination'], local_height=14, contacts=[contact]))


def receipt(e):
    return dict(expected=e, evidence_verified=True, import_accepted=True,
                maturity_reached=True, original_output_spendable_now=True,
                original_output_remaining='9', local_finality_covers_import=True,
                quarantined=False)


class StopModel(Model):
    """Observe sequencing only. Its synthetic values never qualify a network."""
    result_change = None

    def wait(self, label, check):
        if self.phase == 'restored-maturity':
            self.receipt_stop_candidates = [1]
            value = check({slot: None for slot in SLOTS})
            assert value == dict(owned_stop_hint_only=True, receipt_authority=False)
            self.sequence.append('stop-hint-only')
        return super().wait(label, check)

    def call(self, label, n, command, *args):
        assert (label, n, command) == ('proxima', 1 if not self.processes else 0, 'wallet-receipt')
        self.calls.append(dict(command=command))
        if self.processes:
            self.sequence.append('read-busy')
            raise NativeReadBusy('exact native lock unknown')
        self.sequence.append('independent-stopped-native-read')
        value = receipt(self.expectation)
        if self.result_change:
            value[self.result_change[0]] = self.result_change[1]
        return value


class Tests(unittest.TestCase):
    def test_hint_requires_exact_native_observation_and_two_height_maturity(self):
        value = hint()
        before = copy.deepcopy(value)
        self.assertTrue(mature_contact_stop_hint(value, expected(), 14))
        self.assertEqual(value, before)
        for height in (None, True, 13, 15):
            self.assertFalse(mature_contact_stop_hint(value, expected(), height))
        for path, replacement in (
            (('native_observation_available',), False),
            (('native_observation', 'currency'), '7' * 64),
            (('native_observation', 'region'), '7' * 64),
            (('native_observation', 'local_height'), True),
            (('native_observation', 'contacts'), {}),
        ):
            changed = copy.deepcopy(value)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path):
                self.assertFalse(mature_contact_stop_hint(changed, expected(), 14))

    def test_incomplete_wrong_or_quarantined_contact_cannot_schedule_stop(self):
        for key, replacement in (
            ('source', '7' * 64), ('destination', '7' * 64), ('export', '7' * 64),
            ('local_height', 13), ('import_height', True), ('import_height', -1),
            ('recipient_mature_height', 13), ('recipient_mature_height', 15),
            ('evidence_verified', False), ('evidence_verified', 1),
            ('import_accepted', False), ('quarantined', True),
            ('original_recipient_output_spendable_now', False),
            ('original_recipient_output_remaining', '8'),
        ):
            value = hint()
            value['native_observation']['contacts'][0][key] = replacement
            with self.subTest(key=key, replacement=replacement):
                self.assertFalse(mature_contact_stop_hint(value, expected(), 14))
        value = hint()
        value['native_observation']['contacts'] = [None, {}]
        self.assertFalse(mature_contact_stop_hint(value, expected(), 14))

    def test_unknown_observation_keeps_original_independent_receipt_rotation(self):
        driver = Driver.__new__(Driver)
        driver.expectation = expected()
        driver.expectation_path = Path('/not-run')
        driver.calls = []
        driver.file = lambda *args: None
        driver.call = lambda *args: receipt(driver.expectation)
        with patch('regional_paged_fault_driver.time.monotonic', return_value=10):
            self.assertEqual(driver.receipt_ready_for_stop({s: None for s in SLOTS}),
                             receipt(driver.expectation))
        self.assertEqual(driver.receipt_slot, 1)
        self.assertFalse(hasattr(driver, 'receipt_stop_slot'))

    def test_busy_without_stop_hint_remains_unknown_and_real_refusal_stays_fatal(self):
        driver = Driver.__new__(Driver)
        driver.live_receipt = lambda h: (_ for _ in ()).throw(NativeReadBusy('lock'))
        self.assertFalse(driver.receipt_ready_for_stop({}))
        driver.receipt_stop_candidates = [1]
        driver.live_receipt = lambda h: (_ for _ in ()).throw(ValueError('bad signature'))
        with self.assertRaisesRegex(ValueError, 'bad signature'):
            driver.receipt_ready_for_stop({})
        self.assertFalse(hasattr(driver, 'receipt_stop_slot'))

    def test_original_stopped_read_must_succeed_before_keyless_startup_and_cold(self):
        with tempfile.TemporaryDirectory(dir=PROJECT / 'tmp') as tmp:
            model = StopModel(Path(tmp))
            with patch('regional_paged_fault_driver.LiteralFaultRelay', Relay):
                result = model.run()
                model.cleanup()
            order = model.sequence
            self.assertEqual(order[order.index('independent-stopped-native-read') - 1], 'stop')
            self.assertLess(order.index('independent-stopped-native-read'), order.index('startup-pins'))
            self.assertLess(order.index('startup-pins'), order.index('stopped-drain'))
            self.assertLess(order.index('stopped-drain'), order.index('full-cold'))
            self.assertEqual(result['ordinary_service_starts'], 24)
            self.assertEqual((result['stage_seconds'], result['round_seconds'],
                              result['new_height_limit'], result['maturity'], result['quorum']),
                             (600, 60, 24, 2, 3))
            self.assertEqual(model.signed_count, 3)

    def test_hint_cannot_replace_any_original_native_receipt_guard(self):
        for change in (
            ('evidence_verified', False), ('import_accepted', False),
            ('maturity_reached', False), ('original_output_spendable_now', False),
            ('original_output_remaining', '8'), ('local_finality_covers_import', False),
            ('quarantined', True), ('expected', {}),
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=PROJECT / 'tmp') as tmp:
                model = StopModel(Path(tmp))
                model.result_change = change
                with patch('regional_paged_fault_driver.LiteralFaultRelay', Relay):
                    with self.assertRaises(ValueError):
                        model.run()
                    model.cleanup()
                self.assertNotIn('startup-pins', model.sequence)
                self.assertNotIn('stopped-drain', model.sequence)
                self.assertNotIn('full-cold', model.sequence)
                self.assertEqual(model.signed_count, 3)
                self.assertFalse(model.processes)


if __name__ == '__main__':
    unittest.main()
