"""Same-tick read orchestration only; fake responses grant no Native authority."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_contact_node import Service


class ObservationScopeTests(unittest.TestCase):
    def service(self, kind=None, initial_failure=False, final_failure=False,
                mutation_failure=False, outgoing_failure=False):
        service = Service.__new__(Service)
        calls = []
        def call(command, *args):
            calls.append(command)
            if command == 'contact-status':
                count = calls.count(command)
                if initial_failure or (final_failure and count == 2):
                    raise ValueError('Native locked; result unknown')
                return dict(currency='currency', region='region', contacts=[], observation=count)
            if command == 'contact-outgoing':
                if outgoing_failure:raise ValueError('Native outgoing refused')
                return {'offers': []}
            raise AssertionError(command)
        def apply(raw, miner):
            calls.append('contact-apply')
            if mutation_failure:raise ValueError('Native apply outcome unknown')
            return {'accepted': True}
        def receive(entries, errors, rejected, deferred):
            calls.append('bft-receive')
            if mutation_failure:errors.append('Native BFT sync outcome unknown')
        node = SimpleNamespace(id='node', network='currency', state={'adverts': {}},
            tick=lambda:dict(errors=[]), summaries=lambda:{'packet':{}},
            receipts=lambda:{'packet':{}}, transit=lambda _: {}, route=lambda _:None)
        service.native = SimpleNamespace(call=call, apply=apply, currency='currency')
        service.region, service.miner = 'region', None
        service.carriage = None
        service.bft = SimpleNamespace(tick=lambda: {}, failed=False)
        service.tcp = SimpleNamespace(tick=lambda:dict(errors=[]))
        service.selection_node = lambda:nullcontext(node)
        service.receive_candidates = lambda *_:['packet'] if kind else []
        service.receive_bft_batch = receive
        service.bft_individual_retry = False
        service.contact_trace = None
        service.local_os_error_history = ()
        service.progress = {'cursor':0}
        service.path = Path('/unused/model-progress')
        service.root = Path('/unused/model-root')
        service.kind, service.calls = kind, calls
        return service

    def tick(self, service):
        with patch('regional_contact_node.mesh.atomic'), \
             patch('regional_contact_node.mesh.transit_check', return_value=({},b'raw',[])), \
             patch('regional_contact_node.mesh.receipt_matches'), \
             patch('regional_contact_node.wire.inspect_frame', return_value=({'kind':service.kind,'message_id':'message'},b'')):
            return service.tick()

    def test_read_only_tick_requires_one_full_native_read(self):
        service=self.service();report=self.tick(service)
        self.assertEqual(service.calls,['contact-status','contact-outgoing'])
        self.assertTrue(report['native_observation_available'])
        self.assertEqual(report['native_observation']['observation'],1)

    def test_next_tick_never_reuses_prior_observation(self):
        service=self.service();self.tick(service);report=self.tick(service)
        self.assertEqual(service.calls.count('contact-status'),2)
        self.assertEqual(report['native_observation']['observation'],2)

    def test_initial_refusal_is_unknown_and_prevents_receive_outgoing(self):
        service=self.service(kind='regional-bft',initial_failure=True);report=self.tick(service)
        self.assertEqual(service.calls,['contact-status'])
        self.assertFalse(report['native_observation_available'])
        self.assertIsNone(report['native_observation'])

    def test_value_and_bft_attempts_refresh_even_if_outcome_unknown(self):
        for kind in ('regional-export','regional-bft'):
            for failure in (False,True):
                with self.subTest(kind=kind,failure=failure):
                    service=self.service(kind=kind,mutation_failure=failure);report=self.tick(service)
                    self.assertEqual(service.calls.count('contact-status'),2)
                    self.assertEqual(report['native_observation']['observation'],2)

    def test_post_attempt_refusal_cannot_publish_first_read_as_fresh(self):
        service=self.service(kind='regional-bft',final_failure=True);report=self.tick(service)
        self.assertFalse(report['native_observation_available'])
        self.assertIsNone(report['native_observation'])
        self.assertTrue(report['errors'])

    def test_read_only_outgoing_refusal_retains_same_tick_observation_and_error(self):
        service=self.service(outgoing_failure=True);report=self.tick(service)
        self.assertEqual(service.calls.count('contact-status'),1)
        self.assertTrue(report['native_observation_available'])
        self.assertTrue(report['errors'])


if __name__ == '__main__':unittest.main()
