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
        service.config = dict(contacts=[])
        calls = []
        def call(command, *args):
            calls.append(command)
            if command in ('contact-status','contact-observation'):
                count = calls.count(command)
                if initial_failure or (final_failure and count == 2):
                    raise ValueError('Native locked; result unknown')
                status=dict(currency='currency',region='region',contacts=[],observation=count,source_http_required=False)
                if command=='contact-status':return status
                return dict(format='RLD-NATIVE-CONTACT-OBSERVATION-V1',currency='currency',region='region',
                    status=status,outgoing=dict(currency='currency',region='region',offers=[],
                        all_offers_require_native_contact_export_validation=not outgoing_failure),
                    ledger_changed=False,signing_authority=False)
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
            tick=lambda **_:dict(errors=[]), summaries=lambda:{'packet':{}},
            receipts=lambda:{'packet':{}}, transit=lambda _: {}, route=lambda _:None)
        service.native = SimpleNamespace(call=call, apply=apply, currency='currency')
        service.region, service.miner = 'region', None
        service.carriage = None
        service.bft = SimpleNamespace(tick=lambda: {}, failed=False)
        service.tcp = SimpleNamespace(tick=lambda **_:dict(errors=[]))
        service.selection_node = lambda:nullcontext(node)
        node.flush_spool_outgoing=lambda:[]
        service.tcp.ordinary_mesh_node=lambda:nullcontext(node)
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

    def test_failed_consensus_reports_unknown_signing_role_without_stale_progress(self):
        for failure in ('native rejected: regional candidate rejected: BFT signer is already locked',
                        'native rejected: invalid proof',
                        'TCP runtime is stopping; preserve evidence'):
            with self.subTest(failure=failure):
                service=self.service();service.bft.failed=False
                def tick():raise ValueError(failure)
                service.bft.tick=tick
                report=self.tick(service);consensus=report['consensus']
                self.assertIsNone(consensus['autonomous_signing_enabled'])
                self.assertFalse(consensus['progress_observation_available'])
                self.assertEqual(consensus['diagnostic'],failure)
                self.assertNotIn('height',consensus);self.assertNotIn('round',consensus)
                self.assertIn(failure,report['errors'])
                self.assertEqual(service.calls,['contact-observation'])
                # Only a later successful complete observation may show a role.
                service.bft.tick=lambda:dict(autonomous_signing_enabled=False,height=14,round=0)
                later=self.tick(service)
                self.assertFalse(later['consensus']['autonomous_signing_enabled'])
                self.assertEqual(later['consensus']['height'],14)
                self.assertNotIn(failure,later['errors'])

    def test_read_only_tick_requires_one_full_native_read(self):
        service=self.service();report=self.tick(service)
        self.assertEqual(service.calls,['contact-observation'])
        self.assertTrue(report['native_observation_available'])
        self.assertEqual(report['native_observation']['observation'],1)

    def test_next_tick_never_reuses_prior_observation(self):
        service=self.service();self.tick(service);report=self.tick(service)
        self.assertEqual(service.calls.count('contact-observation'),2)
        self.assertEqual(report['native_observation']['observation'],2)

    def test_initial_refusal_is_unknown_and_prevents_receive_outgoing(self):
        service=self.service(kind='regional-bft',initial_failure=True);report=self.tick(service)
        self.assertEqual(service.calls,['contact-observation'])
        self.assertFalse(report['native_observation_available'])
        self.assertIsNone(report['native_observation'])

    def test_value_and_bft_attempts_refresh_even_if_outcome_unknown(self):
        for kind in ('regional-export','regional-bft'):
            for failure in (False,True):
                with self.subTest(kind=kind,failure=failure):
                    service=self.service(kind=kind,mutation_failure=failure);report=self.tick(service)
                    self.assertEqual(service.calls.count('contact-observation'),2)
                    self.assertEqual(report['native_observation']['observation'],2)

    def test_post_attempt_refusal_cannot_publish_first_read_as_fresh(self):
        service=self.service(kind='regional-bft',final_failure=True);report=self.tick(service)
        self.assertFalse(report['native_observation_available'])
        self.assertIsNone(report['native_observation'])
        self.assertTrue(report['errors'])

    def test_incomplete_combined_projection_cannot_release_first_status(self):
        service=self.service(outgoing_failure=True);report=self.tick(service)
        self.assertEqual(service.calls.count('contact-observation'),1)
        self.assertFalse(report['native_observation_available'])
        self.assertIsNone(report['native_observation'])
        self.assertTrue(report['errors'])

    def test_combined_domain_flags_and_projection_identity_refuse(self):
        for mode in ('format','currency','region','ledger','signing','status-domain','offer-domain','extra'):
            with self.subTest(mode=mode):
                service=self.service()
                original=service.native.call
                def changed(command,*args):
                    value=original(command,*args)
                    if mode=='format':value['format']='unknown'
                    elif mode=='currency':value['currency']='foreign'
                    elif mode=='region':value['region']='foreign'
                    elif mode=='ledger':value['ledger_changed']=True
                    elif mode=='signing':value['signing_authority']=True
                    elif mode=='status-domain':value['status']['currency']='foreign'
                    elif mode=='offer-domain':value['outgoing']['region']='foreign'
                    else:value['unexpected']='field'
                    return value
                service.native.call=changed
                report=self.tick(service)
                self.assertEqual(service.calls,['contact-observation'])
                self.assertIsNone(report['native_observation'])
                self.assertTrue(report['errors'])

    def test_unknown_write_must_refresh_before_outgoing_projection(self):
        service=self.service(kind='regional-bft',mutation_failure=True)
        self.tick(service)
        self.assertEqual(service.calls,['contact-observation','bft-receive','contact-observation'])

    def test_refresh_refusal_suppresses_all_outgoing_before_exports(self):
        service=self.service(kind='regional-bft',final_failure=True)
        report=self.tick(service)
        self.assertEqual(service.calls,['contact-observation','bft-receive','contact-observation'])
        self.assertIsNone(report['native_observation'])
        self.assertEqual(report['applied'],[])

    def test_origin_completion_is_current_before_selection_and_unknown_read_clears_it(self):
        service=self.service();original=service.native.call;observed=[]
        def native(command,*args):
            result=original(command,*args)
            result['status']['origin_evidence_message_ids']=['9'*64]
            return result
        service.native.call=native
        service.receive_candidates=lambda *_:observed.append(service._native_origin_messages) or []
        self.tick(service)
        self.assertEqual(observed,[frozenset({'9'*64})])
        def refused(*args):raise ValueError('Native read unknown')
        service.native.call=refused
        report=self.tick(service)
        self.assertEqual(observed[-1],frozenset())
        self.assertIsNone(report['native_observation'])

    def test_malformed_origin_completion_cannot_become_selection_authority(self):
        for ids in ([{}],['bad'],['9'*64,'9'*64],['9'*64,'1'*64],'9'*64):
            service=self.service();original=service.native.call
            def changed(command,*args):
                result=original(command,*args);result['status']['origin_evidence_message_ids']=ids
                return result
            service.native.call=changed
            report=self.tick(service)
            self.assertIsNone(report['native_observation'])
            self.assertEqual(service._native_origin_messages,frozenset())


if __name__ == '__main__':unittest.main()
