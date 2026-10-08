"""Bounded ordinary source scheduling; model Native replies grant no authority."""
from contextlib import nullcontext
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
import tempfile

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Service,MAX_PER_TICK
import test_regional_contact_observation_scope as observation_scope


class OutgoingScopeTests(unittest.TestCase):
    def source(self,offers=1,candidates=4,ready=True):
        service=observation_scope.ObservationScopeTests(methodName='runTest').service()
        service.bft=None;service.region='1'*64;service.native.currency='a'*64
        service.config={'contacts':[{'outbox':'modeled-directory'}]}
        calls=[];phases=[];queued=[]
        offer_rows=[dict(destination=f'{n+2:064x}',export=f'{n+100:064x}') for n in range(offers)]
        adverts={f'{1000+n*100+j:064x}':{'body':{'region':o['destination']}}
                 for n,o in enumerate(offer_rows) for j in range(candidates)}
        def native(action,*args):
            calls.append(action)
            if action=='contact-observation':
                return dict(format='RLD-NATIVE-CONTACT-OBSERVATION-V1',currency=service.native.currency,
                    region=service.region,status=dict(currency=service.native.currency,region=service.region,
                    contacts=[],source_http_required=False),outgoing=dict(currency=service.native.currency,
                    region=service.region,offers=offer_rows if ready else [],
                    all_offers_require_native_contact_export_validation=True),ledger_changed=False,signing_authority=False)
            if action=='contact-export':
                phases.append('native-export')
                offer=next(o for o in offer_rows if o['export']==args[1])
                return wire.decode_json(wire.make_frame('source-finality',service.region,offer['destination'],
                    offer['export'],b'{"modeled_native_response":"no_ledger_authority"}'))
            raise AssertionError(action)
        def intake(**kwargs):
            phases.append('intake')
            if not kwargs.get('defer_spool_outgoing'):phases.append('outgoing')
            return dict(errors=[])
        def enqueue(raw,to):queued.append((raw,to));phases.append('enqueue');return f'{len(queued):064x}'
        def enqueue_batch(items):return [enqueue(raw,to) for raw,to in items]
        node=SimpleNamespace(id='b'*64,state={'adverts':adverts},tick=intake,
            summaries=lambda:{},receipts=lambda:{},route=lambda to:['b'*64,to],
            enqueue=enqueue,enqueue_batch=enqueue_batch,
            flush_spool_outgoing=lambda:phases.append('outgoing') or [])
        service.native.call=native;service.selection_node=lambda:nullcontext(node)
        service.tcp.ordinary_mesh_node=lambda:nullcontext(node)
        return service,calls,phases,queued,offer_rows,adverts

    def tick(self,service):
        with patch('regional_contact_node.mesh.atomic'):return service.tick()

    def test_native_source_release_precedes_single_directory_send(self):
        service,calls,phases,queued,_,_=self.source()
        result=self.tick(service)
        self.assertFalse(result['errors'])
        self.assertEqual(phases.count('outgoing'),1)
        self.assertGreater(phases.index('outgoing'),phases.index('enqueue'))
        self.assertEqual(phases.count('intake'),1)

    def test_one_offer_uses_original_four_recipient_budget_without_reexport(self):
        service,calls,phases,queued,_,adverts=self.source()
        result=self.tick(service)
        self.assertFalse(result['errors'])
        self.assertEqual({to for _,to in queued},set(adverts))
        self.assertEqual(len(queued),MAX_PER_TICK)
        self.assertEqual(calls.count('contact-export'),1)
        self.assertEqual(len({raw for raw,_ in queued}),1)

    def test_unready_source_does_not_export_or_create_transport_or_value(self):
        service,calls,phases,queued,_,_=self.source(ready=False)
        result=self.tick(service)
        self.assertFalse(result['errors']);self.assertEqual(queued,[])
        self.assertEqual(calls,['contact-observation'])
        self.assertEqual(phases,['intake','outgoing'])

    def test_each_selected_offer_keeps_first_service_before_spare_recipients(self):
        service,calls,phases,queued,offers,_=self.source(offers=4)
        result=self.tick(service)
        self.assertFalse(result['errors']);self.assertEqual(len(queued),4)
        self.assertEqual(calls.count('contact-export'),4)
        self.assertEqual({wire.inspect_frame(raw)[0]['export_id'] for raw,_ in queued},
                         {o['export'] for o in offers})

    def test_more_offers_and_recipients_rotate_under_original_budget(self):
        service,calls,phases,queued,offers,adverts=self.source(offers=7,candidates=5)
        seen=set()
        for _ in range(35):
            queued.clear();result=self.tick(service);self.assertFalse(result['errors'])
            self.assertLessEqual(len(queued),4)
            seen.update((wire.inspect_frame(raw)[0]['export_id'],to) for raw,to in queued)
        expected={(o['export'],to) for o in offers for to,a in adverts.items()
                  if a['body']['region']==o['destination']}
        self.assertEqual(seen,expected)

    def test_actual_directory_source_unit_and_cold_transport_custody(self):
        from test_interstellar_mesh import Fixture
        with tempfile.TemporaryDirectory() as directory:
            fixture=Fixture(directory);fixture.rounds()
            service,calls,_,_,offers,_=self.source(candidates=1)
            offers[0]['destination']='2'*64
            service.config=fixture.configs['earth'];service.root=Path(service.config['state'])
            service.path=service.root/'modeled-native-progress.json'
            service.selection_node=lambda:fixture.node('earth')
            service.tcp.ordinary_mesh_node=lambda:fixture.node('earth')
            result=service.tick();self.assertFalse(result['errors'])
            peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as source:
                packets=[ident for ident,row in source.summaries().items()
                         if row['source']==source.id and row['destination']==peer
                         and row['kind']=='source-finality']
                self.assertEqual(len(packets),1)
                self.assertNotIn(packets[0],source.receipts())
                retained=wire.canonical(source.state['messages'][packets[0]])
            with fixture.node('proxima') as receiver:
                self.assertFalse(receiver.tick()['errors'])
                self.assertIn(packets[0],receiver.receipts())
            with fixture.node('proxima') as cold:
                self.assertIn(packets[0],cold.receipts())
                transit=cold.transit(packets[0])
                frame,_=wire.inspect_frame(mesh.transit_check(transit,cold.network)[1])
                self.assertEqual(frame['kind'],'source-finality')
            # Repeated exact export reconciles original custody before enqueue.
            self.assertFalse(service.tick()['errors'])
            with fixture.node('earth') as source:
                self.assertEqual(wire.canonical(source.state['messages'][packets[0]]),retained)
                self.assertEqual(len([row for row in source.summaries().values()
                    if row['source']==source.id and row['destination']==peer
                    and row['kind']=='source-finality']),1)
            self.assertEqual(calls.count('contact-export'),2)

    def test_failed_native_export_or_queue_never_releases_success(self):
        for failure in ('native','queue'):
            with self.subTest(failure=failure):
                service,calls,phases,queued,_,_=self.source()
                original=service.native.call
                if failure=='native':
                    def call(action,*args):
                        if action=='contact-export':raise ValueError('model native proof refused')
                        return original(action,*args)
                    service.native.call=call
                else:
                    with service.tcp.ordinary_mesh_node() as node:
                        def enqueue(items):raise OSError('model durable admission refused')
                        node.enqueue_batch=enqueue
                result=self.tick(service)
                self.assertTrue(result['errors']);self.assertEqual(queued,[])
                self.assertEqual(result['applied'],[])
