"""Typed Native receive refusal boundaries; no Native/Runtime/socket starts."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from regional_contact_node import Service, NativeRefusal

BUSY = 'regional candidate rejected: lock acquisition failed because the operation would block'


class ReceiveDeferredTests(unittest.TestCase):
    def service(self, error=None):
        service = Service.__new__(Service)
        service.bft = SimpleNamespace(receive_many=Mock(side_effect=error))
        service.bft_seen = {'previous'}
        service.bft_individual_retry = False
        service.contact_trace = SimpleNamespace(native_received=Mock(), native_stage=Mock())
        return service

    def receive(self, service, count=2):
        rows = [(str(n), b'exact-complete-' + bytes([n])) for n in range(count)]
        before = copy.deepcopy(rows)
        errors, rejected, deferred = [], [], []
        service.receive_bft_batch(rows, errors, rejected, deferred)
        self.assertEqual(rows, before)
        service.bft.receive_many.assert_called_with([raw for _, raw in rows])
        return errors, rejected, deferred

    def test_exact_typed_lock_defers_without_seen_or_trace_credit(self):
        for action in ('bft-network-inspect-batch', 'bft-network-check', 'bft-sync', 'bft-context'):
            with self.subTest(action=action):
                service = self.service(NativeRefusal(action, 1, BUSY))
                errors, rejected, deferred = self.receive(service)
                self.assertEqual(errors, ['native rejected: ' + BUSY])
                self.assertEqual(rejected, [])
                self.assertEqual(len(deferred), 2)
                self.assertTrue(all(v['command'] == action and v['exit_code'] == 1
                                    and not v['ledger_acceptance_known']
                                    and not v['signing_authority'] for v in deferred))
                self.assertEqual(service.bft_seen, {'previous'})
                service.contact_trace.native_received.assert_not_called()
                stages = [call.args[0] for call in service.contact_trace.native_stage.call_args_list]
                self.assertEqual(stages, ['native_receive_attempt']*2 + ['native_receive_refused']*2)
                self.assertTrue(service.bft_individual_retry)

    def test_next_success_checks_complete_original_bytes_before_seen_credit(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, BUSY))
        self.receive(service)
        service.bft.receive_many.side_effect = None
        errors, rejected, deferred = self.receive(service)
        self.assertEqual((errors, rejected, deferred), ([], [], []))
        self.assertEqual(service.bft_seen, {'previous', '0', '1'})
        self.assertEqual(service.bft.receive_many.call_count, 2)
        self.assertEqual(service.contact_trace.native_received.call_count, 2)
        self.assertEqual([call.args[0] for call in service.contact_trace.native_stage.call_args_list],
                         ['native_receive_attempt']*2 + ['native_receive_refused']*2
                         + ['native_receive_attempt']*2)

    def test_altered_proof_after_deferral_still_rejects(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, BUSY))
        self.receive(service)
        service.bft.receive_many.side_effect = NativeRefusal('bft-network-inspect-batch', 1,
                                                           'regional candidate rejected: invalid later proof')
        errors, rejected, deferred = self.receive(service)
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(rejected), 2)
        self.assertEqual(deferred, [])
        self.assertEqual(service.bft_seen, {'previous'})
        service.contact_trace.native_received.assert_not_called()

    def test_unbound_wrong_action_exit_and_complete_later_diagnostic_do_not_defer(self):
        for error in (ValueError('native rejected: ' + BUSY),
                      NativeRefusal('bft-sign', 1, BUSY),
                      NativeRefusal('bft-network-inspect-batch', 2, BUSY),
                      NativeRefusal('bft-network-inspect-batch', True, BUSY),
                      NativeRefusal('bft-network-inspect-batch', 1, BUSY + ' ' * 2200 + 'bad proof'),
                      NativeRefusal('bft-network-inspect-batch', 1, 'Permission denied'),
                      OSError('persistence failure')):
            with self.subTest(error=str(error)):
                service = self.service(error)
                _, rejected, deferred = self.receive(service)
                self.assertEqual(len(rejected), 2)
                self.assertEqual(deferred, [])
                self.assertEqual(service.bft_seen, {'previous'})

    def test_existing_seen_hint_cannot_skip_a_later_complete_proof(self):
        service = self.service(NativeRefusal('bft-network-inspect-batch', 1, 'invalid later proof'))
        service.bft_seen.add('0')
        _, rejected, deferred = self.receive(service, 1)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(deferred, [])
        self.assertFalse(service.bft_individual_retry)

    def test_trace_disabled_keeps_complete_native_validation_and_seen_behavior(self):
        service = self.service()
        service.contact_trace = None
        errors, rejected, deferred = self.receive(service)
        self.assertEqual((errors, rejected, deferred), ([], [], []))
        self.assertEqual(service.bft_seen, {'previous', '0', '1'})


class ContactApplyDeferredTests(unittest.TestCase):
 def service(self,error):
  from contextlib import nullcontext
  from pathlib import Path
  import interstellar_transfer as wire
  service=Service.__new__(Service);service.region='b'*64;network='a'*64;node_id='c'*64;pid='d'*64
  raw=wire.make_frame('finalized-import','e'*64,service.region,'f'*64,b'complete-ground-proof-model')
  service.contact_trace=None;service.bft_seen={'unchanged'};service.bft_individual_retry=False;service.receive_after={'novel':None,'background':None};service.progress={'cursor':0};service.miner=None;service.carriage=None;service.root=Path('/synthetic-not-opened');service.path=service.root/'progress.json';service.bft=None
  def call(action):
   if action=='contact-status':return dict(currency=network,region=service.region,contacts=[])
   if action=='contact-outgoing':return dict(offers=[])
   raise AssertionError(action)
  service.native=SimpleNamespace(currency=network,call=call,apply=Mock(side_effect=error));service.tcp=SimpleNamespace(tick=lambda:dict(errors=[]))
  node=SimpleNamespace(id=node_id,network=network,state={'adverts':{}},tick=lambda:dict(errors=[]),summaries=lambda:{pid:dict(destination=node_id,kind='finalized-import',export_id='f'*64)},receipts=lambda:{pid:{'modeled':True}},transit=lambda _:dict(modeled=True))
  service.selection_node=lambda:nullcontext(node)
  return service,pid,raw
 def tick(self,service,raw):
  from unittest.mock import patch
  import interstellar_mesh as mesh
  with patch.object(mesh,'transit_check',return_value=({},raw,[])),patch.object(mesh,'receipt_matches'),patch.object(mesh,'atomic'):
   return service.tick()
 def test_exact_contact_apply_lock_is_unknown_not_rejected(self):
  for text in (BUSY,'regional candidate rejected: complete stream already locked'):
   with self.subTest(diagnostic=text):
    service,pid,raw=self.service(NativeRefusal('contact-apply',1,text));before=set(service.bft_seen);report=self.tick(service,raw);service.native.apply.assert_called_once_with(raw,None)
    self.assertEqual(report['applied'],[]);self.assertEqual(service.bft_seen,before);self.assertEqual(report['rejected'],[],'exact typed contact-apply lock was treated as complete-envelope rejection')
    self.assertEqual(report['deferred'],[dict(packet_id=pid,stage='native-validation-pending',command='contact-apply',exit_code=1,diagnostic=text,ledger_acceptance_known=False,signing_authority=False)])
 def test_complete_original_bytes_retry_requires_native_success_before_applied(self):
  service,pid,raw=self.service(NativeRefusal('contact-apply',1,BUSY));before=set(service.bft_seen);self.tick(service,raw);service.native.apply.side_effect=None;service.native.apply.return_value=dict(evidence_verified=True,import_accepted=False)
  report=self.tick(service,raw);self.assertEqual(report['rejected'],[]);self.assertEqual(report['deferred'],[]);self.assertEqual(report['applied'],[dict(packet_id=pid,native=dict(evidence_verified=True,import_accepted=False))]);self.assertEqual(service.bft_seen,before);self.assertEqual(service.native.apply.call_count,2);self.assertEqual([call.args for call in service.native.apply.call_args_list],[(raw,None),(raw,None)])
 def test_unbound_wrong_action_exit_and_long_later_proof_error_refuse(self):
  for error in (ValueError('native rejected: '+BUSY),NativeRefusal('bft-sign',1,BUSY),NativeRefusal('contact-apply',2,BUSY),NativeRefusal('contact-apply',True,BUSY),NativeRefusal('contact-apply',1,BUSY+' '*2200+'bad proof'),NativeRefusal('contact-apply',1,'Permission denied'),OSError('persistence failure')):
   with self.subTest(error=str(error)):
    service,pid,raw=self.service(error);report=self.tick(service,raw);self.assertEqual(len(report['rejected']),1);self.assertEqual(report['deferred'],[]);self.assertEqual(report['applied'],[]);self.assertEqual(service.bft_seen,{'unchanged'})
 def test_later_invalid_proof_refuses_after_prior_deferral(self):
  service,pid,raw=self.service(NativeRefusal('contact-apply',1,BUSY));self.tick(service,raw);service.native.apply.side_effect=NativeRefusal('contact-apply',1,'invalid later proof');report=self.tick(service,raw);self.assertEqual(len(report['rejected']),1);self.assertEqual(report['deferred'],[]);self.assertEqual(report['applied'],[]);self.assertEqual(service.bft_seen,{'unchanged'})
 def test_corrupt_frame_refuses_before_native_call_even_after_deferral(self):
  service,pid,raw=self.service(NativeRefusal('contact-apply',1,BUSY));self.tick(service,raw);report=self.tick(service,raw+b'corrupt');self.assertEqual(len(report['rejected']),1);self.assertEqual(report['deferred'],[]);self.assertEqual(service.native.apply.call_count,1)

if __name__ == '__main__':
    unittest.main()
