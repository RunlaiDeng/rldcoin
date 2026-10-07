from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock,patch
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Service,NativeRefusal
BUSY='regional candidate rejected: lock acquisition failed because the operation would block'
class ContactApplyDeferredTests(unittest.TestCase):
 def service(self,error):
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
  with patch.object(mesh,'transit_check',return_value=({},raw,[])),patch.object(mesh,'receipt_matches'),patch.object(mesh,'atomic'):
   return service.tick()
 def test_exact_contact_apply_lock_is_unknown_not_rejected(self):
  for text in (BUSY,'regional candidate rejected: complete stream already locked'):
   with self.subTest(diagnostic=text):
    service,pid,raw=self.service(NativeRefusal('contact-apply',1,text));before=set(service.bft_seen);report=self.tick(service,raw);service.native.apply.assert_called_once_with(raw,None)
    self.assertEqual(report['applied'],[]);self.assertEqual(service.bft_seen,before);self.assertEqual(report['rejected'],[],'exact typed contact-apply lock was treated as complete-envelope rejection')
    self.assertEqual(report['deferred'],[dict(packet_id=pid,stage='native-validation-pending',command='contact-apply',exit_code=1,diagnostic=text,ledger_acceptance_known=False,signing_authority=False)])
