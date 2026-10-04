"""Real private ground queues; no Native ledger/signing or custody inference."""
import copy,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_receipt_scheduler import Fixture
from test_interstellar_tcp import Fixture as TcpFixture

class ColdCarriageChecks(unittest.TestCase):
 def fixture(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);f=Fixture(temp.name)
  with f.node(0) as node:
   for family,count in ((1,40),(2,1)):
    frame=wire.make_frame('source-finality','1'*64,'3'*64,format(family,'064x'),b'{"synthetic":true}')
    for _ in range(count):node.enqueue(frame,f.ids[2])
  return f
 def coverage(self,f):
  with f.node(0) as node:
   expected=copy.deepcopy(node.state['messages']);seen=set()
   for _ in range(80):seen.update(mesh.digest(t['packet']) for t in node.prepare_exchange(f.ids[2])['body']['transits'])
   self.assertEqual(seen,set(expected));self.assertEqual(node.state['messages'],expected);self.assertFalse(node.state['receipts'])
 def test_disabled_positions_retain_complete_failed_send_coverage(self):
  f=self.fixture()
  with patch.object(mesh,'MAX_CARRIAGE_POSITIONS',0):self.coverage(f)
 def test_tiny_position_budget_retains_complete_failed_send_coverage(self):
  f=self.fixture()
  with patch.object(mesh,'MAX_CARRIAGE_POSITION_BYTES',1):self.coverage(f)
 def test_eviction_before_every_open_retains_durable_packet_rotation(self):
  f=self.fixture();seen=set()
  with f.node(0) as node:expected=copy.deepcopy(node.state['messages'])
  for _ in range(80):
   with mesh._carriage_position_lock:
    mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
   with f.node(0) as node:seen.update(mesh.digest(t['packet']) for t in node.prepare_exchange(f.ids[2])['body']['transits'])
  with f.node(0) as node:self.assertEqual(node.state['messages'],expected);self.assertFalse(node.state['receipts'])
  self.assertEqual(seen,set(expected))
 def test_failed_durable_preparation_does_not_advance_selected_packet_positions(self):
  f=self.fixture()
  with f.node(0) as node:
   node.exchange(f.ids[2]);raw=node.path.read_bytes();state=copy.deepcopy(node.state)
   with mesh._carriage_position_lock:positions=copy.deepcopy(mesh._carriage_positions)
   with patch.object(mesh,'atomic',side_effect=OSError('injected publication refusal')):
    with self.assertRaises(OSError):node.prepare_exchange(f.ids[2])
   self.assertEqual(node.path.read_bytes(),raw);self.assertEqual(node.state,state)
   with mesh._carriage_position_lock:self.assertEqual(dict(mesh._carriage_positions),dict(positions))
 def test_unverified_later_packet_still_refuses_with_warm_scheduling_positions(self):
  f=self.fixture()
  with f.node(0) as node:
   node.prepare_exchange(f.ids[2]);ident=next(iter(node.state['messages']));node.state['messages'][ident]['packet']['signature']='0'*128;node.save();path=node.path;raw=path.read_bytes()
  with self.assertRaisesRegex(ValueError,'signature'):f.node(0)
  self.assertEqual(path.read_bytes(),raw)
 def test_ordinary_enqueue_lease_keeps_bounded_refusal_intent_then_releases_after_success(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);f=TcpFixture(temp.name,names=('earth','proxima'));self.addCleanup(f.close);server=f.servers['earth'];held=threading.Event();release=threading.Event()
  def hold():
   with mesh.Node(f.configs['earth']):held.set();release.wait(5)
  worker=threading.Thread(target=hold);worker.start()
  try:
   self.assertTrue(held.wait(5))
   with self.assertRaises(BlockingIOError):
    with server.ordinary_mesh_node():self.fail('held OS lock was acquired')
   self.assertIs(server.selection_owner,threading.current_thread());release.set();worker.join(5);self.assertFalse(worker.is_alive())
   with server.ordinary_mesh_node() as node:self.assertEqual(node.id,f.ids['earth'])
   self.assertIsNone(server.selection_owner)
  finally:release.set();worker.join(5)

if __name__=='__main__':unittest.main()
