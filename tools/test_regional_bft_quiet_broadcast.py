"""Empty carriage scheduling never substitutes for Native/transport authority."""
import copy,os,tempfile,time,unittest
from pathlib import Path
from contextlib import contextmanager
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_bft_network_campaign import Campaign
from regional_bft_node import Runtime,MAX_BROADCAST_QUIET_CALLS,MAX_BROADCAST_QUIET_SECONDS
from regional_contact_node import Native
from regional_contact_campaign import public
BINARY=Path(os.environ['RLD_CONTACT_BINARY'])
class QuietBroadcastTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='rld-quiet-broadcast-')
  self.c=Campaign(BINARY,Path(self.temp.name).resolve()/'fixture')
  self.cfg=mesh.load(self.c.root/'mesh-config-1.json',65536)
  self.native=Native(BINARY,self.c.node('earth',1),public(1),self.c.currency)
  self.runtime=Runtime(self.native,self.cfg,self.c.root/'bft-config-1.json')
  self.server=tcp.Server(self.cfg,('127.0.0.1',self.c.ports[1]));self.opens=0
  @contextmanager
  def carriage():
   with self.server.ordinary_mesh_node() as node:
    self.opens+=1;yield node
  self.runtime.carriage_node=carriage
  message=self.c.sign('earth',0,{'Timeout':{'context':self.c.cli('earth',0,'bft-context')['context'],'round':0}})['message']
  self.envelope=self.runtime.envelope({'Signed':message})
  self.runtime.retain(self.envelope,sync=False,local=True);self.runtime.broadcast()
 def tearDown(self):
  self.server.close();self.runtime.close();self.c.cleanup();self.temp.cleanup()
 def test_quiet_repeat_preserves_native_head_and_every_durable_recipient_pair(self):
  before=self.native.call('bft-status','--signer-dir',self.runtime.signer)
  opens=self.opens;self.runtime.broadcast();self.assertEqual(self.opens,opens)
  with mesh.Node(self.cfg) as node:
   content=mesh.digest(self.envelope);pairs={(v['export_id'],v['destination']) for v in node.summaries().values()}
   self.assertTrue(all((content,peer) in pairs for peer in set(self.runtime.peers.values())-{node.id}))
  after=self.native.call('bft-status','--signer-dir',self.runtime.signer)
  self.assertEqual(before['head'],after['head']);self.assertEqual(after['records'],0)
 def test_changed_authenticated_local_envelope_and_publication_failure_take_full_path(self):
  message=self.c.sign('earth',2,{'Timeout':{'context':self.c.cli('earth',2,'bft-context')['context'],'round':0}})['message']
  envelope=self.runtime.envelope({'Signed':message});self.runtime.retain(envelope,sync=False,local=True)
  path=Path(self.cfg['state'])/'mesh-state.json';atomic=mesh.atomic
  def fail(p,v):
   if Path(p)==path:raise OSError('injected mesh publication refusal')
   return atomic(p,v)
  opens=self.opens
  with patch.object(mesh,'atomic',side_effect=fail):
   with self.assertRaises(OSError):self.runtime.broadcast()
  self.runtime.broadcast();self.assertGreaterEqual(self.opens,opens+2)
  with mesh.Node(self.cfg) as node:
   content=mesh.digest(envelope);pairs={(v['export_id'],v['destination']) for v in node.summaries().values()}
   self.assertTrue(all((content,peer) in pairs for peer in set(self.runtime.peers.values())-{node.id}))
 def test_bad_later_proof_cannot_use_quiet_hint_to_mutate_or_authenticate(self):
  bad=copy.deepcopy(self.envelope);bad['evidence']['snapshots']=[{}]
  before=self.runtime.state_path.read_bytes();head=self.runtime.head_path.read_bytes()
  with self.assertRaises(ValueError):self.runtime.retain(bad,sync=False,local=True)
  self.assertEqual(self.runtime.state_path.read_bytes(),before);self.assertEqual(self.runtime.head_path.read_bytes(),head)
  self.assertEqual(self.runtime.state['messages'].payload(mesh.digest(self.envelope['body'])),__import__('interstellar_transfer').canonical(self.envelope))
 def test_finite_call_and_time_probes_and_capacity_fallback_reread_full_mesh(self):
  opens=self.opens
  for _ in range(MAX_BROADCAST_QUIET_CALLS):self.runtime.broadcast()
  self.assertEqual(self.opens,opens);self.runtime.broadcast();self.assertEqual(self.opens,opens+1)
  time.sleep(MAX_BROADCAST_QUIET_SECONDS+.05);self.runtime.broadcast();self.assertEqual(self.opens,opens+2)
  with patch('regional_bft_node.MAX_BROADCAST_HINT_BYTES',1):
   self.runtime.broadcast();self.runtime.broadcast()
  self.assertEqual(self.opens,opens+4)
 def test_restart_and_operator_contact_change_forget_or_miss_hint(self):
  self.runtime.close();self.runtime=Runtime(self.native,self.cfg,self.c.root/'bft-config-1.json')
  @contextmanager
  def carriage():
   with self.server.ordinary_mesh_node() as node:self.opens+=1;yield node
  self.runtime.carriage_node=carriage;opens=self.opens;self.runtime.broadcast();self.assertEqual(self.opens,opens+1)
  self.runtime.transport=copy.deepcopy(self.cfg);self.runtime.transport['contacts'][0]['port']+=1
  self.runtime.broadcast();self.assertEqual(self.opens,opens+2)
if __name__=='__main__':unittest.main()
