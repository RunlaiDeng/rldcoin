from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
from test_interstellar_mesh import mesh,evidence,json,copy,patch,NETWORK
def test_newest_current_pair_keeps_forwarded_prepare_ahead_of_local(self):
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds();source=self.f.identities['earth']['node_id'];relay=self.f.identities['proxima']['node_id'];peer=self.f.identities['andromeda']['node_id']
    context=dict(currency=NETWORK,region='9'*64,epoch='4'*64,previous='1'*64,parent_height=14,parent_block='2'*64,parent_state='3'*64)
    keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8));messages=Messages();raws=[]
    for n,phase in ((4,'Prepare'),(5,'Commit'),(6,'Prepare')):
        key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32);public=keys[n-4];data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps([context,0,'5'*64,phase,public],separators=(',',':'),ensure_ascii=False).encode();signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
        env=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase=phase,approval=dict(key=public,signature=signature)))))
        messages=messages.append(mesh.digest(env['body']),env,None,True);payload=evidence.canonical(env);raws.append(evidence.make_frame('regional-bft',context['region'],context['region'],evidence.hashlib.sha256(payload).hexdigest(),payload))
    frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region']);self.assertEqual(len(frames),3)
    # Fresh ordinary signed source packet/hop, then durable relay custody. No
    # old packet, signer, Native/Runtime constructor or ledger authority.
    with self.f.node('earth') as node:
        target=node.enqueue(raws[-1],peer);bundle=node.prepare_exchange(relay);original=copy.deepcopy(node.state['messages'][target]);self.assertIn(target,[mesh.digest(t['packet']) for t in bundle['body']['transits']])
    with self.f.node('proxima') as node:
        for _ in range(40):node.enqueue(self.f.frame(),peer)
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        local=[node.enqueue(raw,peer) for raw in raws[:2]];node.receive(bundle,source);self.assertIn(target,node.state['messages']);self.assertNotIn(target,node.receipts());self.assertNotEqual(node.state['messages'][target]['packet']['body']['node_id'],node.id)
        domain=node.carriage_position_domain();scope=mesh.digest(context);bucket=lambda i:(node.state['messages'][i]['packet']['body']['destination'],node.state['messages'][i]['routing']['body']['frame_id']);buckets=sorted(set(bucket(i) for i in node.state['recent_transits']))
        def pressure(step):
            previous=buckets[(buckets.index(bucket(local[0]))-1)%len(buckets)];mesh.remember_carriage_position((domain,peer,'recent_transit_cursors','ring'),previous);mesh.forget_carriage_position((domain,peer,'native-current-frame',scope,frames,True));node.state['transit_class_steps'][peer]=step;node.save();node.set_carriage_priority(scope,frames)
            groups=node.transit_groups(peer);self.assertEqual(next(i for i in groups[0] if i in local or i==target),local[0])
        pressure(0);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
        state=copy.deepcopy(node.state);durable=node.path.read_bytes();node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
        with patch.object(mesh,'atomic',side_effect=OSError('forwarded current preparation')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
        newest=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in newest['body']['transits']);self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4);self.assertTrue(set(selected[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        self.assertIn(target,selected[2:],'existing newest current pair selected locally originated current frame before retained forwarded Prepare')
        self.assertFalse(set(local)&set(selected[2:]));self.assertEqual(node.state['messages'][target]['packet'],original['packet']);self.assertEqual(node.state['messages'][target]['routing'],original['routing'])
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')};full=node.prepare_exchange(peer,retry_packet_ids=selected);self.assertEqual(tuple(mesh.digest(t['packet']) for t in full['body']['transits']),selected);self.assertEqual({k:node.state[k] for k in positions},positions)
        # Oldest pair keeps its actual prior local/failed-frame order.
        pressure(4);old_pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);old=node.prepare_exchange(peer);old_ids=tuple(mesh.digest(t['packet']) for t in old['body']['transits']);self.assertEqual(old_ids[:2],old_pair);self.assertIn(local[0],old_ids[2:]);self.assertNotIn(target,old_ids[2:])
        for _ in range(3):pressure(0);self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        tr=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(tr,NETWORK,peer,relay);mesh.receipt_matches(receipt,tr);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(tr['packet'],NETWORK)[1],raws[-1]);self.assertEqual(tr['packet'],original['packet']);self.assertEqual(tr['routing'],original['routing']);self.assertEqual(len(tr['hops']),2)

class Retained(tests.MeshTests):
 def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/forwarded-current-baseline-v29-private-20261007'+'/'+self._testMethodName)
 def tearDown(self):pass
Retained.test_newest_current_pair_keeps_forwarded_prepare_ahead_of_local=test_newest_current_pair_keeps_forwarded_prepare_ahead_of_local
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([Retained('test_newest_current_pair_keeps_forwarded_prepare_ahead_of_local')]))
raise SystemExit(0 if result.wasSuccessful() else 1)
