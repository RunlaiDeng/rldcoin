from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
from test_interstellar_mesh import mesh,evidence,json,copy,patch,NETWORK
def test_stable_current_frame_set_survives_ordinary_ring_interference(self):
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
    context=dict(currency=NETWORK,region='9'*64,epoch=0,previous='0'*64,parent_height=14,parent_block='2'*64,parent_state='3'*64)
    keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
    messages=Messages();raws=[]
    for n,phase in ((4,'Prepare'),(5,'Commit'),(6,'Commit')):
        key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32);public=keys[n-4]
        data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps([context,0,'5'*64,phase,public],separators=(',',':'),ensure_ascii=False).encode()
        signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase=phase,approval=dict(key=public,signature=signature)))))
        messages=messages.append(mesh.digest(envelope['body']),envelope,None,True);payload=evidence.canonical(envelope)
        raws.append(evidence.make_frame('regional-bft',context['region'],context['region'],evidence.hashlib.sha256(payload).hexdigest(),payload))
    frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region']);self.assertEqual(len(frames),3)
    with self.f.node('earth') as node:
        baseline=[node.enqueue(self.f.frame(),destination) for _ in range(32)]
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        current=[node.enqueue(raw,destination) for raw in raws];target=current[-1]
        originals={i:copy.deepcopy(node.state['messages'][i]) for i in current};domain=node.carriage_position_domain()
        bucket=lambda ident:(node.state['messages'][ident]['packet']['body']['destination'],node.state['messages'][ident]['routing']['body']['frame_id'])
        buckets=sorted(set(bucket(i) for i in node.state['recent_transits']))
        def pressure(ident):
            previous=buckets[(buckets.index(bucket(ident))-1)%len(buckets)]
            mesh.remember_carriage_position((domain,peer,'recent_transit_cursors','ring'),previous)
            node.state['transit_class_steps'][peer]=4;node.save();node.set_carriage_priority(mesh.digest(context),frames)
            groups=node.transit_groups(peer);self.assertEqual(next(i for i in groups[0] if i in current),ident)
        # Original real preparations classify all three as prepared, not custody.
        for ident in current:
            pressure(ident);bundle=node.prepare_exchange(peer)
            self.assertIn(ident,[mesh.digest(t['packet']) for t in bundle['body']['transits']])
        self.assertTrue(set(current)<=set(node.state['first_carriage'][peer]['prepared']));self.assertFalse(node.receipts())
        seen=[]
        for turn in range(4):
            pressure(current[turn%2]);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
            bundle=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4)
            self.assertTrue(set(selected[2:]) & (set(node.state['messages'])-set(node.state['recent_transits'])))
            seen.extend(selected[2:]);self.assertEqual(node.state['messages'][target],originals[target]);self.assertFalse(node.receipts())
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=selected)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),selected)
            self.assertEqual({k:node.state[k] for k in positions},positions)
        self.assertIn(target,seen,'stable three-current-frame set repeatedly selects the two competitors under ordinary ring interference')
        for _ in range(3):
            pressure(current[0]);self.assertFalse(node.tick()['errors'])
    for _ in range(3):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        transit=node.state['messages'][target];receipt=node.receipts()[target]
        mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
        self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raws[-1]);self.assertEqual(transit['packet'],originals[target]['packet']);self.assertEqual(transit['routing'],originals[target]['routing']);self.assertEqual(len(transit['hops']),2)

class Retained(tests.MeshTests):
 def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/current-frame-set-baseline-v25-private-20261007'+'/'+self._testMethodName)
 def tearDown(self):pass
Retained.test_stable_current_frame_set_survives_ordinary_ring_interference=test_stable_current_frame_set_survives_ordinary_ring_interference
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([Retained('test_stable_current_frame_set_survives_ordinary_ring_interference')]))
raise SystemExit(0 if result.wasSuccessful() else 1)
