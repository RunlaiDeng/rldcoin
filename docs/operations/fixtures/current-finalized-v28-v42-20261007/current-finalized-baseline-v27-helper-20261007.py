from pathlib import Path
import sys,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import test_interstellar_mesh as tests
from test_interstellar_mesh import mesh,evidence,json,copy,patch,NETWORK
def test_current_finalized_checkpoint_keeps_complete_spare_carriage(self):
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
    statement_fields=('currency','region','height','block','state','previous','epoch')
    encode=lambda z:json.dumps(z,separators=(',',':'),ensure_ascii=False).encode()
    checkpoint=lambda stmt:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'+encode({k:stmt[k] for k in statement_fields})).hexdigest()
    keymap={mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex():mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in range(4,8)};keys=tuple(sorted(keymap))
    context=dict(currency=NETWORK,region='9'*64,epoch='4'*64,previous='1'*64,parent_height=14,parent_block='2'*64,parent_state='3'*64)
    statement=dict(currency=NETWORK,region=context['region'],height=15,block='6'*64,state='3'*64,previous=context['previous'],epoch=context['epoch']);value=checkpoint(statement)
    def quorum(phase):
        votes=[]
        for public in keys[:3]:
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+encode([context,0,value,phase,public]);signature=keymap[public].sign(data).hex();keymap[public].public_key().verify(bytes.fromhex(signature),data)
            votes.append(dict(context=context,round=0,value=value,phase=phase,approval=dict(key=public,signature=signature)))
        return dict(context=context,round=0,value=value,phase=phase,votes=votes)
    final=dict(base=context['previous'],bft=dict(prepared=quorum('Prepare'),committed=quorum('Commit')),statement=statement,approvals=[],blocks=[],epochs=[])
    envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),body=dict(Finalized=final))
    # Model has actual original domain signatures, but no block/state proof and
    # never Native authority; only complete ground-carriage classification.
    payload=evidence.canonical(envelope);raw=evidence.make_frame('regional-bft',context['region'],context['region'],evidence.hashlib.sha256(payload).hexdigest(),payload);frame=evidence.inspect_frame(raw)[0]['message_id'];messages=Messages().append(mesh.digest(envelope['body']),envelope,None,True)
    current=dict(currency=NETWORK,region=context['region'],epoch=context['epoch'],previous=value,parent_height=15,parent_block=statement['block'],parent_state=statement['state'])
    frames=bft.commit_carriage_frames(messages,current,keys,NETWORK,context['region'])
    self.assertEqual(frames,(frame,),'Native-checked exact current checkpoint complete envelope was omitted after local finalization')
    # Malformed/foreign/latest-head/value/quorum/signature variants must remain
    # ordinary scheduling, never select an unchecked checkpoint shortcut.
    variants=[]
    for field,replacement in (('currency','0'*64),('parent_height',14),('parent_block','0'*64),('parent_state','0'*64),('previous','0'*64),('epoch','0'*64)):
        bad=copy.deepcopy(current);bad[field]=replacement;self.assertEqual(bft.commit_carriage_frames(messages,bad,keys,NETWORK,context['region']),())
    for mode in ('signature','two-votes','duplicate-key','unordered','round','phase','value','context','unknown-field'):
        bad=copy.deepcopy(envelope);cert=bad['body']['Finalized']['bft'];q=cert['committed']
        if mode=='signature':q['votes'][0]['approval']['signature']='0'*128
        elif mode=='two-votes':q['votes']=q['votes'][:2]
        elif mode=='duplicate-key':q['votes'][1]=copy.deepcopy(q['votes'][0])
        elif mode=='unordered':q['votes'].reverse()
        elif mode=='round':q['round']=32
        elif mode=='phase':q['phase']='Prepare'
        elif mode=='value':q['value']='0'*64
        elif mode=='context':q['context']['parent_height']=13
        else:bad['body']['Finalized']['unknown']=True
        variant=Messages().append(mesh.digest(bad['body']),bad,None,True)
        self.assertEqual(bft.commit_carriage_frames(variant,current,keys,NETWORK,context['region']),(),mode)
    with self.f.node('earth') as node:
        for _ in range(32):node.enqueue(self.f.frame(),destination)
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer);target=node.enqueue(raw,destination);original=copy.deepcopy(node.state['messages'][target]);node.set_carriage_priority(mesh.digest(current),frames);node.state['transit_class_steps'][peer]=4;node.save();pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
        state=copy.deepcopy(node.state);durable=node.path.read_bytes()
        node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
        with patch.object(mesh,'atomic',side_effect=OSError('current final checkpoint publication')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
        first=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in first['body']['transits']);self.assertEqual(selected[:2],pair);self.assertIn(target,selected[2:]);self.assertEqual(len(selected),4);self.assertTrue(set(selected[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')};retry=node.prepare_exchange(peer,retry_packet_ids=selected);self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),selected);self.assertEqual({k:node.state[k] for k in positions},positions);self.assertFalse(node.receipts())
        for _ in range(3):node.state['transit_class_steps'][peer]=4;node.save();node.set_carriage_priority(mesh.digest(current),frames);self.assertFalse(node.tick()['errors'])
    for _ in range(3):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        transit=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw);self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])

class Retained(tests.MeshTests):
 def setUp(self):self.f=tests.Fixture('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930/current-finalized-baseline-v27-private-20261007'+'/'+self._testMethodName)
 def tearDown(self):pass
Retained.test_current_finalized_checkpoint_keeps_complete_spare_carriage=test_current_finalized_checkpoint_keeps_complete_spare_carriage
result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([Retained('test_current_finalized_checkpoint_keeps_complete_spare_carriage')]))
raise SystemExit(0 if result.wasSuccessful() else 1)
