def test_active_proposal_precedes_completed_checkpoint_spare(self):
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
    encode=lambda z:json.dumps(z,separators=(',',':'),ensure_ascii=False).encode()
    block_hash=lambda h:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encode(h)).hexdigest()
    keymap={mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex():mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in range(4,8)};keys=tuple(sorted(keymap))
    parent_context=dict(currency=NETWORK,region='9'*64,epoch='4'*64,previous='1'*64,parent_height=13,parent_block='2'*64,parent_state='3'*64)
    parent=dict(currency=NETWORK,region=parent_context['region'],parent=parent_context['parent_block'],anchor=parent_context['previous'],height=14,miner=keys[2],commands='4'*64,state='3'*64,nonce=0)
    statement=dict(currency=NETWORK,region=parent_context['region'],height=14,block=block_hash(parent),state=parent['state'],previous=parent_context['previous'],epoch=parent_context['epoch'])
    value=evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'+encode(statement)).hexdigest()
    def quorum(phase):
        votes=[]
        for key in keys[:3]:
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+encode([parent_context,0,value,phase,key]);signature=keymap[key].sign(data).hex();keymap[key].public_key().verify(bytes.fromhex(signature),data)
            votes.append(dict(context=parent_context,round=0,value=value,phase=phase,approval=dict(key=key,signature=signature)))
        return dict(context=parent_context,round=0,value=value,phase=phase,votes=votes)
    final=dict(base=parent_context['previous'],bft=dict(prepared=quorum('Prepare'),committed=quorum('Commit')),statement=statement,approvals=[],blocks=[dict(header=parent,commands=[])],epochs=[])
    current=dict(currency=NETWORK,region=parent_context['region'],epoch=parent_context['epoch'],previous=value,parent_height=14,parent_block=statement['block'],parent_state=statement['state'])
    child=dict(parent,parent=statement['block'],anchor=value,height=15,state='5'*64)
    snapshot=dict(base=value,statement=dict(currency=NETWORK,region=current['region'],height=15,block=block_hash(child),state=child['state'],previous=value,epoch=current['epoch']),approvals=[],blocks=[dict(header=parent,commands=[]),dict(header=child,commands=[])],epochs=[])
    leader=keys[2];data=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\0'+encode([0,snapshot,None,leader]);signature=keymap[leader].sign(data).hex();keymap[leader].public_key().verify(bytes.fromhex(signature),data)
    proposal=dict(round=0,snapshot=snapshot,timeout=None,leader=dict(key=leader,signature=signature))
    final_env=dict(format=bft.NETWORK,currency=NETWORK,region=current['region'],evidence=dict(snapshots=[]),body=dict(Finalized=final))
    active_env=dict(format=bft.NETWORK,currency=NETWORK,region=current['region'],evidence=dict(snapshots=[final]),body=dict(Signed=dict(Proposal=proposal)))
    def frame(env):
        payload=evidence.canonical(env);raw=evidence.make_frame('regional-bft',current['region'],current['region'],evidence.hashlib.sha256(payload).hexdigest(),payload);return raw,evidence.inspect_frame(raw)[0]['message_id']
    final_raw,final_frame=frame(final_env);active_raw,active_frame=frame(active_env)
    only_final=Messages().append(mesh.digest(final_env['body']),final_env,None,True)
    only_active=Messages().append(mesh.digest(active_env['body']),active_env,None,True)
    messages=only_final.append(mesh.digest(active_env['body']),active_env,None,True)
    self.assertEqual(bft.commit_carriage_frames(only_final,current,keys,NETWORK,current['region']),(final_frame,))
    self.assertEqual(bft.commit_carriage_frames(only_active,current,keys,NETWORK,current['region']),(active_frame,))
    frames=bft.commit_carriage_frames(messages,current,keys,NETWORK,current['region'])
    # Fresh real signed ground analogue of Proposal2->destination1. Retained
    # complete certificate travels inside the proposal too. No Native authority.
    with self.f.node('earth') as node:
        for _ in range(40):node.enqueue(self.f.frame(),destination)
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        cert=node.enqueue(final_raw,destination);target=node.enqueue(active_raw,destination);original=copy.deepcopy(node.state['messages'][target]);node.set_carriage_priority(mesh.digest(current),frames);node.state['transit_class_steps'][peer]=4;node.save();pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
        before=copy.deepcopy(node.state);durable=node.path.read_bytes()
        node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(before)
        with patch.object(mesh,'atomic',side_effect=OSError('mixed current publication')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),durable)
        bundle=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
        self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4);self.assertTrue(set(selected[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        self.assertIn(target,selected[2:],'completed checkpoint displaced the active Proposal in its first eligible spare opportunity')
        self.assertEqual(frames,(active_frame,));self.assertNotIn(cert,selected[2:])
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')};retry=node.prepare_exchange(peer,retry_packet_ids=selected);self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),selected);self.assertEqual({k:node.state[k] for k in positions},positions)
        for _ in range(3):node.state['transit_class_steps'][peer]=4;node.save();node.set_carriage_priority(mesh.digest(current),frames);self.assertFalse(node.tick()['errors'])
    for _ in range(3):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        tr=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(tr,NETWORK,destination,peer);mesh.receipt_matches(receipt,tr);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(tr['packet'],NETWORK)[1],active_raw);self.assertEqual(tr['packet'],original['packet']);self.assertEqual(tr['routing'],original['routing'])
    # Unsupported/invalid active candidates preserve latest-certificate fallback.
    for mode in ('signature','round'):
        bad=copy.deepcopy(active_env)
        if mode=='signature':bad['body']['Signed']['Proposal']['leader']['signature']='0'*128
        else:bad['body']['Signed']['Proposal']['round']=1
        retained=only_final.append(mesh.digest(bad['body']),bad,None,True)
        self.assertEqual(bft.commit_carriage_frames(retained,current,keys,NETWORK,current['region']),(final_frame,))
    # Ignored fallback bytes cannot exhaust the original active hint budget.
    ceiling=len(evidence.canonical(active_env))+len(evidence.canonical(final_env))-1
    with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',ceiling):self.assertEqual(bft.commit_carriage_frames(messages,current,keys,NETWORK,current['region']),(active_frame,))
    with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',len(evidence.canonical(active_env))-1):self.assertEqual(bft.commit_carriage_frames(only_active,current,keys,NETWORK,current['region']),())
