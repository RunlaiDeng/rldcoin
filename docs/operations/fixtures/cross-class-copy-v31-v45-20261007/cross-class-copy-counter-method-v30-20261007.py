def test_same_current_copy_survives_recent_to_history_transition(self):
    # Same fresh signed Prepare, two original independently routed packets.
    # Empty Native proof is a ground analogy, never ledger authority.
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
    key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([4])*32)
    public=key.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex()
    keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
        mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
    context=dict(currency=NETWORK,region='9'*64,epoch=0,previous='0'*64,
                 parent_height=14,parent_block='2'*64,parent_state='3'*64)
    data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps(
        [context,0,'5'*64,'Prepare',public],separators=(',',':'),ensure_ascii=False).encode()
    signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
    envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),
        body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase='Prepare',
                                      approval=dict(key=public,signature=signature)))))
    messages=Messages().append(mesh.digest(envelope['body']),envelope,None,True)
    payload=evidence.canonical(envelope)
    raw=evidence.make_frame('regional-bft',context['region'],context['region'],
                            evidence.hashlib.sha256(payload).hexdigest(),payload)
    frame=evidence.inspect_frame(raw)[0]['message_id']
    with self.f.node('earth') as node:
        baseline=[node.enqueue(self.f.frame(),destination) for _ in range(40)]
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        competitor,target=node.enqueue_batch([(raw,peer),(raw,destination)])
        originals={ident:copy.deepcopy(node.state['messages'][ident]) for ident in (competitor,target)}
        frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region']);self.assertEqual(frames,(frame,));scope=mesh.digest(context);domain=node.carriage_position_domain()
        cursor=lambda kind:(domain,peer,'native-current-copy',scope,kind,frame)
        bucket=lambda ident:(node.state['messages'][ident]['packet']['body']['destination'],node.state['messages'][ident]['routing']['body']['frame_id'])
        def pressure(kind,step=0):
            pool=[i for i in node.state['messages'] if (i in node.state['recent_transits'])==kind];buckets=sorted(set(bucket(i) for i in pool));preceding=buckets[(buckets.index(bucket(competitor))-1)%len(buckets)]
            name='recent_transit_cursors' if kind else 'history_transit_cursors';mesh.remember_carriage_position((domain,peer,name,'ring'),preceding);node.state['transit_class_steps'][peer]=step;node.save();node.set_carriage_priority(scope,frames)
            groups=node.transit_groups(peer);index=(0 if kind else 1) if step%2==0 else (1 if kind else 0);self.assertEqual([i for i in groups[index] if i in (competitor,target)],[competitor,target])
        pressure(True);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);first=node.prepare_exchange(peer);first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits']);self.assertEqual(first_ids[:2],pair);self.assertIn(competitor,first_ids[2:]);self.assertNotIn(target,first_ids[2:]);self.assertEqual(mesh.carriage_position(cursor(True)),competitor);self.assertIsNone(mesh.carriage_position(cursor(False)))
        # Original32 recent bound moves both original signed copies into history.
        for _ in range(32):node.enqueue(self.f.frame(),destination)
        self.assertFalse({competitor,target}&set(node.state['recent_transits']));pressure(False);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
        state=copy.deepcopy(node.state);durable=node.path.read_bytes();node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
        with patch.object(mesh,'atomic',side_effect=OSError('cross-class same-frame preparation')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable);self.assertIsNone(mesh.carriage_position(cursor(False)));self.assertEqual(mesh.carriage_position(cursor(True)),competitor)
        bundle=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits']);self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4);self.assertTrue(set(selected[2:])&set(node.state['recent_transits']))
        self.assertIn(target,selected[2:],'same current frame recent-to-history transition reset copy rotation and repeated prepared sibling before unprepared other destination')
        self.assertNotIn(competitor,selected[2:]);self.assertEqual(mesh.carriage_position(cursor(False)),target);self.assertEqual(node.state['messages'][target],originals[target]);positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')}
        replay=node.prepare_exchange(peer,retry_packet_ids=selected);self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),selected);self.assertEqual({k:node.state[k] for k in positions},positions)
        # The oldest pair and a missing position in both original classes retain
        # original cold order. No authority or position may survive a cache miss.
        mesh.forget_carriage_position(cursor(False));pressure(False,4);old=node.prepare_exchange(peer);self.assertIn(competitor,[mesh.digest(t['packet']) for t in old['body']['transits']][2:]);self.assertNotIn(target,[mesh.digest(t['packet']) for t in old['body']['transits']][2:])
        mesh.forget_carriage_position(cursor(False));mesh.forget_carriage_position(cursor(True));pressure(False);cold=node.prepare_exchange(peer);self.assertIn(competitor,[mesh.digest(t['packet']) for t in cold['body']['transits']][2:]);self.assertNotIn(target,[mesh.digest(t['packet']) for t in cold['body']['transits']][2:])
        for _ in range(3):pressure(False);self.assertFalse(node.tick()['errors'])
    for _ in range(2):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        transit=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw);self.assertEqual(transit['packet'],originals[target]['packet']);self.assertEqual(transit['routing'],originals[target]['routing']);self.assertEqual(len(transit['hops']),2)
