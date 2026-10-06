def test_failed_current_prepare_oldest_pair_precedes_newer_current(self):
    # Fresh real Vote/packet/hop signatures; empty Native proof is ground only.
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    self.f.rounds()
    peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
    context=dict(currency=NETWORK,region='9'*64,epoch=0,previous='0'*64,
                 parent_height=14,parent_block='2'*64,parent_state='3'*64)
    keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
               mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
    messages=Messages()
    def envelope(n):
        nonlocal messages
        key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32)
        public=key.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex()
        data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps(
            [context,0,'5'*64,'Prepare',public],separators=(',',':'),ensure_ascii=False).encode()
        signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
        value=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
                   evidence=dict(snapshots=[]),body=dict(Signed=dict(Vote=dict(
                       context=context,round=0,value='5'*64,phase='Prepare',
                       approval=dict(key=public,signature=signature)))))
        messages=messages.append(mesh.digest(value['body']),value,None,True)
        payload=evidence.canonical(value)
        return evidence.make_frame('regional-bft',context['region'],context['region'],
                                   evidence.hashlib.sha256(payload).hexdigest(),payload)
    old=envelope(4)
    with self.f.node('earth') as node:
        baseline=[node.enqueue(self.f.frame(),destination) for _ in range(32)]
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        target=node.enqueue(old,destination)
        frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region'])
        self.assertEqual(frames,(evidence.inspect_frame(old)[0]['message_id'],))
        node.set_carriage_priority(mesh.digest(context),frames)
        node.state['transit_class_steps'][peer]=4;node.save()
        first=node.prepare_exchange(peer)
        first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
        self.assertIn(target,first_ids[2:])
        original=copy.deepcopy(node.state['messages'][target])
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
        retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
        self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
        self.assertEqual({k:node.state[k] for k in positions},positions)
        self.assertFalse(node.receipts());self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
        newer=node.enqueue(envelope(5),destination)
        for _ in range(8):node.enqueue(self.f.frame(),destination)
        self.assertIn(target,node.state['recent_transits']);self.assertIn(newer,node.state['recent_transits'])
        node.state['transit_class_steps'][peer]=4;node.save()
        node.set_carriage_priority(mesh.digest(context),bft.commit_carriage_frames(
            messages,context,keys,NETWORK,context['region']))
        pending=tuple(node.first_carriage_plan(peer)['pending'][:2])
        self.assertNotIn(target,pending)
        state=copy.deepcopy(node.state);durable=node.path.read_bytes()
        node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
        with patch.object(mesh,'atomic',side_effect=OSError('old current atomic refusal')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
        self.assertFalse(node.tick()['errors'])
        paths=list((self.f.root/'links/earth-proxima').glob('*.json'));self.assertEqual(len(paths),1)
        bundle=mesh.load(paths[0],mesh.MAX_BATCH);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
        self.assertEqual(selected[:2],pending);self.assertEqual(len(selected),4)
        self.assertTrue(set(selected[2:])&set(node.state['messages'])-set(node.state['recent_transits']))
        self.assertEqual(node.state['messages'][target],original);self.assertFalse(node.receipts())
        self.assertIn(target,selected[2:],'oldest priority pair selected a newer current frame before the older failed prepared frame')
        self.assertNotIn(newer,selected[2:])
    for _ in range(2):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        transit=node.state['messages'][target];receipt=node.receipts()[target]
        mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit)
        self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
        self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],old)
        self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
        self.assertEqual(len(transit['hops']),2)
        self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
