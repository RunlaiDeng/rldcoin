def test_same_current_frame_revisits_distinct_unreceipted_destinations(self):
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
        baseline=[node.enqueue(self.f.frame(),destination) for _ in range(32)]
        node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
        competitor,target=node.enqueue_batch([(raw,peer),(raw,destination)])
        frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region'])
        self.assertEqual(frames,(frame,));node.set_carriage_priority(mesh.digest(context),frames)
        node.state['transit_class_steps'][peer]=4;node.save()
        first=node.prepare_exchange(peer);first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
        self.assertTrue({competitor,target}<=set(first_ids[2:]))
        originals={ident:copy.deepcopy(node.state['messages'][ident]) for ident in (competitor,target)}
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
            'history_transit_cursors','transit_class_steps')}
        retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
        self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
        self.assertEqual({k:node.state[k] for k in positions},positions);self.assertFalse(node.receipts())
        self.assertTrue({competitor,target}<=set(node.state['first_carriage'][peer]['prepared']))
        self.assertTrue({competitor,target}<=set(node.state['recent_transits']))
        bucket=lambda ident:(node.state['messages'][ident]['packet']['body']['destination'],
                             node.state['messages'][ident]['routing']['body']['frame_id'])
        keys_by_class=sorted(set(bucket(i) for i in node.state['recent_transits']))
        preceding=keys_by_class[(keys_by_class.index(bucket(competitor))-1)%len(keys_by_class)]
        domain=node.carriage_position_domain()
        # Reproduce measured V38 group order at two priority opportunities:
        # same-frame competitor before target. Only the optional ordinary ring
        # start is fault-injected; signed bytes/admission/route/capacities remain.
        def pressure():
            mesh.remember_carriage_position((domain,peer,'recent_transit_cursors','ring'),preceding)
            node.state['transit_class_steps'][peer]=4;node.save()
            node.set_carriage_priority(mesh.digest(context),frames)
            groups=node.transit_groups(peer)
            current=[i for i in groups[0] if i in (competitor,target)]
            self.assertEqual(current,[competitor,target])
        seen=[];bundles=[]
        for turn in range(2):
            pressure();pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
            bundle=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4)
            self.assertTrue(set(selected[2:]) & (set(node.state['messages'])-set(node.state['recent_transits'])))
            self.assertFalse(node.receipts());self.assertEqual(node.state['messages'][target],originals[target])
            seen.extend(selected[2:]);bundles.append(bundle)
            positions={k:copy.deepcopy(node.state[k]) for k in positions}
            replay=node.prepare_exchange(peer,retry_packet_ids=selected)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),selected)
            self.assertEqual({k:node.state[k] for k in positions},positions)
        self.assertIn(target,seen,'same signed current frame repeatedly selected one recipient and skipped the other across two eligible priority opportunities')
        self.assertIn(competitor,seen)
        # Two ordinary source ticks carry both eligible current copies; no
        # controller-selected packet or manual publication grants delivery.
        for _ in range(2):
            pressure();self.assertFalse(node.tick()['errors'])
        paths=list((self.f.root/'links/earth-proxima').glob('*.json'))
        ordinary=[mesh.load(path,mesh.MAX_BATCH) for path in paths]
        self.assertTrue(any(target in [mesh.digest(t['packet']) for t in bundle['body']['transits']] for bundle in ordinary))
    for _ in range(2):
        with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        transit=node.state['messages'][target];receipt=node.receipts()[target]
        mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit)
        self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
        self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
        self.assertEqual(transit['packet'],originals[target]['packet']);self.assertEqual(transit['routing'],originals[target]['routing'])
        self.assertEqual(len(transit['hops']),2)
        self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
