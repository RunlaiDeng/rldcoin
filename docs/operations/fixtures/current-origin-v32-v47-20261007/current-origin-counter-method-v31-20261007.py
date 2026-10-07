def test_newest_current_pair_rotates_forwarded_and_local_origins(self):
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
        # Same retained forwarded signed frame remains without a receipt. The
        # next newest turn must also serve an untouched eligible local frame;
        # ring/frame-set churn cannot make forwarded priority exclusive.
        origin_key=(domain,peer,'native-current-origin',scope)
        pressure(8);pair2=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(local[0],pair2)
        state=copy.deepcopy(node.state);durable=node.path.read_bytes();prior_origin=mesh.carriage_position(origin_key)
        with patch.object(mesh,'atomic',side_effect=OSError('origin alternation atomic refusal')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable);self.assertEqual(mesh.carriage_position(origin_key),prior_origin)
        second=node.prepare_exchange(peer);second_ids=tuple(mesh.digest(t['packet']) for t in second['body']['transits']);self.assertEqual(second_ids[:2],pair2);self.assertEqual(len(second_ids),4);self.assertTrue(set(second_ids[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        self.assertIn(local[0],second_ids[2:],'newest forwarded priority repeated a retained forwarded current frame before an untouched eligible local current frame')
        self.assertNotIn(target,second_ids[2:]);self.assertTrue(mesh.carriage_position(origin_key))
        positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')};origin=mesh.carriage_position(origin_key)
        full=node.prepare_exchange(peer,retry_packet_ids=second_ids);self.assertEqual(tuple(mesh.digest(t['packet']) for t in full['body']['transits']),second_ids);self.assertEqual({k:node.state[k] for k in positions},positions);self.assertEqual(mesh.carriage_position(origin_key),origin)
        pressure(4);old=node.prepare_exchange(peer);self.assertIn(local[0],[mesh.digest(t['packet']) for t in old['body']['transits']][2:]);self.assertEqual(mesh.carriage_position(origin_key),origin)
        # A missing scoped optional position uses original forwarded-first order.
        mesh.forget_carriage_position(origin_key);pressure(0);fallback=node.prepare_exchange(peer);self.assertIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']][2:])
        original_local=copy.deepcopy(node.state['messages'][local[0]])
        for _ in range(3):pressure(0);self.assertFalse(node.tick()['errors'])
    with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
    with mesh._verified_transits_lock:mesh._verified_transits.clear()
    with self.f.node('andromeda') as node:
        for ident,raw,packet,route,source_id,hops in ((target,raws[-1],original['packet'],original['routing'],relay,2),(local[0],raws[0],original_local['packet'],original_local['routing'],relay,1)):
            tr=node.state['messages'][ident];receipt=node.receipts()[ident];mesh.transit_check(tr,NETWORK,peer,source_id);mesh.receipt_matches(receipt,tr);self.assertEqual(mesh.receipt_check(receipt,NETWORK),ident);self.assertEqual(mesh.packet_check(tr['packet'],NETWORK)[1],raw);self.assertEqual(tr['packet'],packet);self.assertEqual(tr['routing'],route);self.assertEqual(len(tr['hops']),hops)
