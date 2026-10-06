def test_evicted_current_proposal_hint_restored_before_quiet_return(self):
    from contextlib import nullcontext
    from types import SimpleNamespace
    import regional_bft_node as bft
    from regional_bft_retention import Messages
    keys_private=[mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in range(1,5)]
    keys=tuple(k.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for k in keys_private)
    context=dict(currency=NETWORK,region='1'*64,epoch='2'*64,previous='3'*64,
                 parent_height=14,parent_block='4'*64,parent_state='5'*64)
    def envelope(index,phase):
        data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps(
            [context,0,'6'*64,phase,keys[index]],separators=(',',':'),ensure_ascii=False).encode()
        vote=dict(context=context,round=0,value='6'*64,phase=phase,
                  approval=dict(key=keys[index],signature=keys_private[index].sign(data).hex()))
        keys_private[index].public_key().verify(bytes.fromhex(vote['approval']['signature']),data)
        return dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
                    evidence=dict(snapshots=[]),body=dict(Signed=dict(Vote=vote)))
    context,proposal=signed_ground_empty_proposal(context,keys_private[2])
    first=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)));remote=envelope(1,'Commit')
    messages=Messages().append(mesh.digest(first['body']),first,None,True)
    with self.f.node('earth') as node:
        runtime=object.__new__(bft.Runtime);runtime.format=bft.FORMAT;runtime.region=context['region']
        runtime.node_id=node.id;runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,
            ledger=self.f.root/'model-native-ledger')
        runtime.transport=self.f.configs['earth'];runtime.binding=dict(currency=NETWORK,region=context['region'],key=keys[0])
        runtime.peers=dict(zip(keys,(node.id,self.f.identities['proxima']['node_id'],
            self.f.identities['andromeda']['node_id'],'f'*64)));runtime.joint=None
        runtime.state=dict(messages=messages,height=14,tip=context['parent_block'],cursor=0)
        runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
        runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
        runtime.save=lambda state:setattr(runtime,'state',state);runtime.carriage_node=lambda:nullcontext(node)
        try:
            runtime._observe_context(context);runtime.broadcast()
            self.assertIsNotNone(runtime._broadcast_quiet)
            original_hint=mesh.carriage_position(runtime._carriage_priority_key)
            self.assertIsNotNone(original_hint)
            # Real bounded LRU eviction with immutable primitive dummy pressure.
            with patch.object(mesh,'MAX_CARRIAGE_POSITIONS',1):
                mesh.remember_carriage_position(('ground-hint-pressure',),'0'*64)
                self.assertIsNone(mesh.carriage_position(runtime._carriage_priority_key))
            runtime.broadcast()
            self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key),original_hint,
                             'quiet return left authenticated current Proposal hint missing after bounded eviction')
            before=mesh.carriage_position(runtime._carriage_priority_key)[1]
            self.assertEqual(len(before),1)
            # Native admission is explicitly modelled; the new retained
            # remote envelope has a genuine signature but grants no ledger.
            runtime.state['messages']=messages.append(mesh.digest(remote['body']),remote,None,False)
            expected=bft.commit_carriage_frames(runtime.state['messages'],context,keys,NETWORK,context['region'])
            self.assertEqual(len(expected),2)
            self.assertEqual([i for i,_,_,owned in messages.bodies() if owned],
                             [i for i,_,_,owned in runtime.state['messages'].bodies() if owned])
            runtime.broadcast()
            self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],expected,
                             'Native-checked remote current frame remained outside the quiet hint inventory')
            with patch.object(node,'set_carriage_priority',side_effect=AssertionError('unchanged complete inventory reinstalled hint')):
                runtime.broadcast()
        finally:runtime.close()
