"""Fresh signed no-value scheduling models, never Native/value authorization."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_bft_retention import Messages
import test_interstellar_ordered_head_turn as head_fixture
import test_regional_bft_timeout_hint as signatures


class BackgroundDirectHeadTests(unittest.TestCase):
    def fixture(self):
        helper=head_fixture.EarlyHeadTurnTests();node,peer,proposal,raws,frames,key,history,trace,configs=helper.fixture()
        self.addCleanup(helper.doCleanups)
        # Original ordinary preparation borrows one pair, then owes its original
        # two background turns. Only an existing recent-class place may change.
        first=node.prepare_exchange(peer)
        self.assertIn(proposal,[mesh.digest(t['packet']) for t in first['body']['transits']])
        self.assertEqual(mesh.carriage_position(key),2)
        envelope=wire.decode_json(wire.inspect_frame(raws[-1])[1]);p=envelope['body']['Signed']['Proposal']
        context=wire.decode_json(wire.inspect_frame(raws[0])[1])['body']['Signed']['Timeout']['context']
        context={k:context[k] for k in signatures.CONTEXT_FIELDS}
        value=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'
                            +signatures.encoded(p['snapshot']['statement'])).hexdigest()
        signer=signatures.TimeoutCarriageTests();signer.setUp();keys=signer.keys
        vote=dict(context=context,round=p['round'],value=value,phase='Commit',
                  approval=signer.sign(keys[-1],'bft-vote-v1',[context,p['round'],value,'Commit',keys[-1]]))
        body={'Signed':{'Vote':vote}};envelope=dict(format=bft.ORIGIN_NETWORK,currency=context['currency'],
            region=context['region'],evidence={'snapshots':[]},origins=[],body=body)
        messages=Messages().append(mesh.digest(body),envelope,value,True)
        raw=wire.make_frame('regional-bft',context['region'],context['region'],
                            messages.content(mesh.digest(body)),messages.payload(mesh.digest(body)))
        current=bft.commit_carriage_frames(messages,context,keys,context['currency'],context['region'],p['round'])
        self.assertEqual(current,(wire.inspect_frame(raw)[0]['message_id'],))
        target=node.enqueue(raw,peer);node.set_carriage_priority(mesh.digest(context),current,ordered_frames=True)
        return node,peer,target,key,history,trace,configs,raw,current

    def test_background_recent_place_carries_exact_fresh_direct_commit(self):
        node,peer,target,key,history,trace,*_=self.fixture()
        first=node.first_carriage_plan(peer)['pending'][:2]
        original={i:wire.canonical(t) for i,t in node.state['messages'].items()};receipts=copy.deepcopy(node.receipts())
        bundle=node.prepare_exchange(peer);ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        self.assertEqual(ids[:2],first);self.assertEqual(len(ids),4)
        self.assertIn(target,ids[2:])
        self.assertTrue(set(ids[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        self.assertFalse([r for r in trace.snapshot()['events'] if r['stage']=='prepare_selection'][-1]['priority'])
        self.assertEqual(mesh.carriage_position(key),1)
        self.assertEqual(original,{i:wire.canonical(t) for i,t in node.state['messages'].items()})
        self.assertEqual(node.receipts(),receipts)
        self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)


    def test_one_ordinary_recent_service_is_owed_across_scope_changes(self):
        node,peer,target,key,history,trace,configs,raw,current=self.fixture()
        node.prepare_exchange(peer)
        debt=(node.carriage_position_domain(),peer,'native-background-recent-debt')
        self.assertIs(mesh.carriage_position(debt),True)
        changed=self.other_commit(raw)
        new_target=node.enqueue(changed,peer)
        frame=wire.inspect_frame(changed)[0]['message_id']
        node.set_carriage_priority('a'*64,(frame,)+current,ordered_frames=True)
        self.assertIs(mesh.carriage_position(debt),True)
        expected=[mesh.digest(t['packet']) for t in node.exchange(peer)['body']['transits']]
        actual=node.prepare_exchange(peer)
        self.assertEqual([mesh.digest(t['packet']) for t in actual['body']['transits']],expected)
        self.assertIs(mesh.carriage_position(debt),False)
        self.assertFalse([r for r in trace.snapshot()['events'] if r['stage']=='prepare_selection'][-1]['priority'])
        self.assertIs(mesh.carriage_position(key),False)
        self.assertIn(new_target,node.state['messages'])

    def other_commit(self,raw):
        e=wire.decode_json(wire.inspect_frame(raw)[1]);v=e['body']['Signed']['Vote']
        context={k:v['context'][k] for k in signatures.CONTEXT_FIELDS}
        signer=signatures.TimeoutCarriageTests();signer.setUp();key=signer.keys[-2]
        v['approval']=signer.sign(key,'bft-vote-v1',[context,v['round'],v['value'],v['phase'],key])
        messages=Messages().append(mesh.digest(e['body']),e,v['value'],True)
        frames=bft.commit_carriage_frames(messages,context,signer.keys,e['currency'],e['region'],v['round'])
        result=wire.make_frame('regional-bft',e['region'],e['region'],messages.content(mesh.digest(e['body'])),
                               messages.payload(mesh.digest(e['body'])))
        self.assertEqual(frames,(wire.inspect_frame(result)[0]['message_id'],))
        return result

    def test_failed_publication_and_bad_signature_never_advance_debt_or_custody(self):
        node,peer,target,key,*_=self.fixture()
        debt=(node.carriage_position_domain(),peer,'native-background-recent-debt')
        before=node.path.read_bytes();state=copy.deepcopy(node.state)
        with patch.object(mesh,'atomic',side_effect=OSError('original publication refused')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(before,node.path.read_bytes());self.assertEqual(state,node.state)
        self.assertIs(mesh.carriage_position(debt),False);self.assertEqual(mesh.carriage_position(key),2)
        node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(before,node.path.read_bytes());self.assertIs(mesh.carriage_position(debt),False)
        self.assertFalse(node.receipts())

    def test_full_retry_and_missing_hint_keep_original_ordinary_paths(self):
        node,peer,target,key,history,trace,configs,*_=self.fixture()
        bundle=node.prepare_exchange(peer);ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        debt=(node.carriage_position_domain(),peer,'native-background-recent-debt')
        state=copy.deepcopy(node.state)
        with mesh._carriage_position_lock:positions=copy.deepcopy(mesh._carriage_positions)
        retry=node.prepare_exchange(peer,retry_packet_ids=tuple(ids))
        self.assertEqual([mesh.digest(t['packet']) for t in retry['body']['transits']],ids)
        self.assertEqual(state,node.state)
        with mesh._carriage_position_lock:self.assertEqual(positions,mesh._carriage_positions)
        hint=(node.carriage_position_domain(),'native-commit-spare');mesh.forget_carriage_position(hint)
        node.prepare_exchange(peer)
        self.assertIs(mesh.carriage_position(debt),True)
        node.validate_state();packet=copy.deepcopy(node.state['messages'][target]);node.close()
        with mesh.Node(configs[0]) as cold:
            self.assertEqual(cold.state['messages'][target],packet)
            self.assertIn(target,cold.state['first_carriage'][peer]['prepared'])
            cold.validate_state()

    def test_verified_hop_suppression_does_not_create_receipt_or_recent_debt(self):
        node,peer,target,key,*_=self.fixture()
        visible=node.exchange(peer)
        exact=[t for t in visible['body']['transits'] if mesh.digest(t['packet'])==target]
        self.assertEqual(len(exact),1)
        bundle=node.prepare_exchange(peer,{mesh.digest(exact[0])})
        self.assertNotIn(target,[mesh.digest(t['packet']) for t in bundle['body']['transits']])
        debt=(node.carriage_position_domain(),peer,'native-background-recent-debt')
        self.assertIs(mesh.carriage_position(debt),False)
        self.assertIn(target,node.state['messages']);self.assertFalse(node.receipts())
        self.assertNotIn(target,node.state['first_carriage'][peer]['prepared'])


if __name__=='__main__':unittest.main()
