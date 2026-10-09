"""Peer-local ordered phase availability; ground signatures grant no authority."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_bft_retention import Messages
from regional_contact_trace import ContactTrace
import test_regional_bft_ordered_carriage as ground
import test_regional_bft_timeout_hint as signatures


class WaitingPhaseHeadTests(unittest.TestCase):
    def fixture(self):
        helper=ground.OrderedCarriageTests()
        context,keys,messages,raws,frames=helper.signed_frames()
        signer=signatures.TimeoutCarriageTests();signer.setUp()
        value=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'
                            +signatures.encoded(wire.decode_json(wire.inspect_frame(raws[-1])[1])['body']['Signed']['Proposal']['snapshot']['statement'])).hexdigest()
        votes=[]
        for key in keys[:3]:
            vote=dict(context=context,round=4,value=value,phase='Prepare',
                      approval=signer.sign(key,'bft-vote-v1',[context,4,value,'Prepare',key]))
            body={'Signed':{'Vote':vote}}
            envelope=dict(format=bft.ORIGIN_NETWORK,currency=context['currency'],region=context['region'],
                          evidence={'snapshots':[]},origins=[],body=body)
            ident=mesh.digest(body);messages=messages.append(ident,envelope,value,True)
            votes.append(wire.make_frame('regional-bft',context['region'],context['region'],
                                        messages.content(ident),messages.payload(ident)))
        frames=bft.commit_carriage_frames(messages,context,keys,context['currency'],context['region'],4,import_proposals=True)
        self.assertEqual(frames[0],wire.inspect_frame(raws[-1])[0]['message_id'])
        self.assertTrue(all(wire.inspect_frame(raw)[0]['message_id'] in frames for raw in votes))
        retained=helper.retained_directory('rld-waiting-phase-');directory=Path(retained.__enter__())
        self.addCleanup(lambda:retained.__exit__(None,None,None))
        configs=helper.fixture(directory,context['currency'])
        with mesh.Node(configs[0]) as target:source_id=target.id
        with mesh.Node(configs[3]) as sender:
            sender_id=sender.id;sender.enqueue(raws[-1],source_id);proposal=sender.prepare_exchange(source_id)
        node=mesh.Node(configs[0]);self.addCleanup(node.close);node.receive(proposal,sender_id)
        peers=sorted(node.contacts);history=[]
        for n in range(72):
            history.append(node.enqueue(wire.make_frame('source-finality','1'*64,'2'*64,
                hashlib.sha256(str(n).encode()).hexdigest(),b'{"no_value":true}'),peers[n%3]))
        node.set_carriage_priority(mesh.digest(context),frames,ordered_frames=True)
        for peer in peers:
            key=(node.carriage_position_domain(),peer,'native-ordered-spare-turn')
            for _ in range(16):
                if (node.state['transit_class_steps'][peer]//4)%2==0 and mesh.carriage_position(key) is True:break
                node.prepare_exchange(peer)
            else:self.fail('bounded ordinary preparation did not align background turn')
        targets={p:node.enqueue(votes[-1],p) for p in peers}
        trace=ContactTrace();trace.bind(node.network,node.id);node.contact_trace=trace
        return node,peers,targets,frames,history,trace,votes,keys,context,value

    def test_received_global_proposal_does_not_block_missing_third_prepare_for_any_peer(self):
        node,peers,targets,frames,history,trace,votes,keys,context,value=self.fixture()
        original={i:wire.canonical(t) for i,t in node.state['messages'].items()}
        receipts=copy.deepcopy(node.receipts())
        third=wire.decode_json(wire.inspect_frame(votes[-1])[1])['body']['Signed']['Vote']
        for peer in peers:
            first=node.first_carriage_plan(peer)['pending'][:2]
            bundle=node.prepare_exchange(peer);ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
            self.assertEqual(ids[:2],first);self.assertEqual(len(ids),4)
            self.assertIn(targets[peer],ids[2:]);self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)
            # Full inner signatures bind one exact context/round/value and
            # three distinct keys. Availability does not authorize aggregation.
            complete=[wire.decode_json(wire.inspect_frame(raw)[1])['body']['Signed']['Vote'] for raw in votes[:2]]+[third]
            for vote in complete:
                self.assertEqual((vote['context'],vote['round'],vote['value'],vote['phase']),(context,4,value,'Prepare'))
                approval=vote['approval']
                mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(approval['key'])).verify(
                    bytes.fromhex(approval['signature']),b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'
                    +signatures.encoded([context,4,value,'Prepare',approval['key']]))
            self.assertEqual(len({v['approval']['key'] for v in complete}),3)
            key=(node.carriage_position_domain(),peer,'native-ordered-spare-turn')
            self.assertEqual(mesh.carriage_position(key),2)
            for expected in (1,False):
                node.prepare_exchange(peer)
                summary=[e for e in trace.snapshot()['events'] if e['stage']=='prepare_selection' and e['peer']==peer][-1]
                self.assertFalse(summary['priority']);self.assertEqual(mesh.carriage_position(key),expected)
        self.assertEqual(original,{i:wire.canonical(t) for i,t in node.state['messages'].items()})
        self.assertEqual(node.receipts(),receipts);node.validate_state()

    def test_invalid_lower_phase_packet_or_failed_publication_cannot_advance_custody(self):
        node,peers,targets,frames,history,trace,*_=self.fixture();peer=peers[0]
        original=node.path.read_bytes();state=copy.deepcopy(node.state)
        key=(node.carriage_position_domain(),peer,'native-ordered-spare-turn')
        with patch.object(mesh,'atomic',side_effect=OSError('publication refused')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),original);self.assertEqual(node.state,state)
        self.assertIs(mesh.carriage_position(key),True)
        node.state['messages'][targets[peer]]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),original);self.assertIs(mesh.carriage_position(key),True)

    def test_verified_hop_suppression_skips_earlier_waiting_frame_without_receipt(self):
        node,peers,targets,frames,history,trace,votes,*_=self.fixture();peer=peers[0]
        earlier=node.enqueue(votes[0],peer)
        visible=node.exchange(peer)
        suppressed={mesh.digest(t) for t in visible['body']['transits'] if mesh.digest(t['packet'])==earlier}
        self.assertEqual(len(suppressed),1)
        receipts=copy.deepcopy(node.receipts())
        bundle=node.prepare_exchange(peer,suppressed)
        carried=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        self.assertNotIn(earlier,carried);self.assertIn(targets[peer],carried[2:])
        self.assertIn(earlier,node.state['messages']);self.assertEqual(node.receipts(),receipts)
        self.assertNotIn(earlier,node.state['first_carriage'][peer]['prepared'])


if __name__=='__main__':unittest.main()
