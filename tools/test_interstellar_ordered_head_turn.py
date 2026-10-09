"""Bounded early head scheduling; signed ground inputs grant no Native authority."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import ContactTrace
import test_regional_bft_ordered_carriage as ground


class EarlyHeadTurnTests(unittest.TestCase):
    def fixture(self):
        helper=ground.OrderedCarriageTests()
        context,_,_,raws,frames=helper.signed_frames()
        retained=helper.retained_directory('rld-head-turn-');directory=Path(retained.__enter__())
        self.addCleanup(lambda:retained.__exit__(None,None,None))
        configs=helper.fixture(directory,context['currency'])
        node=mesh.Node(configs[0]);self.addCleanup(node.close)
        peers=sorted(node.contacts);peer=peers[0]
        history=[]
        for n in range(48):
            raw=wire.make_frame('source-finality','1'*64,'2'*64,hashlib.sha256(str(n).encode()).hexdigest(),b'{"no_value":true}')
            history.append(node.enqueue(raw,peers[n%3]))
        node.set_carriage_priority(mesh.digest({'context':context,'round':'earlier'}),frames,ordered_frames=True)
        for _ in range(13):
            for p in peers:node.prepare_exchange(p)
        self.assertEqual(node.state['transit_class_steps'][peer],26)
        key=(node.carriage_position_domain(),peer,'native-ordered-spare-turn')
        self.assertIs(mesh.carriage_position(key),True)
        target=node.enqueue(raws[-1],peer)
        node.set_carriage_priority(mesh.digest(context),frames,ordered_frames=True)
        trace=ContactTrace();trace.bind(node.network,node.id);node.contact_trace=trace
        return node,peer,target,raws,frames,key,history,trace,configs

    def prepare(self,node,peer,trace):
        first=node.first_carriage_plan(peer)['pending'][:2]
        bundle=node.prepare_exchange(peer);ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
        self.assertEqual(ids[:len(first)],first)
        self.assertEqual(len(ids),4)
        self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)
        summary=[e for e in trace.snapshot()['events'] if e['stage']=='prepare_selection' and e['peer']==peer][-1]
        return ids,summary

    def test_new_waiting_direct_head_borrows_background_once_and_keeps_fifo(self):
        node,peer,target,_,_,key,history,trace,_=self.fixture()
        before={i:wire.canonical(t) for i,t in node.state['messages'].items()}
        ids,summary=self.prepare(node,peer,trace)
        self.assertIn(target,ids[2:])
        self.assertTrue(summary['priority']);self.assertTrue(summary['newest'])
        self.assertEqual(mesh.carriage_position(key),2)
        self.assertTrue(set(ids[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
        self.assertEqual(before,{i:wire.canonical(t) for i,t in node.state['messages'].items()})
        self.assertFalse(node.receipts())

    def test_changing_head_and_scope_cannot_reset_two_background_repayments(self):
        node,peer,target,raws,frames,key,history,trace,_=self.fixture()
        self.prepare(node,peer,trace)
        for expected in (1,False):
            raw=wire.make_frame('source-finality','1'*64,'2'*64,hashlib.sha256(str(expected).encode()).hexdigest(),b'{"no_value":true}')
            node.enqueue(raw,peer)
            head=wire.inspect_frame(raw)[0]['message_id']
            node.set_carriage_priority(mesh.digest({'new-scope':str(expected)}),(head,)+frames,ordered_frames=True)
            _,summary=self.prepare(node,peer,trace)
            self.assertFalse(summary['priority'])
            self.assertEqual(mesh.carriage_position(key),expected)
        _,summary=self.prepare(node,peer,trace)
        self.assertTrue(summary['priority']);self.assertIs(mesh.carriage_position(key),True)
        self.assertEqual(mesh.MAX_PACKET_BATCH,4)

    def test_full_retry_and_failed_publication_do_not_advance_repayment(self):
        node,peer,target,_,_,key,_,trace,_=self.fixture()
        before=node.path.read_bytes();state=copy.deepcopy(node.state)
        with patch.object(mesh,'atomic',side_effect=OSError('publication refused')):
            with self.assertRaises(OSError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),before);self.assertEqual(node.state,state)
        self.assertIs(mesh.carriage_position(key),True)
        ids,_=self.prepare(node,peer,trace);state=copy.deepcopy(node.state)
        with mesh._carriage_position_lock:positions=copy.deepcopy(mesh._carriage_positions)
        retry=node.prepare_exchange(peer,retry_packet_ids=tuple(ids))
        self.assertEqual([mesh.digest(t['packet']) for t in retry['body']['transits']],ids)
        self.assertEqual(node.state,state)
        with mesh._carriage_position_lock:self.assertEqual(mesh._carriage_positions,positions)
        self.assertEqual(mesh.carriage_position(key),2)

    def test_altered_packet_cannot_use_head_hint_or_publish_prepared_state(self):
        node,peer,target,_,_,key,_,_,_=self.fixture()
        before=node.path.read_bytes()
        node.state['messages'][target]['packet']['signature']='0'*128
        with self.assertRaises(ValueError):node.prepare_exchange(peer)
        self.assertEqual(node.path.read_bytes(),before)
        self.assertIs(mesh.carriage_position(key),True)

    def test_sustained_new_heads_keep_background_turns_and_all_required_history(self):
        node,peer,_,raws,frames,key,history,trace,_=self.fixture()
        turns=[];carried=set(node.state['first_carriage'][peer]['prepared'])
        for n in range(32):
            # Distinct scheduling heads model sustained admitted arrival; this
            # Mesh-only contract grants no Native authenticity or authority.
            raw=wire.make_frame('source-finality','1'*64,'2'*64,hashlib.sha256(str(n+1000).encode()).hexdigest(),b'{"no_value":true}')
            node.enqueue(raw,peer)
            head=wire.inspect_frame(raw)[0]['message_id']
            node.set_carriage_priority(mesh.digest({'scope':n}),(head,)+frames,ordered_frames=True)
            ids,summary=self.prepare(node,peer,trace);turns.append(summary['priority']);carried.update(ids)
        # Existing two FIFO places continue independently; borrowing repays and
        # cannot make three consecutive priority preparations across new scopes.
        self.assertNotIn([True,True,True],[turns[i:i+3] for i in range(len(turns)-2)])
        self.assertGreaterEqual(turns.count(False),len(turns)//2-1)
        self.assertTrue(set(history)<=carried)
        # Required unresolved retransmission remains live after first service.
        repeated=set()
        for _ in range(64):
            ids,_=self.prepare(node,peer,trace);repeated.update(ids)
        self.assertTrue(set(history)<=repeated)
        self.assertFalse(node.receipts());node.validate_state()

    def test_cold_open_keeps_prepared_head_and_complete_original_bytes(self):
        node,peer,target,raws,frames,key,_,trace,configs=self.fixture()
        self.prepare(node,peer,trace);packet=copy.deepcopy(node.state['messages'][target]);node.close()
        with mesh.Node(configs[0]) as cold:
            self.assertIn(target,cold.state['first_carriage'][peer]['prepared'])
            self.assertEqual(cold.state['messages'][target],packet)
            self.assertEqual(mesh.transit_check(cold.state['messages'][target],cold.network)[1],raws[-1])
            cold.set_carriage_priority('a'*64,frames,ordered_frames=True)
            cold.validate_state()


if __name__=='__main__':unittest.main()
