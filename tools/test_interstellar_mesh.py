"""Discovery, custody, hostile input and restart checks for the mesh prototype."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as evidence

NETWORK = 'a' * 64


def signed_ground_empty_proposal(context, key):
    """Real Native-domain signature; no Native proof, work or ledger authority."""
    public=key.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex()
    parent=dict(currency=context['currency'],region=context['region'],parent='2'*64,
        anchor=context['previous'],height=context['parent_height'],miner=public,
        commands='4'*64,state=context['parent_state'],nonce=0)
    block_hash=lambda h:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+
        json.dumps(h,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    context=dict(context,parent_block=block_hash(parent))
    child=dict(parent,parent=context['parent_block'],height=context['parent_height']+1,state='5'*64)
    statement=dict(currency=context['currency'],region=context['region'],height=child['height'],
        block=block_hash(child),state=child['state'],previous=context['previous'],epoch=context['epoch'])
    snapshot=dict(base=context['previous'],statement=statement,approvals=[],
        blocks=[dict(header=parent,commands=[]),dict(header=child,commands=[])],epochs=[])
    signed=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\0'+json.dumps(
        [0,snapshot,None,public],separators=(',',':'),ensure_ascii=False).encode()
    signature=key.sign(signed).hex();key.public_key().verify(bytes.fromhex(signature),signed)
    return context,dict(round=0,snapshot=snapshot,timeout=None,leader=dict(key=public,signature=signature))


def signed_ground_import_parent_proposal(context, key):
    """Fresh ground Import-parent bytes and real proposal signature; no authority."""
    context,proposal=signed_ground_empty_proposal(context,key)
    snapshot=proposal['snapshot'];parent,child=snapshot['blocks']
    parent['commands']=[{'Import':{'snapshot':'6'*64,'export':'7'*64}}]
    encode=lambda v:json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()
    parent['header']['commands']=evidence.hashlib.sha256(
        b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encode(parent['commands'])).hexdigest()
    block_hash=lambda h:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encode(h)).hexdigest()
    context=dict(context,parent_block=block_hash(parent['header']));child['header']['parent']=context['parent_block']
    snapshot['statement']['block']=block_hash(child['header'])
    data=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\0'+encode([0,snapshot,None,proposal['leader']['key']])
    proposal['leader']['signature']=key.sign(data).hex();key.public_key().verify(bytes.fromhex(proposal['leader']['signature']),data)
    return context,proposal


class Fixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.names = ['earth', 'proxima', 'andromeda']
        self.identities = {name: mesh.initialize(self.root / name, NETWORK, str(i + 1) * 64, name)
                           for i, name in enumerate(self.names)}
        self.configs = {}
        for i, name in enumerate(self.names):
            contacts = []
            for j, other in enumerate(self.names):
                if abs(i - j) == 1:
                    contacts.append({'peer': self.identities[other]['node_id'],
                                     'inbox': str(self.root / 'links' / (other + '-' + name)),
                                     'outbox': str(self.root / 'links' / (name + '-' + other))})
            self.configs[name] = {'format': mesh.VERSION, 'state': str(self.root / name),
                                  'network': NETWORK, 'contacts': contacts}

    def node(self, name):
        return mesh.Node(self.configs[name])

    def rounds(self, count=6, names=None):
        for _ in range(count):
            for name in names or self.names:
                with self.node(name) as node:
                    result = node.tick()
                    if result['errors']:
                        raise ValueError(result['errors'])

    def frame(self):
        return evidence.make_frame('source-finality', '1' * 64, '3' * 64, '4' * 64,
                                   b'{"ground_fixture":"requires separate ledger validation"}')


class MeshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.f = Fixture(self.temporary.name)

    def test_waiting_direct_copy_precedes_same_frame_detours_on_ordinary_pair(self):
        self.f.rounds()
        peer=self.f.identities['proxima']['node_id']
        destination=self.f.identities['andromeda']['node_id']
        raw=evidence.make_frame('source-finality','1'*64,'3'*64,'6'*64,
                                b'{"same_complete_frame":"carriage_only"}')
        with self.f.node('earth') as node:
            older=[node.enqueue(self.f.frame(),destination) for _ in range(2)]
            detours=[node.enqueue(raw,destination) for _ in range(2)]
            target=node.enqueue(raw,peer)
            # Exact live counterexample: two older offers, then two copies of
            # the current complete frame for other recipients ahead of its
            # directly connected recipient. The nonpriority pair keeps two
            # ordinary streams; this fixture isolates their already chosen order.
            order=older+detours+[target]
            node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
            node.state['transit_class_steps'][peer]=2;node.save()
            original=copy.deepcopy(node.state['messages']);durable=node.path.read_bytes()
            with patch.object(node,'transit_groups',return_value=[order,[]]):
                selected=node.prepare_exchange(peer)
            ids=[mesh.digest(t['packet']) for t in selected['body']['transits']]
            self.assertEqual(ids[:2],older)
            self.assertEqual(len(ids),4)
            self.assertIn(target,ids[2:],'detour copies filled both spare slots before direct copy')
            self.assertEqual(node.state['messages'],original)
            self.assertFalse(node.receipts())
            self.assertLessEqual(len(evidence.canonical(selected)),mesh.MAX_BATCH)
            positions={k:copy.deepcopy(node.state[k]) for k in
                ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=tuple(ids))
            self.assertEqual([mesh.digest(t['packet']) for t in replay['body']['transits']],ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertNotEqual(node.path.read_bytes(),durable)
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'],original)
            # Prepared direct copies must not displace still waiting detours on
            # successive calls, even with a cold primitive scheduling cache.
            remaining=set(detours)-set(ids)
            seen=set()
            for _ in range(3):
                bundle=node.prepare_exchange(peer)
                seen.update(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertTrue(remaining<=seen)
            self.assertFalse(node.receipts())

    def test_direct_waiting_preference_revalidates_and_cannot_grant_custody(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        destination=self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            raw=self.f.frame();detours=[node.enqueue(raw,destination) for _ in range(4)]
            target=node.enqueue(raw,peer);original=copy.deepcopy(node.state)
            durable=node.path.read_bytes()
            node.state['messages'][target]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(original)
            with patch.object(mesh,'atomic',side_effect=OSError('direct selection publication')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,original);self.assertEqual(node.path.read_bytes(),durable)
            offered=node.exchange(peer,retry_packet_ids=(target,))
            exact=next(t for t in offered['body']['transits'] if mesh.digest(t['packet'])==target)
            suppressed=node.prepare_exchange(peer,accepted_transits={mesh.digest(exact)})
            self.assertNotIn(target,[mesh.digest(t['packet']) for t in suppressed['body']['transits']])
            self.assertNotIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts());self.assertEqual(node.state['messages'],original['messages'])
            bundle=node.prepare_exchange(peer)
            self.assertIn(target,[mesh.digest(t['packet']) for t in bundle['body']['transits']])
            self.assertLessEqual(len(bundle['body']['transits']),4)
            self.assertLessEqual(len(evidence.canonical(bundle)),mesh.MAX_BATCH)
            self.assertFalse(node.receipts());node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'],original['messages'])
            self.assertFalse(node.receipts())

    def test_new_direct_copies_cannot_starve_waiting_detour_offers(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        destination=self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            raw=self.f.frame();older=[node.enqueue(raw,destination) for _ in range(12)]
            node.state['first_carriage'][peer]=node.first_carriage_plan(peer);node.save()
            offered=set()
            for _ in range(6):
                node.enqueue_batch([(raw,peer)]*4)
                pending=node.first_carriage_plan(peer)['pending']
                bundle=node.prepare_exchange(peer)
                ids=[mesh.digest(t['packet']) for t in bundle['body']['transits']]
                self.assertEqual(ids[:2],pending[:2])
                offered.update(ids[:2])
                self.assertLessEqual(len(ids),4)
            self.assertTrue(set(older)<=offered)
            self.assertFalse(node.receipts())
            for ident in older:self.assertIn(ident,node.state['messages'])
            node.validate_state()

    def test_prepare_plan_is_local_to_one_operation_and_revalidates_new_arrival(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):
                node.enqueue(self.f.frame(), destination)
            with patch.object(node, 'first_carriage_plan', wraps=node.first_carriage_plan) as plans:
                first = node.prepare_exchange(peer)
                self.assertEqual(plans.call_count, 1)
                ids = tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
                self.assertEqual(len(ids), 4)
                before = copy.deepcopy(node.state['first_carriage'])
                node.prepare_exchange(peer, retry_packet_ids=ids)
                self.assertEqual(plans.call_count, 1)
                self.assertEqual(node.state['first_carriage'], before)
                target = node.enqueue(self.f.frame(), destination)
                transit = copy.deepcopy(node.state['messages'][target])
                durable = node.path.read_bytes()
                node.state['messages'][target]['packet']['signature'] = '0' * 128
                with self.assertRaises(ValueError):
                    node.prepare_exchange(peer)
                self.assertEqual(plans.call_count, 2)
                self.assertEqual(node.path.read_bytes(), durable)
                node.state['messages'][target] = transit
        with self.f.node('earth') as node:
            with patch.object(node, 'first_carriage_plan', wraps=node.first_carriage_plan) as plans:
                node.prepare_exchange(peer)
                self.assertEqual(plans.call_count, 1)
            node.validate_state()

    def _arrival_before_recent_eviction(self, full):
        self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(10):node.enqueue_batch([(self.f.frame(),destination)]*4)
            node.prepare_exchange(peer)
            if full:
                node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
                self.assertEqual(len(node.state['first_carriage'][peer]['pending']),32)
                node.save()
            target=node.enqueue(self.f.frame(),destination)
            original=copy.deepcopy(node.state['messages'][target])
            for _ in range(8):node.enqueue_batch([(self.f.frame(),destination)]*4)
            self.assertNotIn(target,node.state['recent_transits'])
            self.assertNotIn(target,node.state['first_carriage'][peer]['pending'])
            self.assertIn(target,node.state['first_arrivals'])
            # A fresh exact authenticated outgoing hop can be suppressed without
            # granting a destination receipt. This forces a durable waiting test
            # even if ordinary rotation would otherwise choose the target early.
            outgoing=node.exchange(peer,retry_packet_ids=(target,))['body']['transits'][0]
            self.assertEqual(mesh.digest(outgoing['packet']),target)
            suppressed={mesh.digest(outgoing)}
            state=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('arrival publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(peer,suppressed)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)
            node.prepare_exchange(peer,suppressed)
            first=node.state['first_carriage'][peer]
            self.assertIn(target,first['arrivals']+first['pending'])
            self.assertNotIn(target,first['prepared']);node.validate_state()
            order=list(node.state['first_arrivals']);metadata=copy.deepcopy(first)
        found=None
        for turn in range(17):
            with mesh._carriage_position_lock:
                mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with self.f.node('earth') as node:
                if turn==0:
                    self.assertEqual(node.state['first_arrivals'],order)
                    self.assertEqual(node.state['first_carriage'][peer],metadata)
                self.assertEqual(node.state['messages'][target],original)
                ids={mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']}
                node.validate_state()
                if target in ids:found=turn+1;break
        self.assertIsNotNone(found)
        with self.f.node('earth') as node:
            first=node.state['first_carriage'][peer]
            self.assertIn(target,first['prepared']);self.assertNotIn(target,first['pending']+first['arrivals'])
            self.assertEqual(node.state['messages'][target],original);self.assertNotIn(target,node.receipts())

    def test_other_ordinary_pair_keeps_original_recent_and_history_order(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(10):
                node.enqueue_batch([(self.f.frame(), destination)] * 4)
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            node.state['transit_class_steps'][peer] = 2
            node.save()
            pending = tuple(node.state['first_carriage'][peer]['pending'][:2])
            node.enqueue(self.f.frame(), destination)
            original = copy.deepcopy(node.state['messages'])
            groups = node.transit_groups(peer)
            expected = tuple(next(i for i in group if i not in pending) for group in groups)
            self.assertEqual(len(expected), 2)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pending)
            self.assertEqual(ids[2:], expected)
            self.assertEqual(node.state['transit_class_steps'][peer], 4)
            self.assertEqual(node.state['messages'], original)
            self.assertFalse(node.receipts())
        with self.f.node('earth') as node:
            self.assertEqual(node.state['transit_class_steps'][peer], 4)
            self.assertEqual(node.state['messages'], original)

    def test_new_arrival_uses_ordinary_class_slot_with_full_waiting_queue(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):
                node.enqueue_batch([(self.f.frame(), destination)] * 4)
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            node.save()
            pending = list(node.state['first_carriage'][peer]['pending'])
            self.assertEqual(len(pending), 32)
            target = node.enqueue(self.f.frame(), destination)
            original = copy.deepcopy(node.state['messages'])
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['messages'][target]['packet']['signature'] = '0' * 128
            with self.assertRaises(ValueError):
                node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = copy.deepcopy(state)
            with patch.object(mesh, 'atomic', side_effect=OSError('arrival offer publication')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(peer)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), durable)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(pending[:2]))
            self.assertIn(target, ids[2:])
            self.assertEqual(len(ids), 4)
            first = node.state['first_carriage'][peer]
            self.assertEqual(first['pending'], [i for i in pending if i not in ids])
            self.assertIn(target, first['prepared'])
            self.assertNotIn(target, first['arrivals'])
            self.assertEqual(node.state['messages'], original)
            self.assertFalse(node.receipts())
            positions = {k: copy.deepcopy(node.state[k]) for k in
                         ('first_carriage', 'transit_cursors', 'recent_transit_cursors',
                          'history_transit_cursors', 'transit_class_steps')}
            replay = node.prepare_exchange(peer, retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), ids)
            self.assertEqual({k: node.state[k] for k in positions}, positions)
            node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'], original)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts())
            state = copy.deepcopy(node.state)
            node.state['transit_scheduler'] = 'RLD-CONTACT-TRANSIT-SCHEDULER-V8'
            with self.assertRaises(ValueError):
                node.validate_state()
            node.state = state

    def test_latest_waiting_arrival_gets_spare_slot_without_displacing_pending_pair(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):
                node.enqueue_batch([(self.f.frame(), destination)] * 4)
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            node.save()
            pending = list(node.state['first_carriage'][peer]['pending'])
            self.assertEqual(len(pending), 32)
            waiting = [node.enqueue(self.f.frame(), destination) for _ in range(22)]
            target = waiting[-1]
            self.assertEqual(node.first_carriage_plan(peer)['arrivals'], waiting)
            original = copy.deepcopy(node.state['messages'])
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['messages'][target]['packet']['signature'] = '0' * 128
            with self.assertRaises(ValueError):
                node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = copy.deepcopy(state)
            with patch.object(mesh, 'atomic', side_effect=OSError('latest arrival publication')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(peer)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), durable)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(pending[:2]))
            self.assertEqual(len(ids), 4)
            self.assertIn(target, ids[2:])
            self.assertTrue(set(ids[2:]) & set(pending[2:]))
            self.assertEqual(node.state['messages'], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertNotIn(target, node.state['first_carriage'][peer]['arrivals'])
            self.assertIn(waiting[0], node.state['first_carriage'][peer]['arrivals'])
            positions = {k: copy.deepcopy(node.state[k]) for k in
                         ('first_carriage', 'transit_cursors', 'recent_transit_cursors',
                          'history_transit_cursors', 'transit_class_steps')}
            replay = node.prepare_exchange(peer, retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), ids)
            self.assertEqual({k: node.state[k] for k in positions}, positions)
            node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'], original)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts())
            durable = node.path.read_bytes()
            state = copy.deepcopy(node.state)
            node.state['transit_scheduler'] = 'RLD-CONTACT-TRANSIT-SCHEDULER-V10'
            with self.assertRaises(ValueError):
                node.validate_state()
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = state

    def test_promoted_latest_waiter_keeps_priority_until_prepared(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):
                node.enqueue_batch([(self.f.frame(), destination)] * 4)
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            node.save()
            target = node.enqueue(self.f.frame(), destination)
            target_offer = node.exchange(peer, retry_packet_ids=(target,))
            transit = next(t for t in target_offer['body']['transits']
                           if mesh.digest(t['packet']) == target)
            node.prepare_exchange(peer, accepted_transits={mesh.digest(transit)})
            first = node.state['first_carriage'][peer]
            self.assertIn(target, first['arrivals'])
            self.assertNotIn(target, first['prepared'])
            promoted = node.first_carriage_plan(peer)
            self.assertIn(target, promoted['pending'])
            self.assertNotIn(target, promoted['arrivals'])
            # Retain this authentic admission plan as explicit fixture setup;
            # no carriage, receipt or ledger right is granted by these IDs.
            node.state['first_carriage'][peer] = promoted
            node.state['recent_transit_cursors'][peer] = target
            node.state['transit_class_steps'][peer] = 0
            node.save()
            with mesh._carriage_position_lock:
                mesh._carriage_positions.clear()
                mesh._carriage_position_bytes = 0
            pending = list(promoted['pending'])
            self.assertNotIn(target, pending[:2])
            original = copy.deepcopy(node.state['messages'])
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['messages'][target]['packet']['signature'] = '0' * 128
            with self.assertRaises(ValueError):
                node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = copy.deepcopy(state)
            with patch.object(mesh, 'atomic', side_effect=OSError('promoted priority publication')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(peer)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), durable)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(pending[:2]))
            self.assertEqual(len(ids), 4)
            self.assertIn(target, ids[2:], 'promoted unserved target lost ordinary priority')
            # Ordinary history may retransmit an already prepared original ID.
            self.assertTrue((set(ids[2:]) - {target}) & set(original))
            self.assertEqual(node.state['messages'], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            positions = {k: copy.deepcopy(node.state[k]) for k in
                         ('first_carriage', 'transit_cursors', 'recent_transit_cursors',
                          'history_transit_cursors', 'transit_class_steps')}
            replay = node.prepare_exchange(peer, retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), ids)
            self.assertEqual({k: node.state[k] for k in positions}, positions)
            node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'], original)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts())
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['transit_scheduler'] = 'RLD-CONTACT-TRANSIT-SCHEDULER-V11'
            with self.assertRaises(ValueError):
                node.validate_state()
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = state

    def test_older_pending_advances_under_new_arrivals_and_full_replay(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):
                    break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(self.f.frame(), destination) for _ in range(32)]
            target = admitted[12]
            promoted = node.first_carriage_plan(peer)
            self.assertEqual(promoted['pending'].index(target), 12)
            self.assertEqual(node.state['first_arrivals'].index(target), 29)
            node.state['first_carriage'][peer] = promoted
            node.save()
            for _ in range(22):
                node.enqueue(self.f.frame(), destination)
            original = copy.deepcopy(node.state['messages'][target])
            selected_turn = None
            for turn in range(1, 8):
                node.enqueue_batch([(self.f.frame(), destination)] * 4)
                pending = node.first_carriage_plan(peer)['pending']
                bundle = node.prepare_exchange(peer)
                ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
                self.assertEqual(ids[:2], tuple(pending[:2]))
                self.assertEqual(len(ids), 4)
                positions = {k: copy.deepcopy(node.state[k]) for k in
                             ('first_carriage', 'recent_transit_cursors',
                              'history_transit_cursors', 'transit_class_steps')}
                replay = node.prepare_exchange(peer, retry_packet_ids=ids)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), ids)
                self.assertEqual({k: node.state[k] for k in positions}, positions)
                self.assertEqual(node.state['messages'][target], original)
                self.assertFalse(node.receipts())
                if target in ids:
                    selected_turn = turn
                    break
            self.assertIsNotNone(selected_turn, 'newer arrivals displaced the retained pending target')
            self.assertLessEqual(selected_turn, 7)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'][target], original)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts())

    def test_older_unserved_gets_alternate_priority_pair_without_displacing_offers(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):
                    break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(self.f.frame(), destination) for _ in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            self.assertEqual(node.state['first_carriage'][peer]['pending'], admitted)
            for _ in range(22):
                node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 4
            node.save()
            original = copy.deepcopy(node.state['messages'])
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['messages'][target]['packet']['signature'] = '0' * 128
            with self.assertRaises(ValueError):
                node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = copy.deepcopy(state)
            with patch.object(mesh, 'atomic', side_effect=OSError('older priority publication')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(peer)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), durable)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(admitted[:2]))
            self.assertEqual(len(ids), 4)
            self.assertIn(target, ids[2:], 'older unserved arrival lost alternate spare-class service')
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'], original)
            self.assertFalse(node.receipts())
            positions = {k: copy.deepcopy(node.state[k]) for k in
                         ('first_carriage', 'recent_transit_cursors',
                          'history_transit_cursors', 'transit_class_steps')}
            replay = node.prepare_exchange(peer, retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), ids)
            self.assertEqual({k: node.state[k] for k in positions}, positions)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            node.validate_state()
        with self.f.node('earth') as node:
            self.assertEqual(node.state['messages'], original)
            self.assertIn(target, node.state['first_carriage'][peer]['prepared'])
            self.assertFalse(node.receipts())

    def test_older_spare_priority_reaches_destination_via_ordinary_ticks(self):
        self.f.rounds()
        destination = self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(destination)
                if set(baseline) <= set(node.state['first_carriage'][destination]['prepared']):
                    break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][destination]['prepared']))
            admitted = [node.enqueue(self.f.frame(), destination) for _ in range(32)]
            target = admitted[2]
            node.state['first_carriage'][destination] = node.first_carriage_plan(destination)
            for _ in range(22):
                node.enqueue(self.f.frame(), destination)
            node.state['transit_class_steps'][destination] = 4
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            state = copy.deepcopy(node.state)
            durable = node.path.read_bytes()
            node.state['messages'][target]['packet']['signature'] = '0' * 128
            with self.assertRaises(ValueError):
                node.prepare_exchange(destination)
            self.assertEqual(node.path.read_bytes(), durable)
            node.state = copy.deepcopy(state)
            with patch.object(mesh, 'atomic', side_effect=OSError('ordinary older arrival publication')):
                with self.assertRaises(OSError):
                    node.prepare_exchange(destination)
            self.assertEqual(node.state, state)
            self.assertEqual(node.path.read_bytes(), durable)
            result = node.tick()
            self.assertFalse(result['errors'])
            self.assertIn(target, node.state['first_carriage'][destination]['prepared'])
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
        outgoing = list((self.f.root / 'links/earth-proxima').glob('*.json'))
        self.assertEqual(len(outgoing), 1)
        bundle = mesh.load(outgoing[0], mesh.MAX_BATCH)
        transits = bundle['body']['transits']
        ids = [mesh.digest(t['packet']) for t in transits]
        self.assertEqual(ids[:2], admitted[:2])
        self.assertIn(target, ids[2:])
        with self.f.node('earth') as node:
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            positions = {k: copy.deepcopy(node.state[k]) for k in
                         ('first_carriage', 'recent_transit_cursors',
                          'history_transit_cursors', 'transit_class_steps')}
            replay = node.prepare_exchange(destination, retry_packet_ids=tuple(ids))
            self.assertEqual([mesh.digest(t['packet']) for t in replay['body']['transits']], ids)
            self.assertEqual({k: node.state[k] for k in positions}, positions)
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
        carried = next(t for t in transits if mesh.digest(t['packet']) == target)
        self.assertEqual(carried['packet'], original['packet'])
        self.assertEqual(carried['routing'], original['routing'])
        with self.f.node('proxima') as node:
            self.assertFalse(node.tick()['errors'])
            self.assertIn(target, node.receipts())
        with mesh._verified_transits_lock:
            mesh._verified_transits.clear()
        with self.f.node('proxima') as node:
            transit = node.state['messages'][target]
            receipt = node.receipts()[target]
            mesh.transit_check(transit, NETWORK, destination, self.f.identities['earth']['node_id'])
            self.assertEqual(mesh.receipt_check(receipt, NETWORK), target)
            mesh.receipt_matches(receipt, transit)
            self.assertEqual(transit, carried)
            self.assertEqual(receipt['body']['outcome'], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_current_signed_commit_gets_spare_slot_before_newer_waiters(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Commit', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Commit',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Prepare'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Commit spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                node.set_carriage_priority(mesh.digest(context),frames)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(admitted[:2]))
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())

    def test_native_context_commit_hint_reaches_destination_via_ordinary_ticks(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Commit', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Commit',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Prepare'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Commit spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], tuple(admitted[:2]))
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())

    def test_commit_hint_capacity_eviction_and_contact_scope_fall_back(self):
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        context=dict(currency=NETWORK,region='9'*64,epoch=0,previous='0'*64,
                     parent_height=13,parent_block='2'*64,parent_state='3'*64)
        keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
            mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
        key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([4])*32)
        data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps(
            [context,0,'5'*64,'Commit',keys[0]],separators=(',',':'),ensure_ascii=False).encode()
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),
                      body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase='Commit',
                      approval=dict(key=keys[0],signature=key.sign(data).hex())))))
        messages=Messages().append(mesh.digest(envelope['body']),envelope,None,True)
        with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',1):
            self.assertEqual(bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region']),())
        self.f.rounds()
        with self.f.node('earth') as node:
            raw=node.path.read_bytes();state=copy.deepcopy(node.state)
            for scope,ids in (('bad',()),(NETWORK,['1'*64]),(NETWORK,('1'*64,'1'*64)),
                              (NETWORK,tuple(format(i,'064x') for i in range(513)))):
                with self.assertRaises(ValueError):node.set_carriage_priority(scope,ids)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)
            key=node.set_carriage_priority(NETWORK,('1'*64,))
            with self.f.node('andromeda') as other:
                self.assertNotEqual(node.carriage_position_domain(),other.carriage_position_domain())
                self.assertIsNone(mesh.carriage_position((other.carriage_position_domain(),'native-commit-spare')))
            with patch.object(mesh,'MAX_HOPS',mesh.MAX_HOPS-1):
                self.assertIsNone(mesh.carriage_position((node.carriage_position_domain(),'native-commit-spare')))
            for i in range(mesh.MAX_CARRIAGE_POSITIONS+1):
                mesh.remember_carriage_position(('primitive-test',i),format(i,'064x'))
            self.assertIsNone(mesh.carriage_position(key))
            self.assertLessEqual(len(mesh._carriage_positions),mesh.MAX_CARRIAGE_POSITIONS)
            self.assertLessEqual(mesh._carriage_position_bytes,mesh.MAX_CARRIAGE_POSITION_BYTES)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)

    def test_prepared_unreceipted_commit_keeps_spare_slot_after_full_retry(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Commit', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Commit',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Prepare'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Commit spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            # Both sends are lost in this preparation-only counterexample.
            # Local prepared metadata is not a destination receipt.
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'prepared Commit with no destination receipt lost its ordinary spare priority after full4 retry')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_prepare_keeps_spare_after_native_current_commit_hint(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Prepare', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Prepare',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Commit'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Prepare spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Ground setup grants a one-shot primitive position, not Native authority.
                node.set_carriage_priority(mesh.digest(context),(evidence.inspect_frame(raw)[0]['message_id'],))
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            # Both sends are lost in this preparation-only counterexample.
            # Local prepared metadata is not a destination receipt.
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            # Following turn uses the actual current Native-envelope classifier.
            node.set_carriage_priority(mesh.digest(context),frames)
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'prepared Prepare with no destination receipt lost its ordinary spare priority after full4 retry')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_empty_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Ground setup grants a one-shot primitive position, not Native authority.
                node.set_carriage_priority(mesh.digest(context),(evidence.inspect_frame(raw)[0]['message_id'],))
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            # Both sends are lost in this preparation-only counterexample.
            # Local prepared metadata is not a destination receipt.
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            # Following turn uses the actual current Native-envelope classifier.
            node.set_carriage_priority(mesh.digest(context),frames)
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'prepared Proposal with no destination receipt lost its ordinary spare priority after full4 retry')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_import_parent_proposal_keeps_spare_after_native_current_hint(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_import_parent_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Ground setup grants a one-shot primitive position, not Native authority.
                node.set_carriage_priority(mesh.digest(context),(evidence.inspect_frame(raw)[0]['message_id'],))
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            # Both sends are lost in this preparation-only counterexample.
            # Local prepared metadata is not a destination receipt.
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            # Following turn uses the actual current Native-envelope classifier.
            node.set_carriage_priority(mesh.digest(context),frames)
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'prepared Proposal with no destination receipt lost its ordinary spare priority after full4 retry')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_current_frame_hint_survives_group_position_pressure_in_same_plan(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_import_parent_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Ground setup grants a one-shot primitive position, not Native authority.
                node.set_carriage_priority(mesh.digest(context),(evidence.inspect_frame(raw)[0]['message_id'],))
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            # Both sends are lost in this preparation-only counterexample.
            # Local prepared metadata is not a destination receipt.
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            # Following turn uses the actual current Native-envelope classifier.
            key=node.set_carriage_priority(mesh.digest(context),frames)
            domain=node.carriage_position_domain()
            for index in range(mesh.MAX_CARRIAGE_POSITIONS-1):
                mesh.remember_carriage_position((domain,'ground-only-pressure',index),'')
            # Membership does not refresh LRU; the hint is present at plan entry.
            self.assertIn(key,mesh._carriage_positions)
            self.assertEqual(len(mesh._carriage_positions),mesh.MAX_CARRIAGE_POSITIONS)
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            bundle = node.prepare_exchange(peer)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'prepared Proposal with no destination receipt lost its ordinary spare priority after full4 retry')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())

    def test_prepared_commit_priority_reaches_destination_after_full_retry(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Commit', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Commit',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Prepare'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Commit spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_prepare_priority_reaches_destination_after_full_retry(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        signed = b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0' + json.dumps(
            [context, 0, '5' * 64, 'Prepare', public], separators=(',', ':'), ensure_ascii=False).encode()
        signature = key.sign(signed).hex()
        key.public_key().verify(bytes.fromhex(signature), signed)
        envelope = dict(format=bft.NETWORK, currency=NETWORK, region=context['region'],
                        evidence=dict(snapshots=[]), body=dict(Signed=dict(Vote=dict(
                            context=context, round=0, value='5' * 64, phase='Prepare',
                            approval=dict(key=public, signature=signature)))))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('phase','Commit'),('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope)
                    vote=changed['body']['Signed']['Vote']
                    (vote if field=='phase' else vote['approval'])[field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Prepare spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_empty_proposal_priority_reaches_destination_after_full_retry(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_empty_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                for mutation in ('round','timeout','base','commands','epochs','parent','extra'):
                    changed=copy.deepcopy(envelope);proposal=changed['body']['Signed']['Proposal'];snap=proposal['snapshot']
                    if mutation=='round':proposal['round']=1
                    elif mutation=='timeout':proposal['timeout']={}
                    elif mutation=='base':snap['base']='6'*64
                    elif mutation=='commands':snap['blocks'][1]['commands']=[{'unqualified':True}]
                    elif mutation=='epochs':snap['epochs']=[{'unqualified':True}]
                    elif mutation=='parent':snap['blocks'][0]['header']['state']='6'*64
                    else:snap['bft']={}
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_prepared_import_parent_proposal_priority_reaches_destination_after_full_retry(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_import_parent_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                for mutation in ('round','timeout','base','commands','epochs','parent','extra'):
                    changed=copy.deepcopy(envelope);proposal=changed['body']['Signed']['Proposal'];snap=proposal['snapshot']
                    if mutation=='round':proposal['round']=1
                    elif mutation=='timeout':proposal['timeout']={}
                    elif mutation=='base':snap['base']='6'*64
                    elif mutation=='commands':snap['blocks'][1]['commands']=[{'unqualified':True}]
                    elif mutation=='epochs':snap['epochs']=[{'unqualified':True}]
                    elif mutation=='parent':snap['blocks'][0]['header']['state']='6'*64
                    else:snap['bft']={}
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                for mutation in ('over16','unknown','extra','hex','header_hash'):
                    changed=copy.deepcopy(envelope);snap=changed['body']['Signed']['Proposal']['snapshot'];parent=snap['blocks'][0]
                    if mutation=='over16':parent['commands']*=17
                    elif mutation=='unknown':parent['commands']=[{'Spend':{}}]
                    elif mutation=='extra':parent['commands'][0]['Import']['extra']=None
                    elif mutation=='hex':parent['commands'][0]['Import']['export']='z'*64
                    else:parent['header']['commands']='8'*64
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())


    def test_new_remote_current_frame_invalidates_complete_broadcast_quiet_inventory(self):
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
        first=envelope(0,'Prepare');remote=envelope(1,'Commit')
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

    def test_current_frame_hint_pressure_ordinary_delivery(self):
        # Inner signature and transport signatures are real fixture signatures;
        # the empty Native proof deliberately grants no ledger qualification.
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        destination = self.f.identities['andromeda']['node_id']
        key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
        public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
        context = dict(currency=NETWORK, region='9' * 64, epoch=0, previous='0' * 64,
                       parent_height=13, parent_block='2' * 64, parent_state='3' * 64)
        context,proposal=signed_ground_import_parent_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
        messages = Messages().append(mesh.digest(envelope['body']), envelope, None, True)
        payload = evidence.canonical(envelope)
        raw = evidence.make_frame('regional-bft', context['region'], context['region'],
                                  evidence.hashlib.sha256(payload).hexdigest(), payload)
        with self.f.node('earth') as node:
            baseline = [node.enqueue(self.f.frame(), destination) for _ in range(17)]
            for _ in range(9):
                node.prepare_exchange(peer)
                if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
            self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
            admitted = [node.enqueue(raw if i == 2 else self.f.frame(), destination) for i in range(32)]
            target = admitted[2]
            node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
            for _ in range(22):node.enqueue(self.f.frame(), destination)
            self.assertNotIn(target, node.state['recent_transits'])
            node.state['transit_class_steps'][peer] = 0
            node.save()
            original = copy.deepcopy(node.state['messages'][target])
            if hasattr(bft, 'commit_carriage_frames'):
                keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
                frames = bft.commit_carriage_frames(messages, context, keys, NETWORK, context['region'])
                self.assertEqual(frames, (evidence.inspect_frame(raw)[0]['message_id'],))
                for field,value in (('currency','b'*64),('region','8'*64),('parent_height',14),
                                    ('parent_block','6'*64),('parent_state','7'*64),('epoch',1),('previous','1'*64)):
                    altered=dict(context,**{field:value})
                    self.assertEqual(bft.commit_carriage_frames(messages,altered,keys,NETWORK,context['region']),())
                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                for mutation in ('round','timeout','base','commands','epochs','parent','extra'):
                    changed=copy.deepcopy(envelope);proposal=changed['body']['Signed']['Proposal'];snap=proposal['snapshot']
                    if mutation=='round':proposal['round']=1
                    elif mutation=='timeout':proposal['timeout']={}
                    elif mutation=='base':snap['base']='6'*64
                    elif mutation=='commands':snap['blocks'][1]['commands']=[{'unqualified':True}]
                    elif mutation=='epochs':snap['epochs']=[{'unqualified':True}]
                    elif mutation=='parent':snap['blocks'][0]['header']['state']='6'*64
                    else:snap['bft']={}
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                for mutation in ('over16','unknown','extra','hex','header_hash'):
                    changed=copy.deepcopy(envelope);snap=changed['body']['Signed']['Proposal']['snapshot'];parent=snap['blocks'][0]
                    if mutation=='over16':parent['commands']*=17
                    elif mutation=='unknown':parent['commands']=[{'Spend':{}}]
                    elif mutation=='extra':parent['commands'][0]['Import']['extra']=None
                    elif mutation=='hex':parent['commands'][0]['Import']['export']='z'*64
                    else:parent['header']['commands']='8'*64
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']=[{'ground_only':'different complete proof'}]
                changed_messages=Messages().append(mesh.digest(changed['body']),changed,None,True)
                self.assertNotEqual(bft.commit_carriage_frames(changed_messages,context,keys,NETWORK,context['region']),frames)
                hint_key=node.set_carriage_priority(mesh.digest(context),frames)
                durable=node.path.read_bytes();state=copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('Proposal spare publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                mesh.forget_carriage_position(hint_key)
                fallback=node.exchange(peer)
                self.assertNotIn(target,[mesh.digest(t['packet']) for t in fallback['body']['transits']])
                # Exercise actual Runtime observation/broadcast plumbing with an
                # explicitly modelled Native admission, not a Native constructor.
                from types import SimpleNamespace
                from contextlib import nullcontext
                runtime=object.__new__(bft.Runtime)
                runtime.format=bft.FORMAT;runtime.region=context['region'];runtime.node_id=node.id
                runtime.native=SimpleNamespace(authority=NETWORK,currency=NETWORK,ledger=self.f.root/'model-ledger')
                runtime.transport=node.config if hasattr(node,'config') else self.f.configs['earth']
                runtime.binding=dict(currency=NETWORK,region=context['region'],key=public)
                destinations=(node.id,peer,destination,'f'*64)
                runtime.peers=dict(zip(keys,destinations));runtime.joint=None
                runtime.state=dict(messages=messages,height=13,tip=context['parent_block'],cursor=0)
                runtime._retained_native_authenticated=True;runtime._broadcast_quiet=None
                runtime.extra_locks=[];runtime.lock=runtime.head_lock=None
                runtime.save=lambda state:setattr(runtime,'state',state)
                runtime.carriage_node=lambda:nullcontext(node)
                runtime._observe_context(context)
                runtime.broadcast()
                hint_key=runtime._carriage_priority_key
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                with patch.object(node,'set_carriage_priority',side_effect=AssertionError('quiet broadcast changed hint')):
                    runtime.broadcast()
                with self.assertRaisesRegex(ValueError,'rolled back'):
                    runtime._observe_context(dict(context,parent_block='6'*64))
                self.assertEqual(mesh.carriage_position(hint_key)[1],frames)
                runtime._observe_context(dict(context,parent_height=14,parent_block='6'*64))
                self.assertIsNone(mesh.carriage_position(hint_key))
                runtime.broadcast()
                self.assertEqual(mesh.carriage_position(runtime._carriage_priority_key)[1],())
                # Restore the model's fresh current context, never a ledger or
                # Native rollback. The separately created Runtime stub has no funds.
                runtime.close()
                node.set_carriage_priority(mesh.digest(context),frames)
            first=node.prepare_exchange(peer)
            first_ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            self.assertIn(target,first_ids[2:])
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            retry=node.prepare_exchange(peer,retry_packet_ids=first_ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),first_ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertFalse(node.receipts())
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            node.state['transit_class_steps'][peer]=0;node.save()
            pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
            self.assertNotIn(target,pair)
            key=node.set_carriage_priority(mesh.digest(context),frames)
            domain=node.carriage_position_domain()
            for index in range(mesh.MAX_CARRIAGE_POSITIONS-1):
                mesh.remember_carriage_position((domain,'ground-only-pressure',index),'')
            self.assertIn(key,mesh._carriage_positions)
            self.assertEqual(len(mesh._carriage_positions),mesh.MAX_CARRIAGE_POSITIONS)
            self.assertFalse(node.tick()['errors'])
            outgoing=list((self.f.root/'links/earth-proxima').glob('*.json'))
            self.assertEqual(len(outgoing),1)
            bundle=mesh.load(outgoing[0],mesh.MAX_BATCH)
            ids = tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
            self.assertEqual(ids[:2], pair)
            self.assertEqual(len(ids), 4)
            self.assertTrue(set(ids[2:]) & set(node.state['recent_transits']))
            self.assertEqual(node.state['messages'][target], original)
            self.assertFalse(node.receipts())
            self.assertIn(target, ids[2:], 'current signed Commit waited behind newer non-Commit arrivals')
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors',
                       'history_transit_cursors','transit_class_steps')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertEqual(node.state['messages'][target],original)
        carried=next(t for t in bundle['body']['transits'] if mesh.digest(t['packet'])==target)
        self.assertEqual(carried['packet'],original['packet']);self.assertEqual(carried['routing'],original['routing'])
        # Sorted contact order reads Earth's inbox after the Andromeda branch.
        # Two ordinary relay ticks are the exact finite bound for this route.
        for _ in range(2):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw)
            mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(transit['packet'],original['packet']);self.assertEqual(transit['routing'],original['routing'])
            self.assertEqual(len(transit['hops']),2)
            self.assertEqual(receipt['body']['outcome'],'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertEqual(node.state['messages'][target],original)
            self.assertFalse(node.receipts())

    def test_arrival_waiting_survives_preparation_gap_atomic_failure_and_cold_open(self):
        self._arrival_before_recent_eviction(False)

    def test_arrival_waiting_survives_full_admission_queue_and_cold_open(self):
        self._arrival_before_recent_eviction(True)

    def test_arrival_metadata_schema_and_original_capacity_refuse_without_write(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state);raw=node.path.read_bytes()
            for rows in ([ident,ident],[],['f'*64],['x'],[format(i,'064x') for i in range(257)]):
                node.state=copy.deepcopy(original);node.state['first_arrivals']=rows
                with self.assertRaisesRegex(ValueError,'arrival order|invalid 32-byte identifier'):node.validate_state()
                self.assertEqual(node.path.read_bytes(),raw)
            for field,value in (('arrivals',[format(i,'064x') for i in range(257)]),('observed',[format(i,'064x') for i in range(257)]),('observed','not-a-list'),('next_kind',True),('next_kind',2),('history_after','x')):
                node.state=copy.deepcopy(original);node.state['first_carriage'][peer][field]=value
                with self.assertRaises(ValueError):node.validate_state()
                self.assertEqual(node.path.read_bytes(),raw)
            node.state=copy.deepcopy(original);first=node.state['first_carriage'][peer];first['arrivals']=[ident];first['pending']=[ident]
            with self.assertRaisesRegex(ValueError,'waiting/prepared overlap'):node.validate_state()
            self.assertEqual(node.path.read_bytes(),raw);node.state=original

    def test_first_offer_queue_is_scoped_to_actual_outgoing_branch(self):
        self.f.rounds();left=self.f.identities['earth']['node_id'];right=self.f.identities['andromeda']['node_id']
        with self.f.node('proxima') as node:
            wrong=[node.enqueue(self.f.frame(),right) for _ in range(32)]
            original=copy.deepcopy(node.state['messages'])
            self.assertFalse(node.prepare_exchange(left)['body']['transits'])
            self.assertEqual(node.state['first_carriage'][left]['pending'],[])
            target=node.enqueue(self.f.frame(),left)
            bundle=node.prepare_exchange(left)
            self.assertIn(target,{mesh.digest(t['packet']) for t in bundle['body']['transits']})
            self.assertIn(target,node.state['first_carriage'][left]['prepared'])
            self.assertEqual({i:node.state['messages'][i] for i in wrong},original)
            self.assertFalse(node.state['receipts'])
            # The other branch retains ordinary first service and original bytes.
            right_ids={mesh.digest(t['packet']) for t in node.prepare_exchange(right)['body']['transits']}
            self.assertTrue(right_ids&set(wrong));self.assertNotIn(target,right_ids)

    def test_ineligible_waiting_metadata_changes_only_after_atomic_preparation(self):
        self.f.rounds();left=self.f.identities['earth']['node_id'];right=self.f.identities['andromeda']['node_id']
        with self.f.node('proxima') as node:
            wrong=[node.enqueue(self.f.frame(),right) for _ in range(32)]
            # Route changes may leave valid but currently ineligible metadata.
            node.state['first_carriage'][left]['pending']=wrong;node.save()
            target=node.enqueue(self.f.frame(),left);before=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('first queue publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(left)
            self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),raw)
        with self.f.node('proxima') as node:
            self.assertIn(target,{mesh.digest(t['packet']) for t in node.prepare_exchange(left)['body']['transits']})
            self.assertFalse(node.state['first_carriage'][left]['pending'])
            self.assertEqual(node.state['messages'],before['messages']);self.assertFalse(node.state['receipts'])

    def test_first_offer_survives_recent_eviction_and_cold_positions(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            initial=[node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id']) for _ in range(40)]
            old=set(initial)-set(node.state['recent_transits'])
            first=node.prepare_exchange(peer)
            carried={mesh.digest(t['packet']) for t in first['body']['transits']}
            self.assertTrue(carried&old)  # ordinary historical service still runs
            queue=node.state['first_carriage'][peer]['pending']
            self.assertLessEqual(len(queue),mesh.MAX_RECENT_TRANSITS)
            target=queue[-1];original=copy.deepcopy(node.state['messages'][target])
            for _ in range(40):node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.assertNotIn(target,node.state['recent_transits'])
        found=None
        for turn in range(16):
            with mesh._carriage_position_lock:
                mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with self.f.node('earth') as node:
                self.assertEqual(node.state['messages'][target],original)
                ids={mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']}
                if target in ids:found=turn+1;break
        self.assertIsNotNone(found)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertNotIn(target,node.state['first_carriage'][peer]['pending'])
            self.assertNotIn(target,node.receipts())
            self.assertEqual(node.state['messages'][target],original)

    def test_first_offer_authentication_and_failed_atomic_do_not_publish_metadata(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            before=node.path.read_bytes();state=copy.deepcopy(node.state)
            node.state['messages'][ident]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(),before)
            node.state=copy.deepcopy(state)
            with patch.object(mesh,'atomic',side_effect=OSError('first offer publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,state)
            self.assertEqual(node.path.read_bytes(),before)

    def test_first_offer_metadata_schema_and_original_capacities_refuse(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state['first_carriage']);before=node.path.read_bytes()
            invalid=[{**mesh.empty_first_carriage(),'pending':[ident],'prepared':[ident]},
                {**mesh.empty_first_carriage(),'pending':[format(i,'064x') for i in range(33)],'prepared':[]},
                {**mesh.empty_first_carriage(),'pending':[],'prepared':[format(i,'064x') for i in range(257)]},
                {**mesh.empty_first_carriage(),'pending':['x'],'prepared':[]},{**mesh.empty_first_carriage(),'pending':[],'prepared':[],'authority':True}]
            for value in invalid:
                node.state['first_carriage'][peer]=value
                with self.assertRaises(ValueError):node.validate_state()
                self.assertEqual(node.path.read_bytes(),before)
            node.state['first_carriage']=original

    def test_retry_preserves_ordinary_positions_and_retains_original_packets(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            first=node.prepare_exchange(peer)
            ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            positions={k:copy.deepcopy(node.state[k]) for k in ('transit_cursors','recent_transit_cursors','history_transit_cursors','transit_class_steps','first_carriage')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            following=node.prepare_exchange(peer)
            self.assertTrue({mesh.digest(t['packet']) for t in following['body']['transits']}-set(ids))
            self.assertTrue(set(ids)<=set(node.state['messages']))
            self.assertFalse(set(ids)&set(node.receipts()))

    def test_retry_still_authenticates_and_obeys_suppression(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            first=node.prepare_exchange(peer);ids=(ident,)
            replay=node.exchange(peer,{mesh.digest(t) for t in first['body']['transits']},ids)
            self.assertEqual(replay['body']['transits'],[])
            original=copy.deepcopy(node.state['messages'][ident]);before=node.path.read_bytes()
            node.state['messages'][ident]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(node.path.read_bytes(),before)
            node.state['messages'][ident]=original
            for invalid in ([ident],(ident,ident),('x',),tuple(str(i)*64 for i in range(5))):
                with self.assertRaises(ValueError):node.exchange(peer,retry_packet_ids=invalid)

    def test_retry_hint_is_bounded_scoped_and_forgettable(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            domain=node.carriage_position_domain();ids=('1'*64,)
            mesh.remember_carriage_position((domain,peer,'failed-carriage'),ids)
            self.assertEqual(node.failed_carriage(peer),ids)
            with patch.object(mesh,'MAX_PACKET_BATCH',3):self.assertEqual(node.failed_carriage(peer),())
            node.forget_failed_carriage(peer)
            self.assertEqual(node.failed_carriage(peer),())
            with patch.object(mesh,'MAX_CARRIAGE_POSITIONS',2):
                for i in range(5):mesh.remember_carriage_position((domain,peer,'test',i),ids)
                self.assertLessEqual(len(mesh._carriage_positions),2)
                self.assertLessEqual(mesh._carriage_position_bytes,mesh.MAX_CARRIAGE_POSITION_BYTES)

    def test_previous_scheduler_identity_refuses_without_rewrite(self):
        path=self.f.root/'earth/identity.private.json'
        identity=json.loads(path.read_text());identity['transit_scheduler']='RLD-CONTACT-TRANSIT-SCHEDULER-V7'
        path.write_text(json.dumps(identity));before=path.read_bytes()
        with self.assertRaises(ValueError):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def routed_fixture(self, names, edges):
        root=self.f.root/'routed'
        ids={n:mesh.initialize(root/n,NETWORK,str(i+1)*64,n)['node_id'] for i,n in enumerate(names)}
        configs={n:{'format':mesh.VERSION,'state':str(root/n),'network':NETWORK,'contacts':[]} for n in names}
        for a,b in edges:
            for source,target in [(a,b),(b,a)]:
                configs[source]['contacts'].append({'peer':ids[target],
                    'inbox':str(root/'links'/(target+'-'+source)),'outbox':str(root/'links'/(source+'-'+target))})
        # Discovery alone: no packets have yet been created.
        for _ in range(5):
            for a,b in [(s,t) for edge in edges for s,t in [edge,edge[::-1]]]:
                with mesh.Node(configs[a]) as node:bundle=node.exchange(ids[b])
                with mesh.Node(configs[b]) as node:node.receive(bundle,ids[a])
        return ids,configs

    def authenticated_transits(self, count=1):
        self.f.rounds()
        with self.f.node('earth') as node:
            for _ in range(count):
                node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            transits=node.exchange(self.f.identities['proxima']['node_id'])['body']['transits']
        with mesh._verified_transits_lock:
            mesh._verified_transits.clear()
        return transits

    def completed_local(self, count=1):
        with self.f.node('earth') as node:
            ids=[node.enqueue(self.f.frame(),node.id) for _ in range(count)]
        return ids

    def test_archive_cold_streamed_bytes_are_exact_and_authentication_stays_required(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertEqual(node.archive_completed(),1)
            body=copy.deepcopy(node.state['archives'][ident]['body'])
        canonical=evidence.canonical
        def small_metadata(value):
            if (isinstance(value,dict) and
                    ((set(value)=={'format','network','node_id','frame'} and isinstance(value['frame'],str) and bool(value['frame']))
                     or (set(value)=={'format','network','node_id','packet_id','transit','receipt'}
                         and value['transit'] is not None and 'frame' in value['transit']['packet']['body']))):
                raise AssertionError('full archive frame canonical encoding repeated')
            return canonical(value)
        with self.f.node('earth') as node:
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            with patch.object(evidence,'canonical',side_effect=small_metadata):
                complete=node.archived(ident)
            encoded=canonical(complete)
            self.assertEqual((evidence.hashlib.sha256(encoded).hexdigest(),len(encoded)),
                             (body['expanded_sha256'],body['expanded_size_bytes']))
            for code in range(128):
                trial=copy.deepcopy(complete)
                trial['transit']['packet']['body']['frame']='AA'+chr(code)+'BB'
                raw=canonical(trial)
                self.assertEqual(mesh.frame_digest.archive_commitment(trial),
                                 (evidence.hashlib.sha256(raw).hexdigest(),len(raw)))
            for trial in ({},[],dict(complete,transit=None),
                          dict(complete,transit={'packet':{'body':{'frame':'雪\\"'}}}),
                          dict(complete,transit={'packet':{'body':{'frame':12}}})):
                raw=canonical(trial)
                self.assertEqual(mesh.frame_digest.archive_commitment(trial),
                                 (evidence.hashlib.sha256(raw).hexdigest(),len(raw)))
            archive=node.archive_root/(body['frame_object']['file_id']+'.json')
            original=archive.read_bytes();changed=bytearray(original);changed[-3]^=1;archive.write_bytes(changed)
            with self.assertRaisesRegex(ValueError,'frame bytes differ'):node.archived(ident)
            self.assertEqual(archive.read_bytes(),bytes(changed))
            archive.write_bytes(original)
            node.state['archives'][ident]['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):node.archived(ident)

    def test_completed_archive_reopens_exact_frame_and_keeps_scoped_receipt(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            original=node.state['messages'][ident]
            self.assertEqual(node.archive_completed(),1)
            self.assertNotIn(ident,node.state['messages'])
            self.assertEqual(node.transit(ident),original)
            self.assertEqual(node.summaries()[ident]['frame_id'],original['routing']['body']['frame_id'])
        with self.f.node('earth') as node:
            path=self.f.root/'restored-frame.json'
            node.export_received(ident,path)
            self.assertEqual(path.read_bytes(),self.f.frame())
            self.assertIn(ident,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_default_early_archive_keeps_pending_evidence_and_every_completed_payload(self):
        completed=self.completed_local(mesh.ARCHIVE_HIGH_WATER)
        with self.f.node('earth') as node:
            pending=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state['messages'])
            receipts=copy.deepcopy(node.receipts())
            moved=node.archive_completed()
            self.assertGreater(moved,0)
            self.assertLessEqual(moved,mesh.MAX_ARCHIVE_BATCH)
            self.assertIn(pending,node.state['messages'])
            self.assertNotIn(pending,node.state['archives'])
            self.assertNotIn(pending,node.receipts())
        with self.f.node('earth') as node:
            self.assertEqual(node.receipts(),receipts)
            for ident in completed+[pending]:
                self.assertEqual(node.transit(ident),original[ident])
            self.assertFalse(node.status()['payment_authorized'])

    def test_archive_failure_before_payload_custody_preserves_active_state(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'archive_write',side_effect=OSError('injected archive custody failure')):
                with self.assertRaisesRegex(OSError,'custody failure'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            self.assertIn(ident,node.state['messages'])
            self.assertEqual(node.state['archives'],{})

    def test_archive_index_failure_keeps_active_and_recovers_complete_orphan(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('injected archive index failure')):
                with self.assertRaisesRegex(OSError,'index failure'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            files=list(node.archive_root.glob('*.json'))
            self.assertEqual(len(files),2);raw={p:p.read_bytes() for p in files}
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertIn(ident,node.state['messages'])
            self.assertEqual(node.archive_completed(),1)
            self.assertEqual({p:p.read_bytes() for p in files},raw)
            self.assertNotIn(ident,node.state['messages'])

    def test_archive_full_preserves_active_and_does_not_remove_existing_files(self):
        self.completed_local()
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            for field,limit in [('MAX_ARCHIVE_FILES',0),('MAX_ARCHIVE_BYTES',1)]:
                with patch.object(mesh,field,limit),self.assertRaisesRegex(ValueError,'capacity'):
                    node.archive_completed()
                self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual(list(node.archive_root.iterdir()),[])

    def test_archive_payload_corruption_is_refused_when_read_or_reacknowledged(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed();entry=node.state['archives'][ident]['body']
            path=node.archive_root/(entry['file_id']+'.json');raw=path.read_bytes()
            index=raw.index(b'"signature":"')+len(b'"signature":"')
            bad=raw[:index]+(b'0' if raw[index:index+1]!=b'0' else b'1')+raw[index+1:]
            self.assertEqual(len(raw),len(bad));path.write_bytes(bad)
            before=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'bytes differ'):node.transit(ident)
            self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual(path.read_bytes(),bad)

    def test_archive_signed_index_tamper_missing_file_and_symlink_refuse(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed();state=copy.deepcopy(node.state);path=node.path
            archive=node.archive_root/(state['archives'][ident]['body']['file_id']+'.json')
        bad=copy.deepcopy(state);bad['archives'][ident]['body']['frame_id']='f'*64
        mesh.atomic(path,bad);before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)
        mesh.atomic(path,state);raw=archive.read_bytes();archive.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):self.f.node('earth')
        external=self.f.root/'retained.json';external.write_bytes(raw);archive.symlink_to(external)
        with self.assertRaisesRegex(ValueError,'unsafe archive'):self.f.node('earth')
        self.assertEqual(external.read_bytes(),raw)

    def archived_index_fixture(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed()
            state=copy.deepcopy(node.state)
            archive=node.archive_root/(state['archives'][ident]['body']['file_id']+'.json')
            path=node.path
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        return ident,path,state,archive

    def test_exact_archive_index_witness_reuses_only_immutable_verified_metadata(self):
        _,path,_,_=self.archived_index_fixture();before=path.read_bytes()
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with mesh._verified_archive_index_lock:
                witness=mesh._verified_archive_index
                self.assertIsInstance(witness[1],bytes)
                self.assertTrue(all(isinstance(row,tuple) for row in witness[2]))
                mesh._verified_archive_index=None # Fresh process has no witness.
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,2)
        self.assertEqual(path.read_bytes(),before)

    def test_archive_index_witness_reauthenticates_changed_signature_and_domain_limits(self):
        ident,path,state,_=self.archived_index_fixture()
        with self.f.node('earth'):pass
        bad=copy.deepcopy(state);bad['archives'][ident]['signature']='0'*128
        mesh.atomic(path,bad);retained=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),retained)
        mesh.atomic(path,state)
        with self.f.node('earth'):pass
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with patch.object(mesh,'MAX_STATE',mesh.MAX_STATE-1):
                with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with patch.object(evidence,'KINDS',set()):
                with self.assertRaisesRegex(ValueError,'kind'):self.f.node('earth')
            self.assertEqual(checked.call_count,2)

    def test_warm_archive_index_still_checks_inventory_and_authenticates_changed_payload(self):
        ident,path,_,archive=self.archived_index_fixture()
        with self.f.node('earth'):pass
        before=path.read_bytes();raw=archive.read_bytes()
        index=raw.index(b'"signature":"')+len(b'"signature":"')
        bad=raw[:index]+(b'0' if raw[index:index+1]!=b'0' else b'1')+raw[index+1:]
        archive.write_bytes(bad)
        with self.f.node('earth') as node:
            with self.assertRaisesRegex(ValueError,'bytes differ'):node.archived(ident)
        self.assertEqual(archive.read_bytes(),bad)
        archive.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def test_archive_index_witness_budget_falls_back_and_scope_is_store_specific(self):
        _,path,_,_=self.archived_index_fixture();before=path.read_bytes()
        with self.f.node('proxima'):pass
        with self.f.node('earth'):pass
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with patch.object(mesh,'MAX_VERIFIED_ARCHIVE_INDEX_BYTES',1):
                for _ in range(2):
                    with self.f.node('earth'):pass
                self.assertIsNone(mesh._verified_archive_index)
            self.assertEqual(checked.call_count,2)
            with self.f.node('earth'):pass
            with self.f.node('proxima'):pass # One other store evicts the witness.
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,4)
        self.assertEqual(path.read_bytes(),before)

    def test_receipt_only_archive_returns_without_claiming_original_payload(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        with mesh.Node(cfg['return']) as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.receive(bundle,ids['destination']);node.archive_completed()
            self.assertNotIn(ident,node.summaries())
            with self.assertRaisesRegex(ValueError,'no frame'):node.transit(ident)
            bundle=node.exchange(ids['source'])
        with mesh.Node(cfg['source']) as node:
            node.receive(bundle,ids['return']);self.assertIn(ident,node.state['receipts'])
            self.assertFalse(node.status()['payment_authorized'])

    def test_receipt_only_archive_then_original_transit_retains_arrival_order_on_cold_open(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
            later=node.exchange(ids['return'])
            self.assertIn(ident,{mesh.digest(t['packet']) for t in later['body']['transits']})
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        with mesh.Node(cfg['return']) as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.receive(bundle,ids['destination']);node.archive_completed()
            with self.assertRaisesRegex(ValueError,'no frame'):node.transit(ident)
            node.receive(later,ids['source'])
            self.assertIn(ident,node.state['messages']);self.assertIn(ident,node.state['first_arrivals'])
            self.assertNotIn(ident,node.state['recent_transits']);node.validate_state()
            original=copy.deepcopy(node.state['messages'][ident])
        with mesh.Node(cfg['return']) as node:
            self.assertEqual(node.state['messages'][ident],original)
            self.assertIn(ident,node.state['first_arrivals']);self.assertIn(ident,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_archive_batches_are_bounded_and_unacknowledged_packets_remain_active(self):
        ids=self.completed_local(20)
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            queued=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.assertEqual(node.archive_completed(),mesh.MAX_ARCHIVE_BATCH)
            self.assertEqual(node.archive_completed(),4)
            self.assertIn(queued,node.state['messages'])
            self.assertNotIn(queued,node.state['archives'])
            self.assertEqual(set(node.state['archives']),set(ids))

    def test_warm_state_owner_check_avoids_unused_decode_but_cold_misses_fully_authenticate(self):
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            transit=copy.deepcopy(node.state['messages'][ident])
            original=mesh.transit_check(transit,NETWORK);durable=node.path.read_bytes()
            with patch.object(mesh.base64,'b64decode',side_effect=AssertionError('warm owner validation decoded unused frame')):
                node.validate_state()
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            full=mesh._transit_check
            with patch.object(mesh,'_transit_check',side_effect=full) as checked:
                packet,raw,visited=mesh.transit_check(transit,NETWORK,include_frame=False)
                self.assertEqual(checked.call_count,1)
            self.assertEqual(packet,original[0]);self.assertIsNone(raw);self.assertEqual(visited,original[2])
            self.assertEqual(mesh.transit_check(transit,NETWORK),original)
            bad=copy.deepcopy(transit);bad['packet']['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):mesh.transit_check(bad,NETWORK,include_frame=False)
            bad=copy.deepcopy(transit);body=dict(bad['packet']['body'],frame='invalid!')
            bad['packet']=mesh.sign(node.key,'packet',body)
            with self.assertRaises(ValueError):mesh.transit_check(bad,NETWORK,include_frame=False)
            self.assertEqual(node.path.read_bytes(),durable)

    def test_exact_transit_witness_cannot_authorize_changed_bytes_or_contact(self):
        transit=self.authenticated_transits()[0]
        recipient=self.f.identities['proxima']['node_id']
        sender=self.f.identities['earth']['node_id']
        validator=mesh._transit_check
        with patch.object(mesh,'_transit_check',wraps=validator) as validate:
            expected=mesh.transit_check(transit,NETWORK,recipient,sender)
            expected[2].clear()
            repeated=mesh.transit_check(copy.deepcopy(transit),NETWORK,recipient,sender)
            self.assertEqual(repeated[2],[sender,recipient])
            self.assertEqual(validate.call_count,1)
            for changed in ['packet','routing','hops']:
                candidate=copy.deepcopy(transit)
                signed=candidate[changed][0] if changed=='hops' else candidate[changed]
                signed['signature']='0'*128
                with self.assertRaises(ValueError):
                    mesh.transit_check(candidate,NETWORK,recipient,sender)
            for network,peer,previous in [('b'*64,recipient,sender),
                    (NETWORK,self.f.identities['andromeda']['node_id'],sender),
                    (NETWORK,recipient,self.f.identities['andromeda']['node_id'])]:
                with self.assertRaises(ValueError):
                    mesh.transit_check(transit,network,peer,previous)
            self.assertEqual(validate.call_count,7)

    def test_receipt_matching_revalidates_changed_packet_before_using_its_frame_binding(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node:
            transit=copy.deepcopy(node.state['messages'][ident]);receipt=copy.deepcopy(node.state['receipts'][ident])
            mesh.receipt_matches(receipt,transit)
            bad=copy.deepcopy(transit);bad['packet']['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):mesh.receipt_matches(receipt,bad)
            bad=copy.deepcopy(transit);bad['routing']['body']['frame_id']='f'*64
            with self.assertRaisesRegex(ValueError,'signature'):mesh.receipt_matches(receipt,bad)
            with patch.object(evidence,'MAX_FRAME',1),self.assertRaisesRegex(ValueError,'bound'):
                mesh.receipt_matches(receipt,transit)
            self.assertEqual(node.state['messages'][ident],transit)
            self.assertFalse(node.status()['payment_authorized'])

    def test_cold_state_refuses_validly_signed_receipt_for_a_different_frame_binding(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node:
            state=copy.deepcopy(node.state)
            receipt=state['receipts'][ident]
            route=mesh.sign(node.key,'receipt-route',{
                **receipt['body']['routing']['body'],'frame_id':'f'*64})
            altered=mesh.sign(node.key,'receipt',{
                **receipt['body'],'routing':route,'frame_id':'f'*64})
            self.assertEqual(mesh.receipt_check(altered,NETWORK),ident)
            state['receipts'][ident]=altered
            path=node.path
        retained=evidence.canonical(mesh.pack_state_storage(state));path.write_bytes(retained)
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.assertRaisesRegex(ValueError,'wrong destination receipt'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),retained)

    def test_witness_limits_revalidate_and_eviction_preserves_archive(self):
        transits=self.authenticated_transits(3)
        state_path=self.f.root/'earth'/'mesh-state.json'
        before=state_path.read_bytes()
        validator=mesh._transit_check
        with patch.object(mesh,'MAX_VERIFIED_TRANSITS',2),patch.object(mesh,'_transit_check',wraps=validator) as validate:
            for transit in transits:mesh.transit_check(transit,NETWORK)
            self.assertEqual(len(mesh._verified_transits),2)
            mesh.transit_check(transits[0],NETWORK)
            self.assertEqual(validate.call_count,4)
            with patch.object(mesh,'MAX_HOPS',1):
                with self.assertRaisesRegex(ValueError,'bound'):
                    mesh.transit_check(transits[0],NETWORK)
            with patch.object(evidence,'MAX_FRAME',1):
                with self.assertRaisesRegex(ValueError,'bound'):
                    mesh.transit_check(transits[0],NETWORK)
            with patch.object(mesh,'MAX_VERIFIED_TRANSITS',0):
                mesh.transit_check(transits[0],NETWORK)
                mesh.transit_check(transits[0],NETWORK)
                self.assertEqual(len(mesh._verified_transits),0)
            self.assertEqual(validate.call_count,8)
        self.assertEqual(state_path.read_bytes(),before)

    def test_warm_witness_does_not_hide_retained_archive_tampering(self):
        transit=self.authenticated_transits()[0]
        mesh.transit_check(transit,NETWORK)
        path=self.f.root/'earth'/'mesh-state.json'
        state=mesh.load(path,mesh.MAX_STATE)
        ident=mesh.digest(transit['packet'])
        # The source's zero-hop copy remains separately validated. Warm that
        # precise namespace before changing its retained source certificate.
        mesh.transit_check(state['messages'][ident],NETWORK)
        state['messages'][ident]['routing']['signature']='0'*128
        mesh.atomic(path,state)
        before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def test_receipt_returns_over_a_carrier_without_the_forward_packet(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        self.assertEqual(bundle['body']['transits'],[])
        with mesh.Node(cfg['return']) as node:
            node.receive(bundle,ids['destination'])
            self.assertNotIn(ident,node.state['messages'])
            self.assertIn(ident,node.state['receipts'])
            bundle=node.exchange(ids['source'])
        with mesh.Node(cfg['source']) as node:
            node.receive(bundle,ids['return'])
            self.assertIn(ident,node.state['receipts'])
            self.assertIn(ident,node.state['messages'])
            self.assertFalse(node.status()['payment_authorized'])

    def test_unrelated_local_receipts_do_not_flood_other_regions(self):
        ids,cfg=self.routed_fixture(['local','local-destination','remote','remote-destination'],
            [('local','local-destination'),('local','remote'),('remote','remote-destination')])
        for source,target in [('local','local-destination'),('remote','remote-destination')]:
            with mesh.Node(cfg[source]) as node:
                ident=node.enqueue(self.f.frame(),ids[target]);bundle=node.exchange(ids[target])
            with mesh.Node(cfg[target]) as node:
                node.receive(bundle,ids[source]);bundle=node.exchange(ids[source])
            with mesh.Node(cfg[source]) as node:
                node.receive(bundle,ids[target]);self.assertIn(ident,node.state['receipts'])
        with mesh.Node(cfg['local']) as node:bundle=node.exchange(ids['remote'])
        self.assertEqual(bundle['body']['receipts'],[])
        with mesh.Node(cfg['remote']) as node:
            before=set(node.state['receipts']);node.receive(bundle,ids['local'])
            self.assertEqual(set(node.state['receipts']),before)

    def test_destination_cannot_forge_source_receipt_route_and_inventory_is_signed(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            bundle=node.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as node:
            node.receive(bundle,self.f.identities['earth']['node_id']);bundle=node.exchange(self.f.identities['andromeda']['node_id'])
        with self.f.node('andromeda') as node:
            node.receive(bundle,self.f.identities['proxima']['node_id'])
            receipt=node.state['receipts'][ident];base=node.exchange(self.f.identities['proxima']['node_id'])
            hostile=[]
            for field in ('node_id','packet_id','destination','frame_id'):
                altered=copy.deepcopy(receipt)
                altered['body']['routing']['body'][field]='f'*64
                altered=mesh.sign(node.key,'receipt',altered['body'])
                hostile.append(mesh.sign(node.key,'exchange',{**base['body'],'receipts':[altered]}))
            forged=copy.deepcopy(base)
            forged['body']['inventory']['body']['packet_ids']=['f'*64]
            hostile.append(mesh.sign(node.key,'exchange',forged['body']))
        with self.f.node('proxima') as node:
            before=node.path.read_bytes()
            for bundle in hostile:
                with self.assertRaises(ValueError):node.receive(bundle,self.f.identities['andromeda']['node_id'])
                self.assertEqual(node.path.read_bytes(),before)

    def test_v1_configuration_is_refused_without_rewriting_retained_state(self):
        path=self.f.root/'earth/mesh-state.json'
        with self.f.node('earth'):pass
        before=path.read_bytes();cfg=dict(self.f.configs['earth'],format='RLD-CONTACT-MESH-V1')
        with self.assertRaises(ValueError):mesh.Node(cfg)
        self.assertEqual(path.read_bytes(),before)

    def test_automatic_neighbor_exchange_discovers_three_regions_and_two_hop_route(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            destination = self.f.identities['andromeda']['node_id']
            self.assertEqual(len(node.state['adverts']), 3)
            self.assertEqual(len(node.status()['regions']), 3)
            self.assertEqual(node.route(destination), [self.f.identities[n]['node_id'] for n in self.f.names])
            self.assertNotIn(destination, node.contacts)

    def test_incremental_node_addition_supplies_an_alternate_route_after_preferred_relay_stops(self):
        root = self.f.root/'diamond'
        names = ['source', 'left', 'right', 'destination']
        identities = {name: mesh.initialize(root/name, NETWORK, str(i+1)*64, name)
            for i, name in enumerate(names)}
        configs = {name: {'format': mesh.VERSION, 'state': str(root/name),
            'network': NETWORK, 'contacts': []} for name in names}
        def connect(a, b):
            for source, target in [(a,b), (b,a)]:
                configs[source]['contacts'].append({'peer': identities[target]['node_id'],
                    'inbox': str(root/'links'/(target+'-'+source)),
                    'outbox': str(root/'links'/(source+'-'+target))})
        def rounds(active, count=6):
            for _ in range(count):
                for name in active:
                    with mesh.Node(configs[name]) as node:
                        self.assertFalse(node.tick()['errors'])
        connect('source', 'left')
        rounds(['source', 'left'])
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 2)
            self.assertIsNone(node.route(identities['destination']['node_id']))
        connect('left', 'destination')
        rounds(['source', 'left', 'destination'])
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 3)
            self.assertEqual(len(node.route(identities['destination']['node_id'])), 3)
        connect('source', 'right')
        connect('right', 'destination')
        rounds(names)
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 4)
            preferred = node.route(identities['destination']['node_id'])[1]
            ident = node.enqueue(self.f.frame(), identities['destination']['node_id'])
        stopped = next(name for name in ['left','right'] if identities[name]['node_id'] == preferred)
        rounds([name for name in names if name != stopped], 8)
        with mesh.Node(configs['destination']) as node:
            self.assertIn(ident, node.state['receipts'])
            self.assertEqual(len(node.state['messages'][ident]['hops']), 2)
            visited = mesh.transit_check(node.state['messages'][ident], NETWORK)[2]
            self.assertNotIn(preferred, visited)
        with mesh.Node(configs['source']) as node:
            self.assertIn(ident, node.state['receipts'])
            self.assertEqual(len(node.state['messages']), 1)

    def test_exact_multihop_delivery_return_receipt_and_restart(self):
        self.f.rounds()
        raw = self.f.frame()
        with self.f.node('earth') as node:
            ident = node.enqueue(raw, self.f.identities['andromeda']['node_id'])
        self.f.rounds(5)
        with self.f.node('andromeda') as node:
            target = self.f.root / 'received.frame.json'
            node.export_received(ident, target)
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(len(node.state['messages'][ident]['hops']), 2)
            self.assertFalse(node.status()['payment_authorized'])
        with self.f.node('earth') as node:
            self.assertEqual(node.status()['messages'][ident], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            self.assertIn(ident, node.state['messages'])

    def test_disconnected_relay_retains_then_delivers_without_global_timeout(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
        self.f.rounds(4, ['earth'])
        with self.f.node('earth') as node:
            self.assertEqual(node.status()['messages'][ident], 'QUEUED_WAITING_CONTACT_OR_ROUTE')
        self.f.rounds(4)
        with self.f.node('earth') as node:
            self.assertIn(ident, node.state['receipts'])

    def test_unknown_route_keeps_packet_without_inventing_connection(self):
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), 'b' * 64)
            self.assertIsNone(node.route('b' * 64))
            self.assertEqual(node.exchange(self.f.identities['proxima']['node_id'])['body']['transits'], [])
            self.assertIn(ident, node.state['messages'])

    def test_authenticated_malformed_advert_and_frame_raise_clean_rejections(self):
        with self.f.node('earth') as node:
            advert = node.state['adverts'][node.id]
            malformed = mesh.sign(node.key, 'advert', {**advert['body'], 'neighbors': [{}]})
            with self.assertRaisesRegex(ValueError, 'neighbor'):
                mesh.advert_check(malformed, NETWORK)
            for key, value in [('kind', {}), ('payload_b64', 42)]:
                bad = json.loads(self.f.frame())
                bad[key] = value
                with self.assertRaises(ValueError):
                    evidence.inspect_frame(evidence.canonical(bad))

    def test_message_duplicate_is_idempotent_and_sender_keeps_original(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            bundle = node.exchange(peer)
        with self.f.node('proxima') as node:
            node.receive(bundle, self.f.identities['earth']['node_id'])
            node.receive(bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(list(node.state['messages']), [ident])
        with self.f.node('earth') as node:
            self.assertIn(ident, node.state['messages'])

    def test_signed_tamper_wrong_network_and_wrong_contact_are_atomic_rejections(self):
        with self.f.node('earth') as sender:
            bundle = sender.exchange(self.f.identities['proxima']['node_id'])
            tampered = copy.deepcopy(bundle)
            tampered['body']['adverts'][0]['body']['label'] = 'forged'
            foreign = mesh.sign(sender.key, 'exchange', {**bundle['body'], 'network': 'f' * 64})
        with self.f.node('proxima') as receiver:
            before = receiver.path.read_bytes()
            for candidate, peer in [(tampered, self.f.identities['earth']['node_id']),
                                    (foreign, self.f.identities['earth']['node_id']),
                                    (bundle, self.f.identities['andromeda']['node_id'])]:
                with self.assertRaises(ValueError):
                    receiver.receive(candidate, peer)
                self.assertEqual(receiver.path.read_bytes(), before)

    def test_stale_advert_is_ignored_conflicting_same_revision_preserved(self):
        with self.f.node('earth') as sender:
            old = sender.state['adverts'][sender.id]
            newer = mesh.sign(sender.key, 'advert', {**old['body'], 'sequence': 2, 'label': 'updated'})
            conflict = mesh.sign(sender.key, 'advert', {**newer['body'], 'label': 'contradiction'})
            def bundle(advert):
                b = sender.exchange(self.f.identities['proxima']['node_id'])
                return mesh.sign(sender.key, 'exchange', {**b['body'], 'adverts': [advert]})
            new_bundle, old_bundle, conflict_bundle = bundle(newer), bundle(old), bundle(conflict)
        with self.f.node('proxima') as receiver:
            receiver.receive(new_bundle, self.f.identities['earth']['node_id'])
            receiver.receive(old_bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(receiver.state['adverts'][self.f.identities['earth']['node_id']], newer)
            before = receiver.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                receiver.receive(conflict_bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(receiver.path.read_bytes(), before)

    def test_hop_limit_prevents_over_budget_forwarding(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'], 1)
            self.assertEqual(node.exchange(self.f.identities['proxima']['node_id'])['body']['transits'], [])
            self.assertIn(ident, node.state['messages'])

    def test_hop_chain_cannot_be_rewritten_or_shortened_by_next_relay(self):
        self.f.rounds()
        with self.f.node('earth') as source:
            source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            bundle = source.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as relay:
            relay.receive(bundle, self.f.identities['earth']['node_id'])
            onward = relay.exchange(self.f.identities['andromeda']['node_id'])
            transit = copy.deepcopy(onward['body']['transits'][0])
            transit['hops'].pop(0)
            with self.assertRaisesRegex(ValueError, 'broken'):
                mesh.transit_check(transit, NETWORK, self.f.identities['andromeda']['node_id'], relay.id)
            transit = copy.deepcopy(onward['body']['transits'][0])
            transit['hops'][0]['body']['to'] = self.f.identities['andromeda']['node_id']
            with self.assertRaisesRegex(ValueError, 'signature'):
                mesh.transit_check(transit, NETWORK)

    def test_capacity_refusal_retains_original_and_does_not_consume_inbox(self):
        self.f.rounds()
        with self.f.node('earth') as source:
            ident = source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            with patch.object(mesh, 'MAX_MESSAGES', 1):
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            self.assertIn(ident, source.state['messages'])
            bundle = source.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as relay:
            path = self.f.root / 'links' / 'earth-proxima' / (mesh.digest(bundle) + '.json')
            evidence.write_new(path, evidence.canonical(bundle))
            with patch.object(mesh, 'MAX_MESSAGES', 0):
                self.assertTrue(relay.tick()['errors'])
            self.assertTrue(path.exists())
            self.assertEqual(relay.state['messages'], {})
            for field in ['MAX_SPOOL_FILES', 'MAX_SPOOL_BYTES']:
                with patch.object(mesh, field, 0):
                    self.assertTrue(relay.tick()['errors'])
                self.assertTrue(path.exists())
                self.assertEqual(relay.state['messages'], {})

    def test_fake_destination_receipt_cannot_mark_sender_delivered(self):
        self.f.rounds()
        with self.f.node('earth') as sender:
            ident = sender.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            routing = sender.state['messages'][ident]['routing']
        with self.f.node('proxima') as relay:
            fake = mesh.sign(relay.key, 'receipt', {'format': mesh.VERSION, 'network': NETWORK,
                'node_id': relay.id, 'packet_id': ident, 'frame_id': evidence.inspect_frame(self.f.frame())[0]['message_id'],
                'routing': routing,
                'outcome': 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'})
            body = relay.exchange(self.f.identities['earth']['node_id'])['body']
            bundle = mesh.sign(relay.key, 'exchange', {**body, 'receipts': [fake]})
        with self.f.node('earth') as sender:
            with self.assertRaisesRegex(ValueError, 'wrong destination receipt'):
                sender.receive(bundle, self.f.identities['proxima']['node_id'])
            self.assertNotIn(ident, sender.state['receipts'])

    def test_corrupt_state_symlink_and_duplicate_json_fail_closed(self):
        with self.f.node('earth') as node:
            path = node.path
        state = mesh.load(path, mesh.MAX_STATE)
        state['network'] = 'f' * 64
        path.write_bytes(evidence.canonical(mesh.pack_state_storage(state)))
        with self.assertRaisesRegex(ValueError, 'corrupt'):
            self.f.node('earth')
        linked = self.f.root / 'alias'
        linked.symlink_to(self.f.root / 'proxima', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            mesh.safe_dir(linked)
        path.write_bytes(b'{"format":1,"format":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            mesh.load(path, 8192)

    def test_opening_unchanged_archive_does_not_rewrite_and_still_authenticates_it(self):
        self.f.rounds()
        with self.f.node('earth') as node:path=node.path
        before=path.read_bytes()
        with patch.object(mesh,'atomic',side_effect=OSError('unexpected archive rewrite')):
            with self.f.node('earth') as node:self.assertEqual(node.path.read_bytes(),before)
        state=mesh.load(path, mesh.MAX_STATE)
        state['adverts'][self.f.identities['proxima']['node_id']]['body']['label']='forged'
        tampered=evidence.canonical(mesh.pack_state_storage(state));path.write_bytes(tampered)
        with self.assertRaisesRegex(ValueError,'signature'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),tampered)

    def test_exact_repeated_exchange_syncs_custody_and_sync_failure_preserves_evidence(self):
        self.f.rounds()
        peer=self.f.identities['proxima']['node_id']
        with self.f.node('proxima') as node:bundle=node.exchange(self.f.identities['earth']['node_id'])
        with self.f.node('earth') as node:
            node.receive(bundle,peer)
            before=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('unexpected archive rewrite')):
                node.receive(bundle,peer)
            self.assertEqual(node.path.read_bytes(),before)
            with patch.object(mesh.os,'fsync',side_effect=OSError('injected retained custody sync failure')):
                with self.assertRaisesRegex(OSError,'sync failure'):node.receive(bundle,peer)
            self.assertEqual(node.path.read_bytes(),before)

    def test_cyclic_advertisements_do_not_loop_or_refund(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            self.assertIsNone(node.route('f' * 64))
            self.assertIsNone(node.route(self.f.identities['andromeda']['node_id'], [self.f.identities['proxima']['node_id']]))
            self.assertFalse(node.status()['payment_authorized'])

    def test_serialized_batch_budget_and_rotation_do_not_starve_messages(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            for i in range(9):
                node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            expected = set(node.state['messages'])
            seen = set()
            peer = self.f.identities['proxima']['node_id']
            full = node.exchange(peer)
            first_size = len(evidence.canonical({**full['body'], 'transits': full['body']['transits'][:1]})) + 512
            with patch.object(mesh, 'MAX_BATCH', first_size + 16):
                for _ in range(9):
                    batch = node.prepare_exchange(peer)
                    self.assertLessEqual(len(evidence.canonical(batch)), mesh.MAX_BATCH)
                    seen.update(mesh.digest(t['packet']) for t in batch['body']['transits'])
            self.assertEqual(seen, expected)

    def test_state_byte_limit_does_not_replace_existing_durable_state(self):
        with self.f.node('earth') as node:
            before = node.path.read_bytes()
            with patch.object(mesh, 'MAX_STATE', len(before)):
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            self.assertEqual(node.path.read_bytes(), before)


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
                    node.transit_groups(self.f.identities['proxima']['node_id'])
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
            # Neither failed authentication nor failed durable publication may
            # advance a current-copy position or alter retained signed bytes.
            cursor_key=(domain,peer,'native-current-copy',mesh.digest(context),True,frame)
            before_cursor=mesh.carriage_position(cursor_key)
            self.assertIn(before_cursor,(competitor,target))
            pressure();state=copy.deepcopy(node.state);durable=node.path.read_bytes()
            bad=node.first_carriage_plan(peer)['pending'][0]
            node.state['messages'][bad]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
            self.assertEqual(mesh.carriage_position(cursor_key),before_cursor)
            with patch.object(mesh,'atomic',side_effect=OSError('same-frame copy publication')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
            self.assertEqual(mesh.carriage_position(cursor_key),before_cursor)
            # Two ordinary source ticks carry both eligible current copies; no
            # controller-selected packet or manual publication grants delivery.
            for _ in range(2):
                pressure();self.assertFalse(node.tick()['errors'])
            paths=list((self.f.root/'links/earth-proxima').glob('*.json'))
            ordinary=[mesh.load(path,mesh.MAX_BATCH) for path in paths]
            self.assertTrue(any(target in [mesh.digest(t['packet']) for t in bundle['body']['transits']] for bundle in ordinary))
        for _ in range(2):
            with self.f.node('proxima') as node:
                # Model the actual companion's exact current-frame hint at the
                # relay too; retain the original two ordinary ticks and cold proof.
                node.set_carriage_priority(mesh.digest(context),frames)
                self.assertFalse(node.tick()['errors'])
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


    def test_stable_current_frame_set_survives_ordinary_ring_interference(self):
        import regional_bft_node as bft
        from regional_bft_retention import Messages
        self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
        context=dict(currency=NETWORK,region='9'*64,epoch=0,previous='0'*64,parent_height=14,parent_block='2'*64,parent_state='3'*64)
        keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
        messages=Messages();raws=[]
        for n,phase in ((4,'Prepare'),(5,'Commit'),(6,'Commit')):
            key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32);public=keys[n-4]
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps([context,0,'5'*64,phase,public],separators=(',',':'),ensure_ascii=False).encode()
            signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
            envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],evidence=dict(snapshots=[]),body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase=phase,approval=dict(key=public,signature=signature)))))
            messages=messages.append(mesh.digest(envelope['body']),envelope,None,True);payload=evidence.canonical(envelope)
            raws.append(evidence.make_frame('regional-bft',context['region'],context['region'],evidence.hashlib.sha256(payload).hexdigest(),payload))
        frames=bft.commit_carriage_frames(messages,context,keys,NETWORK,context['region']);self.assertEqual(len(frames),3)
        with self.f.node('earth') as node:
            baseline=[node.enqueue(self.f.frame(),destination) for _ in range(32)]
            node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
            current=[node.enqueue(raw,destination) for raw in raws];target=current[-1]
            originals={i:copy.deepcopy(node.state['messages'][i]) for i in current};domain=node.carriage_position_domain()
            bucket=lambda ident:(node.state['messages'][ident]['packet']['body']['destination'],node.state['messages'][ident]['routing']['body']['frame_id'])
            buckets=sorted(set(bucket(i) for i in node.state['recent_transits']))
            def pressure(ident):
                previous=buckets[(buckets.index(bucket(ident))-1)%len(buckets)]
                mesh.remember_carriage_position((domain,peer,'recent_transit_cursors','ring'),previous)
                node.state['transit_class_steps'][peer]=4;node.save();node.set_carriage_priority(mesh.digest(context),frames)
                groups=node.transit_groups(peer);self.assertEqual(next(i for i in groups[0] if i in current),ident)
            # Original real preparations classify all three as prepared, not custody.
            for ident in current:
                pressure(ident);bundle=node.prepare_exchange(peer)
                self.assertTrue(set(current)&{mesh.digest(t['packet']) for t in bundle['body']['transits']})
            self.assertTrue(set(current)<=set(node.state['first_carriage'][peer]['prepared']));self.assertFalse(node.receipts())
            seen=[]
            for turn in range(4):
                pressure(current[turn%2]);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
                bundle=node.prepare_exchange(peer);selected=tuple(mesh.digest(t['packet']) for t in bundle['body']['transits'])
                self.assertEqual(selected[:2],pair);self.assertEqual(len(selected),4)
                self.assertTrue(set(selected[2:]) & (set(node.state['messages'])-set(node.state['recent_transits'])))
                seen.extend(selected[2:]);self.assertEqual(node.state['messages'][target],originals[target]);self.assertFalse(node.receipts())
                positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')}
                replay=node.prepare_exchange(peer,retry_packet_ids=selected)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),selected)
                self.assertEqual({k:node.state[k] for k in positions},positions)
            self.assertIn(target,seen,'stable three-current-frame set repeatedly selects the two competitors under ordinary ring interference')
            frame_key=(domain,peer,'native-current-frame',mesh.digest(context),frames,True)
            before_cursor=mesh.carriage_position(frame_key);self.assertIn(before_cursor,frames)
            pressure(current[0]);state=copy.deepcopy(node.state);durable=node.path.read_bytes()
            bad=node.first_carriage_plan(peer)['pending'][0];node.state['messages'][bad]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
            self.assertEqual(mesh.carriage_position(frame_key),before_cursor)
            with patch.object(mesh,'atomic',side_effect=OSError('current frame-set publication')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
            self.assertEqual(mesh.carriage_position(frame_key),before_cursor)
            for _ in range(3):
                pressure(current[0]);self.assertFalse(node.tick()['errors'])
        for _ in range(3):
            with self.f.node('proxima') as node:self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target]
            mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target)
            self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raws[-1]);self.assertEqual(transit['packet'],originals[target]['packet']);self.assertEqual(transit['routing'],originals[target]['routing']);self.assertEqual(len(transit['hops']),2)


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
            for _ in range(40):node.enqueue(self.f.frame(),destination)
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

    def test_newest_current_pair_keeps_forwarded_prepare_ahead_of_local(self):
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
            positions={k:copy.deepcopy(node.state[k]) for k in ('first_carriage','recent_transit_cursors','history_transit_cursors','transit_class_steps')};full=node.prepare_exchange(peer,retry_packet_ids=selected);self.assertEqual(tuple(mesh.digest(t['packet']) for t in full['body']['transits']),selected);self.assertEqual({k:node.state[k] for k in positions},positions)
            # Oldest pair keeps its actual prior local/failed-frame order.
            pressure(4);old_pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);old=node.prepare_exchange(peer);old_ids=tuple(mesh.digest(t['packet']) for t in old['body']['transits']);self.assertEqual(old_ids[:2],old_pair);self.assertIn(local[0],old_ids[2:]);self.assertNotIn(target,old_ids[2:])
            for _ in range(3):pressure(0);self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            tr=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(tr,NETWORK,peer,relay);mesh.receipt_matches(receipt,tr);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(tr['packet'],NETWORK)[1],raws[-1]);self.assertEqual(tr['packet'],original['packet']);self.assertEqual(tr['routing'],original['routing']);self.assertEqual(len(tr['hops']),2)

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
            with self.f.node('proxima') as node:
                node.set_carriage_priority(mesh.digest(context),frames)
                self.assertFalse(node.tick()['errors'])
        with self.f.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.f.node('andromeda') as node:
            transit=node.state['messages'][target];receipt=node.receipts()[target];mesh.transit_check(transit,NETWORK,destination,peer);mesh.receipt_matches(receipt,transit);self.assertEqual(mesh.receipt_check(receipt,NETWORK),target);self.assertEqual(mesh.packet_check(transit['packet'],NETWORK)[1],raw);self.assertEqual(transit['packet'],originals[target]['packet']);self.assertEqual(transit['routing'],originals[target]['routing']);self.assertEqual(len(transit['hops']),2)


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

if __name__ == '__main__':
    unittest.main()
