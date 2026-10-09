"""Signed no-value spare ordering; empty proofs grant no Native authority."""
import copy
from contextlib import contextmanager
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_bft_retention import Messages
from test_interstellar_mesh import signed_ground_import_parent_proposal
import test_regional_bft_timeout_hint as timeout_fixture


class OrderedCarriageTests(unittest.TestCase):
    @contextmanager
    def retained_directory(self, prefix):
        parent = Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                      str(Path(__file__).resolve().parents[1] / 'tmp'))).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        # Retain fresh no-value fixtures, including failed observations.
        yield tempfile.mkdtemp(prefix=prefix, dir=parent)

    def signed_frames(self):
        signer = timeout_fixture.TimeoutCarriageTests()
        signer.setUp()
        context, base = signed_ground_import_parent_proposal(
            signer.context, signer.private[signer.keys[1]])
        signer.context, signer.base = context, base
        proposal = signer.proposal(round_number=4)
        bodies = [{'Signed': {'Timeout': dict(context=context, round=n, high=None,
            approval=signer.sign(key, 'bft-timeout-v1', [context, n, None, key]))}}
            for n in (3, 4) for key in signer.keys[:3]]
        bodies.append({'Signed': {'Proposal': proposal}})
        messages, raws = Messages(), []
        for body in bodies:
            envelope = dict(format=bft.ORIGIN_NETWORK, currency=context['currency'],
                            region=context['region'], evidence={'snapshots': []},
                            origins=[], body=body)
            ident = mesh.digest(body)
            messages = messages.append(ident, envelope, None, True)
            raws.append(wire.make_frame('regional-bft', context['region'], context['region'],
                        messages.content(ident), messages.payload(ident)))
        frames = bft.commit_carriage_frames(messages, context, signer.keys,
                    context['currency'], context['region'], 4, import_proposals=True)
        return context, signer.keys, messages, raws, frames

    def test_origin_keeps_proposal_first_and_legacy_order_and_capacity(self):
        context, keys, messages, raws, frames = self.signed_frames()
        self.assertEqual(frames[0], wire.inspect_frame(raws[-1])[0]['message_id'])
        before = {i: messages.payload(i) for i in messages}
        legacy = bft.commit_carriage_frames(messages, context, keys,
                    context['currency'], context['region'], 4)
        self.assertEqual(legacy, tuple(sorted(set(legacy))))
        with patch.object(bft, 'MAX_BROADCAST_HINT_BYTES', 1):
            self.assertEqual(bft.commit_carriage_frames(messages, context, keys,
                context['currency'], context['region'], 4, import_proposals=True), ())
        self.assertEqual({i: messages.payload(i) for i in messages}, before)

    def fixture(self, root, network):
        root = root.resolve()
        identities = [mesh.initialize(root / str(n), network, 'b'*64, str(n)) for n in range(4)]
        configs = [dict(format=mesh.VERSION, state=str(root / str(n)), network=network,
            contacts=[dict(peer=identities[j]['node_id'], inbox=str(root / f'{j}-{n}'),
                           outbox=str(root / f'{n}-{j}')) for j in range(4) if j != n])
            for n in range(4)]
        for _ in range(3):
            for config in configs:
                with mesh.Node(config) as node:self.assertEqual(node.tick()['errors'], [])
        return configs

    def test_three_direct_proposals_keep_first_offers_and_background_eventually_carries(self):
        context, _, _, raws, frames = self.signed_frames()
        with self.retained_directory('rld-ordered-spare-') as directory:
            configs = self.fixture(Path(directory), context['currency'])
            with mesh.Node(configs[0]) as node:
                peers = sorted(node.contacts)
                background = []
                carried = {peer: set() for peer in peers}
                for n in range(48):
                    raw = wire.make_frame('source-finality', '1'*64, '2'*64,
                        wire.hashlib.sha256(str(n).encode()).hexdigest(), b'{"no_value":true}')
                    background.append(node.enqueue(raw, peers[n % 3]))
                for _ in range(2):
                    for peer in peers:
                        carried[peer].update(mesh.digest(t['packet'])
                            for t in node.prepare_exchange(peer)['body']['transits'])
                targets = {}
                for raw in raws:
                    for peer in peers:
                        ident = node.enqueue(raw, peer)
                        if raw == raws[-1]:targets[peer] = ident
                before = {i: wire.canonical(t) for i, t in node.state['messages'].items()}
                node.set_carriage_priority(mesh.digest(context), frames, ordered_frames=True)
                # Count background first service from its own enqueue boundary,
                # including the actual preparations preceding proposal arrival.
                for turn in range(40):
                    for peer in peers:
                        first = node.first_carriage_plan(peer)['pending'][:2]
                        bundle = node.prepare_exchange(peer)
                        ids = [mesh.digest(t['packet']) for t in bundle['body']['transits']]
                        self.assertEqual(ids[:len(first)], first)
                        self.assertLessEqual(len(ids), mesh.MAX_PACKET_BATCH)
                        self.assertLessEqual(len(wire.canonical(bundle)), mesh.MAX_BATCH)
                        carried[peer].update(ids)
                        if turn == 0:self.assertIn(targets[peer], ids)
                for peer in peers:
                    missing = set(background) - carried[peer]
                    direct = [i for i in missing if node.state['messages'][i]['packet']['body']['destination'] == peer]
                    self.assertFalse(missing, (node.root, 'missing', len(missing), 'direct', len(direct)))
                    self.assertTrue(set(targets.values()) <= carried[peer])
                self.assertEqual({i: wire.canonical(t) for i, t in node.state['messages'].items()}, before)
                self.assertFalse(node.receipts())
                node.validate_state()

    def test_ordered_spare_bad_signature_and_failed_prepare_never_publish(self):
        context, _, _, raws, frames = self.signed_frames()
        with self.retained_directory('rld-ordered-refusal-') as directory:
            configs = self.fixture(Path(directory), context['currency'])
            with mesh.Node(configs[0]) as node:
                peer = sorted(node.contacts)[0]
                target = node.enqueue(raws[-1], peer)
                node.set_carriage_priority(mesh.digest(context), frames, ordered_frames=True)
                node.exchange(peer)
                before = node.path.read_bytes()
                state = copy.deepcopy(node.state)
                node.state['messages'][target]['packet']['signature'] = '0'*128
                with self.assertRaisesRegex(ValueError, 'signature'):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(), before)
                node.state = copy.deepcopy(state)
                with patch.object(mesh, 'atomic', side_effect=OSError('prepare refused')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state, state)
                self.assertEqual(node.path.read_bytes(), before)
                actual = node.prepare_exchange(peer)
                ids = tuple(mesh.digest(t['packet']) for t in actual['body']['transits'])
                metadata = copy.deepcopy(node.state)
                retry = node.prepare_exchange(peer, retry_packet_ids=ids)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']), ids)
                self.assertEqual(node.state, metadata)
                self.assertFalse(node.receipts())
                empty_key = node.set_carriage_priority(mesh.digest(context), (), ordered_frames=True)
                self.assertEqual(mesh.carriage_position(empty_key), (mesh.digest(context), ()))

    def test_full_ordinary_batches_alternate_spares_without_advancing_background_ring(self):
        context, _, _, raws, frames = self.signed_frames()
        with self.retained_directory('rld-ordered-turn-') as directory:
            configs = self.fixture(Path(directory), context['currency'])
            with mesh.Node(configs[0]) as node:
                peer = sorted(node.contacts)[0]
                for n in range(48):
                    node.enqueue(wire.make_frame('source-finality', '1'*64, '2'*64,
                        wire.hashlib.sha256(str(n).encode()).hexdigest(), b'{"no_value":true}'), peer)
                for raw in raws:node.enqueue(raw, peer)
                # Complete first service before observing four ordinary slots.
                for _ in range(40):node.prepare_exchange(peer)
                self.assertEqual(node.first_carriage_plan(peer)['pending'], [])
                node.set_carriage_priority(mesh.digest(context), frames, ordered_frames=True)
                domain = node.carriage_position_domain()
                turn_key = (domain, peer, 'native-ordered-spare-turn')
                ring = (domain, peer, 'recent_transit_cursors', 'ring')
                before = mesh.carriage_position(ring)
                priority = node.prepare_exchange(peer)
                self.assertEqual(len(priority['body']['transits']), mesh.MAX_PACKET_BATCH)
                self.assertIs(mesh.carriage_position(turn_key), True)
                self.assertEqual(mesh.carriage_position(ring), before)
                ordinary = node.prepare_exchange(peer)
                self.assertEqual(len(ordinary['body']['transits']), mesh.MAX_PACKET_BATCH)
                self.assertIs(mesh.carriage_position(turn_key), False)
                self.assertNotEqual(mesh.carriage_position(ring), before)
                ids = tuple(mesh.digest(t['packet']) for t in ordinary['body']['transits'])
                state = copy.deepcopy(node.state)
                with mesh._carriage_position_lock:
                    positions = copy.deepcopy(mesh._carriage_positions)
                retry = node.prepare_exchange(peer, retry_packet_ids=ids)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']), ids)
                self.assertEqual(node.state, state)
                with mesh._carriage_position_lock:self.assertEqual(mesh._carriage_positions, positions)


if __name__ == '__main__':unittest.main()
