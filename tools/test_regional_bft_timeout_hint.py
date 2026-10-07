"""Fresh public ground signatures; transport hints grant no Native authority."""
import copy
import hashlib
import unittest
import tempfile

import interstellar_mesh as mesh
from regional_bft_node import current_empty_proposal_hint, commit_carriage_frames, NETWORK
from regional_bft_retention import Messages
from regional_bft_timeout_hint import CONTEXT_FIELDS, encoded, ordered_timeout
from test_interstellar_mesh import signed_ground_empty_proposal


class TimeoutCarriageTests(unittest.TestCase):
    def setUp(self):
        pairs = []
        for seed in range(41, 45):
            key = mesh.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
            public = key.public_key().public_bytes(mesh.Encoding.Raw, mesh.PublicFormat.Raw).hex()
            pairs.append((public, key))
        self.keys = tuple(sorted(p for p, _ in pairs))
        self.private = dict(pairs)
        context = dict(currency='a'*64, region='b'*64, epoch='c'*64, previous='d'*64,
                       parent_height=13, parent_block='e'*64, parent_state='f'*64)
        self.context, self.base = signed_ground_empty_proposal(context, self.private[self.keys[1]])
        self.context = {k: self.context[k] for k in CONTEXT_FIELDS}

    def sign(self, key, domain, value):
        raw = ('RLD-REGIONAL-FIXTURE-V1:' + domain + '\0').encode() + encoded(value)
        return dict(key=key, signature=self.private[key].sign(raw).hex())

    def high(self, round_number=0, value=None):
        if value is None:
            value = hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'
                                   + encoded(self.base['snapshot']['statement'])).hexdigest()
        votes = [dict(context=self.context, round=round_number, value=value, phase='Prepare',
                      approval=self.sign(key, 'bft-vote-v1',
                                         [self.context, round_number, value, 'Prepare', key]))
                 for key in self.keys[:3]]
        return dict(context=self.context, round=round_number, value=value, phase='Prepare', votes=votes)

    def proposal(self, round_number=1, high=None):
        votes = [dict(context=self.context, round=round_number-1, high=copy.deepcopy(high),
                      approval=self.sign(key, 'bft-timeout-v1',
                                         [self.context, round_number-1, high, key]))
                 for key in self.keys[:3]]
        timeout = dict(context=self.context, round=round_number-1, votes=votes)
        key = self.keys[(13+round_number)%4]
        snapshot = copy.deepcopy(self.base['snapshot'])
        return dict(round=round_number, snapshot=snapshot, timeout=timeout,
                    leader=self.sign(key, 'bft-proposal-v1', [round_number, snapshot, timeout, key]))

    def frames(self, proposal, context=None):
        body = {'Signed': {'Proposal': proposal}}
        return self.body_frames(body, context)

    def body_frames(self, body, context=None):
        envelope = dict(format=NETWORK, currency=self.context['currency'], region=self.context['region'],
                        evidence={'snapshots': []}, body=body)
        messages = Messages().append(mesh.digest(body), envelope, None, True)
        return commit_carriage_frames(messages, context or self.context, self.keys,
                                      self.context['currency'], self.context['region'])

    def single_timeout(self, high=None, round_number=0):
        key=self.keys[0]
        return dict(context=self.context,round=round_number,high=copy.deepcopy(high),
                    approval=self.sign(key,'bft-timeout-v1',[self.context,round_number,high,key]))

    def test_single_signed_timeout_gets_carriage_before_timeout_quorum_exists(self):
        for high in (None,self.high()):
            timeout=self.single_timeout(high=high)
            before=copy.deepcopy(timeout)
            self.assertEqual(len(self.body_frames({'Signed':{'Timeout':timeout}})),1)
            self.assertEqual(timeout,before)

    def test_single_timeout_wrong_context_signature_round_or_nested_high_is_no_hint(self):
        for mode in ('context','signature','round','membership','high-count','high-signature','high-phase'):
            high=self.high() if mode.startswith('high-') else None
            if mode=='high-count':high['votes'].pop()
            elif mode=='high-signature':high['votes'][0]['approval']['signature']='0'*128
            elif mode=='high-phase':high['phase']='Commit'
            timeout=self.single_timeout(high=high)
            if mode=='context':timeout['context']=dict(self.context,epoch='9'*64)
            elif mode=='signature':timeout['approval']['signature']='0'*128
            elif mode=='round':timeout['round']=True
            elif mode=='membership':timeout['approval']['key']='9'*64
            before=copy.deepcopy(timeout)
            self.assertEqual(self.body_frames({'Signed':{'Timeout':timeout}}),())
            self.assertEqual(timeout,before)

    def test_single_timeout_complete_frame_and_expansion_bounds_remain_exact(self):
        from unittest.mock import patch
        import regional_bft_node as bft
        timeout=self.single_timeout(high=self.high());body={'Signed':{'Timeout':timeout}}
        frames=self.body_frames(body)
        self.assertEqual(len(frames),1)
        with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',1):self.assertEqual(self.body_frames(body),())
        timeout['round']=32
        self.assertEqual(self.body_frames({'Signed':{'Timeout':timeout}}),())

    def test_single_vote_priority_cannot_reduce_certificate_quorum_or_change_signed_bytes(self):
        timeout=self.single_timeout(high=self.high())
        self.assertEqual(len(self.body_frames({'Signed':{'Timeout':timeout}})),1)
        for count in (1,2):
            certificate=self.proposal(high=self.high())['timeout']
            certificate['votes']=certificate['votes'][:count]
            with self.assertRaises(ValueError):ordered_timeout(certificate,self.context,self.keys,1)
        for high in (None,self.high()):
            certificate=self.proposal(high=high)['timeout']
            before=copy.deepcopy(certificate)
            ordered,_=ordered_timeout(certificate,self.context,self.keys,1)
            self.assertEqual(encoded(ordered),encoded(before))
            self.assertEqual(certificate,before)

    def test_real_round_zero_and_later_complete_timeout_signatures_get_one_frame(self):
        self.assertEqual(len(self.frames(self.base)), 1)
        for round_number in (1, 2, 31):
            proposal = self.proposal(round_number)
            before = copy.deepcopy(proposal)
            self.assertTrue(current_empty_proposal_hint(proposal, self.context, self.keys))
            self.assertEqual(len(self.frames(proposal)), 1)
            self.assertEqual(proposal, before)

    def test_high_prepare_requires_all_original_votes_and_exact_proposed_value(self):
        self.assertEqual(len(self.frames(self.proposal(high=self.high()))), 1)
        self.assertEqual(len(self.frames(self.proposal(high=self.high(value='1'*64)))), 0)
        bad = self.high();bad['votes'][0]['approval']['signature'] = '0'*128
        self.assertEqual(len(self.frames(self.proposal(high=bad))), 0)
        bad = self.high();bad['votes'][1] = copy.deepcopy(bad['votes'][0])
        self.assertEqual(len(self.frames(self.proposal(high=bad))), 0)

    def test_malformed_or_tampered_timeout_never_gets_priority(self):
        base = self.proposal()
        cases = []
        for field in ('currency', 'region', 'epoch', 'parent_block', 'parent_state', 'previous'):
            bad = copy.deepcopy(base);bad['timeout']['context'][field] = '9'*64;cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['votes'].pop();cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['votes'][1] = copy.deepcopy(bad['timeout']['votes'][0]);cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['votes'].reverse();cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['round'] = 1;cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['votes'][0]['round'] = 1;cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout']['votes'][0]['approval']['signature'] = '0'*128;cases.append(bad)
        bad = copy.deepcopy(base);bad['leader']['signature'] = '0'*128;cases.append(bad)
        bad = copy.deepcopy(base);bad['leader']['key'] = self.keys[0];cases.append(bad)
        bad = copy.deepcopy(base);bad['round'] = 32;cases.append(bad)
        bad = copy.deepcopy(base);bad['round'] = True;cases.append(bad)
        bad = copy.deepcopy(base);bad['timeout'] = None;cases.append(bad)
        bad = copy.deepcopy(self.base);bad['timeout'] = base['timeout'];cases.append(bad)
        for bad in cases:
            with self.subTest(case=cases.index(bad)):
                before = copy.deepcopy(bad)
                self.assertEqual(self.frames(bad), ())
                self.assertEqual(bad, before)

    def test_invalid_nested_high_shape_context_phase_round_or_signature_refuses(self):
        for mode in ('phase', 'round', 'context', 'signature', 'recursive', 'count', 'membership'):
            high = self.high()
            if mode == 'phase':high['phase'] = 'Commit'
            elif mode == 'round':high['round'] = 1
            elif mode == 'context':high['votes'][0]['context'] = dict(self.context, epoch='9'*64)
            elif mode == 'signature':high['votes'][0]['approval']['signature'] = '0'*128
            elif mode == 'recursive':high['votes'][0]['high'] = self.high()
            elif mode == 'count':high['votes'].pop()
            else:high['votes'][0]['approval']['key'] = '9'*64
            self.assertEqual(self.frames(self.proposal(high=high)), ())

    def test_later_timeout_proposal_ordinary_delivery_preserves_retry_and_pending_floor(self):
        self.ordinary_delivery({'Signed':{'Proposal':self.proposal(high=self.high())}})

    def test_single_timeout_ordinary_delivery_preserves_retry_pending_floor_and_cold_receipt(self):
        self.ordinary_delivery({'Signed':{'Timeout':self.single_timeout(high=self.high())}})

    def ordinary_delivery(self, body):
        from test_interstellar_mesh import Fixture
        import interstellar_transfer as wire
        with tempfile.TemporaryDirectory(prefix='rld-timeout-carriage-') as directory:
            fixture = Fixture(directory);fixture.rounds()
            peer = fixture.identities['proxima']['node_id']
            destination = fixture.identities['andromeda']['node_id']
            envelope = dict(format=NETWORK, currency=self.context['currency'],
                            region=self.context['region'], evidence={'snapshots': []}, body=body)
            messages = Messages().append(mesh.digest(body), envelope, None, True)
            frames = commit_carriage_frames(messages, self.context, self.keys,
                                            self.context['currency'], self.context['region'])
            self.assertEqual(len(frames), 1)
            payload = wire.canonical(envelope)
            raw = wire.make_frame('regional-bft', self.context['region'], self.context['region'],
                                  hashlib.sha256(payload).hexdigest(), payload)
            with fixture.node('earth') as node:
                baseline = [node.enqueue(fixture.frame(), destination) for _ in range(17)]
                for _ in range(9):
                    node.prepare_exchange(peer)
                    if set(baseline) <= set(node.state['first_carriage'][peer]['prepared']):break
                self.assertTrue(set(baseline) <= set(node.state['first_carriage'][peer]['prepared']))
                admitted = [node.enqueue(raw if i == 2 else fixture.frame(), destination)
                            for i in range(32)]
                target = admitted[2]
                node.state['first_carriage'][peer] = node.first_carriage_plan(peer)
                for _ in range(22):node.enqueue(fixture.frame(), destination)
                self.assertNotIn(target, node.state['recent_transits'])
                original = copy.deepcopy(node.state['messages'][target])
                node.set_carriage_priority(mesh.digest(self.context), frames)
                node.state['transit_class_steps'][peer] = 0;node.save()
                pair = tuple(node.first_carriage_plan(peer)['pending'][:2])
                self.assertNotIn(target, pair)
                prepared = node.prepare_exchange(peer)
                identifiers = tuple(mesh.digest(t['packet']) for t in prepared['body']['transits'])
                self.assertEqual(identifiers[:2], pair)
                self.assertEqual(len(identifiers), 4)
                self.assertIn(target, identifiers[2:])
                positions = {k: copy.deepcopy(node.state[k]) for k in
                             ('first_carriage', 'recent_transit_cursors',
                              'history_transit_cursors', 'transit_class_steps')}
                replay = node.prepare_exchange(peer, retry_packet_ids=identifiers)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']), identifiers)
                self.assertEqual({k: node.state[k] for k in positions}, positions)
                self.assertEqual(node.state['messages'][target], original)
                self.assertFalse(node.receipts())
                node.state['transit_class_steps'][peer] = 0;node.save()
                self.assertFalse(node.tick()['errors'])
            for _ in range(2):
                with fixture.node('proxima') as node:self.assertFalse(node.tick()['errors'])
            with fixture.node('andromeda') as node:self.assertFalse(node.tick()['errors'])
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            with fixture.node('andromeda') as node:
                transit = node.transit(target);receipt = node.receipts()[target]
                mesh.transit_check(transit, self.context['currency'], destination, peer)
                mesh.receipt_matches(receipt, transit)
                self.assertEqual(mesh.packet_check(transit['packet'], self.context['currency'])[1], raw)
                self.assertEqual(transit['packet'], original['packet'])
                self.assertEqual(transit['routing'], original['routing'])
                self.assertEqual(len(transit['hops']), 2)
                self.assertEqual(receipt['body']['outcome'], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')

    def test_context_key_order_and_quorum_bounds_refuse_without_authority(self):
        proposal = self.proposal()
        for keys in (self.keys[::-1], self.keys[:3], (self.keys[0],)*4):
            with self.assertRaises(ValueError):ordered_timeout(proposal['timeout'], self.context, keys, 1)
        changed = dict(self.context, parent_height=True)
        with self.assertRaises(ValueError):ordered_timeout(proposal['timeout'], changed, self.keys, 1)
        before = copy.deepcopy(proposal);ordered_timeout(proposal['timeout'], self.context, self.keys, 1)
        self.assertEqual(proposal, before)


if __name__ == '__main__':unittest.main()
