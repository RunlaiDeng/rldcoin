"""Bounded composition examples and deliberately broken alternatives."""
import unittest
from dataclasses import replace
from itertools import combinations
from collections import deque
import value_composition_model as m


def coin(state, region, owner, amount=None):
    return next(c for c in state.coins if c.region == region and c.owner == owner
                and (amount is None or c.amount == amount))


def mixed_channel():
    s = m.issued_slice((10, 10, 12))
    s = m.export(s, 'earth', ((0, 0),), 'proxima', 'alice', 10, destination_fee=2)
    s = m.import_value(m.certify(s, 0), 0, 'proxima')
    s = m.advance(s, 'proxima', 1)
    s = m.export(s, 'earth', ((1, 0),), 'andromeda', 'alice', 10, destination_fee=1)
    s = m.import_value(m.certify(s, 1), 1, 'andromeda')
    s = m.advance(s, 'andromeda', 1)
    s = m.export(s, 'proxima', (coin(s, 'proxima', 'alice').ident,), 'andromeda', 'alice',
                 7, source_fee=1, destination_fee=1)
    s = m.import_value(m.certify(s, 2), 2, 'andromeda')
    s = m.advance(s, 'andromeda', 2)
    ids = tuple(c.ident for c in s.coins if c.region == 'andromeda' and c.owner == 'alice')
    s = m.open_channel(s, 'andromeda', ids, ('alice', 'bob'), 10,
                       change=(('alice', 4),), fee=1)
    ident = s.channels[0].ident
    s = m.reserve_fee(s, ident, coin(s, 'andromeda', 'alice', 4).ident)
    return s, ident


class Composition(unittest.TestCase):
    def refused_unchanged(self, state, operation, *args, **kwargs):
        original = state
        with self.assertRaises(m.Refusal):
            operation(state, *args, **kwargs)
        self.assertEqual(state, original)
        state.validate()

    def test_partition_fees_merge_split_and_all_authorizations(self):
        for a in range(1, 8):
            for b in range(1, 8):
                s = m.issued_slice((a, b))
                for fee in range(a+b):
                    remainder = a+b-fee
                    for first in range(1, remainder+1):
                        outputs = [('alice', first)]
                        if first < remainder:
                            outputs.append(('bob', remainder-first))
                        t = m.pay(s, 'earth', ((0, 0), (1, 0)), outputs, fee)
                        self.assertEqual(t.buckets(), (a+b, 0, 0))
                        self.assertTrue(all(c.lineage == (0, 1, 2) for c in t.coins))
        s = m.issued_slice((2, 3))
        self.refused_unchanged(s, m.pay, 'earth', ((0, 0), (0, 0)), [('alice', 4)])
        self.refused_unchanged(s, m.pay, 'earth', ((0, 0),), [('alice', 2)], owners_authenticated=False)
        self.refused_unchanged(s, m.pay, 'earth', ((0, 0),), [('alice', 3)])
        self.refused_unchanged(s, m.pay, 'proxima', ((0, 0),), [('alice', 2)])

    def test_checked_amounts_and_model_limits(self):
        for amount in (True, -1, 0, 1.0, '1', m.CAP+1, m.U128+1):
            with self.assertRaises(m.Refusal):
                m.issued_slice((amount,))
        with self.assertRaises(m.Refusal):
            m.issued_slice((m.CAP, 1))
        s = m.issued_slice((m.CAP,))
        self.assertEqual(m.pay(s, 'earth', ((0, 0),), [('bob', m.CAP)]).buckets(), (m.CAP, 0, 0))
        with self.assertRaises(m.Refusal):
            m.issued_slice(tuple(1 for _ in range(m.MAX_NODES+1)))
        s = m.issued_slice(tuple(1 for _ in range(m.MAX_FANOUT+1)))
        self.refused_unchanged(s, m.pay, 'earth', tuple(c.ident for c in s.coins), [('bob', len(s.coins))])

    def test_pending_finality_receipts_duplicates_and_refund_counterexample(self):
        s = m.issued_slice((10,))
        t = m.export(s, 'earth', ((0, 0),), 'proxima', 'bob', 8,
                     change=(('alice', 1),), source_fee=1, destination_fee=2)
        self.assertEqual(t.buckets(), (2, 0, 8))
        self.refused_unchanged(t, m.import_value, 0, 'proxima')
        finalized = m.certify(t, 0)
        self.refused_unchanged(finalized, m.import_value, 0, 'andromeda')
        self.refused_unchanged(finalized, m.import_value, 0, 'proxima', authentic_complete_closure=False)
        # Broken refund after silence adds a consumed source input alongside T.
        broken = replace(finalized, coins=finalized.coins + s.coins)
        with self.assertRaises(m.InvariantFailure):
            broken.validate()
        credited = m.import_value(finalized, 0, 'proxima')
        self.assertEqual(credited.buckets(), (10, 0, 0))
        self.assertEqual(m.import_value(credited, 0, 'proxima'), credited)
        self.refused_unchanged(credited, m.pay, 'proxima',
                               (coin(credited, 'proxima', 'bob').ident,), [('alice', 6)])
        # Broken duplicate credit uses the exact already-live output twice.
        with self.assertRaises(m.InvariantFailure):
            replace(credited, coins=credited.coins + (coin(credited, 'proxima', 'bob'),)).validate()

    def test_only_unfinalized_selected_tail_can_be_replayed(self):
        s = m.issued_slice((10,))
        t = m.export(s, 'earth', ((0, 0),), 'proxima', 'bob', 8,
                     change=(('alice', 1),), source_fee=1)
        undone = m.orphan_unfinalized_export_tail(t, 0)
        self.assertEqual(undone.coins, s.coins)
        self.assertEqual(undone.buckets(), (10, 0, 0))
        self.assertEqual(len(undone.nodes), len(t.nodes))
        self.assertTrue(undone.exports[0].orphaned)
        self.refused_unchanged(undone, m.certify, 0)
        self.refused_unchanged(m.certify(t, 0), m.orphan_unfinalized_export_tail, 0)
        child = m.pay(t, 'earth', (coin(t, 'earth', 'alice').ident,), [('bob', 1)])
        self.refused_unchanged(child, m.orphan_unfinalized_export_tail, 0)

    def test_region_cycle_keeps_causal_graph_and_new_debits(self):
        s = m.issued_slice((10,))
        for source, destination in (('earth', 'proxima'), ('proxima', 'andromeda'), ('andromeda', 'earth')):
            c = coin(s, source, 'alice')
            s = m.export(s, source, (c.ident,), destination, 'alice', 10)
            index = len(s.exports)-1
            s = m.import_value(m.certify(s, index), index, destination)
            s = m.advance(s, destination, s.height(destination)+1)
        self.assertEqual(s.buckets(), (10, 0, 0))
        self.assertEqual(len({e.asset.ident for e in s.exports}), 3)
        self.assertTrue(all(e.imported for e in s.exports))
        c = coin(s, 'earth', 'alice')
        self.assertEqual(len(c.lineage), len(s.nodes))

    def test_mixed_channel_reserve_challenge_deadline_and_settlement(self):
        s, ident = mixed_channel()
        self.assertEqual(s.buckets(), (18, 14, 0))
        self.assertEqual(m.review_channel_payment(s, ident, 1, (4, 6)), s)
        closed = m.close(s, ident, 0, (10, 0))
        deadline = closed.channels[0].deadline
        self.assertEqual(deadline, 2018)
        self.refused_unchanged(closed, m.settle, ident)
        at_deadline = m.advance(closed, 'andromeda', deadline)
        challenged = m.challenge(at_deadline, ident, 1, (4, 6), s.reserves[0].asset.ident, 1)
        self.assertEqual(challenged.buckets(), (22, 10, 0))
        self.refused_unchanged(challenged, m.settle, ident)
        settled = m.settle(m.advance(challenged, 'andromeda', deadline+1), ident)
        self.assertEqual(settled.buckets(), (32, 0, 0))
        self.assertFalse(settled.channels or settled.reserves)
        self.assertEqual(sorted(c.amount for c in settled.coins
                                if c.region == 'andromeda' and c.owner == 'bob'), [6])
        self.refused_unchanged(m.advance(closed, 'andromeda', deadline+1), m.challenge,
                               ident, 1, (4, 6), s.reserves[0].asset.ident, 1)
        self.refused_unchanged(closed, m.challenge, ident, 0, (10, 0), s.reserves[0].asset.ident, 1)
        self.refused_unchanged(closed, m.challenge, ident, 1, (4, 6), s.reserves[0].asset.ident, 5)

    def test_unused_reserve_returns_once_with_complete_union(self):
        s, ident = mixed_channel()
        s = m.close(s, ident, 1, (4, 6))
        t = m.settle(m.advance(s, 'andromeda', 2019), ident)
        self.assertEqual(t.buckets(), (32, 0, 0))
        self.assertEqual(sorted(c.amount for c in t.coins if c.region == 'andromeda' and c.owner == 'alice'), [4, 4])
        created = t.nodes[-1].outputs
        self.assertTrue(all(a.lineage == created[0].lineage for a in created))
        self.refused_unchanged(t, m.settle, ident)

    def test_incident_blocks_escrow_reserve_import_onward_but_not_unrelated(self):
        s, ident = mixed_channel()
        bad = m.notify_incident(s, 'proxima', 'auth-final-A', 'auth-final-B')
        self.assertEqual(bad.buckets(), s.buckets())
        self.assertEqual(m.exposure(bad)['E'], 14)
        self.refused_unchanged(bad, m.review_channel_payment, ident, 1, (4, 6))
        self.refused_unchanged(bad, m.close, ident, 1, (4, 6))
        closed = m.close(s, ident, 0, (10, 0))
        bad_close = m.notify_incident(closed, 'proxima', 'auth-final-A', 'auth-final-B')
        self.refused_unchanged(m.advance(bad_close, 'andromeda', 2019), m.settle, ident)
        self.refused_unchanged(bad_close, m.challenge, ident, 1, (4, 6), s.reserves[0].asset.ident, 1)
        clean = coin(bad, 'earth', 'alice', 12)
        paid = m.pay(bad, 'earth', (clean.ident,), [('bob', 11)], fee=1)
        self.assertEqual(paid.buckets(), bad.buckets())
        self.assertFalse(m.exposure(paid)['T'])
        self.assertEqual(m.notify_incident(bad, 'proxima', 'auth-final-B', 'auth-final-A'), bad)
        self.refused_unchanged(s, m.notify_incident, 'proxima', 'A', 'B', pair_authenticated=False)

    def test_incident_after_settlement_taints_every_fee_change_and_descendant(self):
        s, ident = mixed_channel()
        s = m.close(s, ident, 1, (4, 6))
        s = m.settle(m.advance(s, 'andromeda', 2019), ident)
        contaminated = coin(s, 'andromeda', 'bob', 6)
        s = m.export(s, 'andromeda', (contaminated.ident,), 'earth', 'bob', 4,
                     change=(('bob', 1),), source_fee=1, destination_fee=1)
        s = m.certify(s, len(s.exports)-1)
        bad = m.notify_incident(s, 'proxima', 'auth-final-A', 'auth-final-B')
        self.assertEqual(m.exposure(bad)['T'], 4)
        self.refused_unchanged(bad, m.import_value, len(bad.exports)-1, 'earth')
        for c in bad.coins:
            if bad.quarantined(c):
                self.refused_unchanged(bad, m.pay, c.region, (c.ident,), [('alice', c.amount)])
        self.assertEqual(bad.buckets(), s.buckets())

    def test_laundered_fee_or_ancestor_and_self_certified_ring_are_detected(self):
        s, _ = mixed_channel()
        node = s.nodes[-1]
        asset = node.outputs[-1]
        stripped = replace(asset, lineage=(asset.ident[0],))
        broken_node = replace(node, outputs=node.outputs[:-1] + (stripped,))
        broken = replace(s, nodes=s.nodes[:-1] + (broken_node,))
        with self.assertRaisesRegex(m.InvariantFailure, 'provenance union'):
            broken.validate()
        self_reference = replace(node, inputs=(node.outputs[0].ident,))
        with self.assertRaisesRegex(m.InvariantFailure, 'ancestor'):
            replace(s, nodes=s.nodes[:-1] + (self_reference,)).validate()
        missing_root = replace(node, inputs=((m.MAX_NODES, 0),))
        with self.assertRaisesRegex(m.InvariantFailure, 'ancestor'):
            replace(s, nodes=s.nodes[:-1] + (missing_root,)).validate()

    def test_payment_needs_reserve_and_local_incident_stops_destination_credit(self):
        s = m.issued_slice((3, 1))
        s = m.open_channel(s, 'earth', ((0, 0),), ('alice', 'bob'), 3)
        ident = s.channels[0].ident
        self.refused_unchanged(s, m.review_channel_payment, ident, 1, (1, 2))
        s = m.reserve_fee(s, ident, (1, 0))
        self.refused_unchanged(s, m.review_channel_payment, ident, 1, (1, 2), both_parties_authenticated=False)
        self.assertEqual(m.review_channel_payment(s, ident, 1, (1, 2)), s)
        t = m.export(m.issued_slice((3,)), 'earth', ((0, 0),), 'proxima', 'alice', 3)
        t = m.notify_incident(m.certify(t, 0), 'proxima', 'A', 'B')
        self.refused_unchanged(t, m.import_value, 0, 'proxima')

    def test_disputed_fee_lineage_taints_the_whole_carried_escrow(self):
        s = m.issued_slice((10, 5))
        s = m.export(s, 'earth', ((0, 0),), 'andromeda', 'alice', 10)
        s = m.import_value(m.certify(s, 0), 0, 'andromeda')
        s = m.export(s, 'earth', ((1, 0),), 'proxima', 'alice', 5)
        s = m.import_value(m.certify(s, 1), 1, 'proxima')
        s = m.advance(s, 'proxima', 1)
        s = m.export(s, 'proxima', (coin(s, 'proxima', 'alice').ident,), 'andromeda', 'alice', 5)
        s = m.import_value(m.certify(s, 2), 2, 'andromeda')
        s = m.advance(s, 'andromeda', 1)
        s = m.open_channel(s, 'andromeda', (coin(s, 'andromeda', 'alice', 10).ident,), ('alice', 'bob'), 10)
        ident = s.channels[0].ident
        s = m.reserve_fee(s, ident, coin(s, 'andromeda', 'alice', 5).ident)
        bad = m.notify_incident(s, 'proxima', 'A', 'B')
        self.assertEqual(m.exposure(bad), {'U': 0, 'E': 15, 'T': 0})
        self.refused_unchanged(bad, m.close, ident, 1, (4, 6))
        # Deliberately laundering just the new capacity object still violates
        # the graph's independently reconstructed complete input union.
        node = s.nodes[-1]
        clean_old = s.asset(node.inputs[0])
        stripped = replace(node.outputs[0], lineage=tuple(sorted((*clean_old.lineage, len(s.nodes)-1))))
        with self.assertRaisesRegex(m.InvariantFailure, 'provenance union'):
            replace(s, nodes=s.nodes[:-1] + (replace(node, outputs=(stripped, node.outputs[1])),)).validate()


def bounded_prefix_check(depth=4, max_states=100000):
    """Exhaustive linear extensions through depth, not unbounded proof/liveness."""
    initial = m.issued_slice((1, 2))
    seen = {initial}
    queue = deque([(initial, 0)])
    transitions = 0
    while queue:
        s, level = queue.popleft()
        s.validate()
        if level == depth:
            continue
        next_states = []
        def attempt(fn, *args, **kwargs):
            try:
                following = fn(s, *args, **kwargs)
                if following != s:
                    next_states.append(following)
            except m.Refusal:
                pass
        for c in s.coins:
            owner = 'bob' if c.owner == 'alice' else 'alice'
            attempt(m.pay, c.region, (c.ident,), [(owner, c.amount)])
            for destination in m.REGIONS:
                attempt(m.export, c.region, (c.ident,), destination, owner, c.amount)
            attempt(m.open_channel, c.region, (c.ident,), ('alice', 'bob'), c.amount)
            for ch in s.channels:
                attempt(m.reserve_fee, ch.ident, c.ident)
        for a, b in combinations(s.coins, 2):
            if a.region == b.region:
                attempt(m.pay, a.region, (a.ident, b.ident), [('alice', a.amount+b.amount)])
        for i, record in enumerate(s.exports):
            attempt(m.certify, i)
            attempt(m.import_value, i, record.destination)
            attempt(m.orphan_unfinalized_export_tail, i)
        for channel in s.channels:
            # W=1 is a search parameter; the real 2016 boundary has its own trace.
            attempt(m.close, channel.ident, 0, channel.split, window=1)
            attempt(m.settle, channel.ident)
        for region in m.REGIONS:
            if s.height(region) < 2:
                attempt(m.advance, region, s.height(region)+1)
            attempt(m.notify_incident, region, 'A', 'B')
        for following in next_states:
            transitions += 1
            following.validate()
            if following not in seen:
                m.require(len(seen) < max_states, 'bounded search state budget')
                seen.add(following)
                queue.append((following, level+1))
    return dict(depth=depth, reached_states=len(seen), transitions=transitions,
                exhaustive_prefix_complete=True, full_state_space_or_liveness_proved=False)


if __name__ == '__main__':
    unittest.main()
