"""Bounded current/history carriage; no Native, Runtime startup or custody."""
import copy
import unittest

from regional_bft_node import carriage_batch


class Messages:
    def __init__(self, bodies):
        self.rows = bodies

    def bodies(self):
        for ident, body in self.rows.items():
            yield ident, body, None, True


def proposal(height):
    return {'Signed': {'Proposal': {'snapshot': {'statement': {'height': height}}}}}


def vote(height):
    return {'Signed': {'Vote': {'context': {'parent_height': height}}}}


class CarriageBatchTests(unittest.TestCase):
    def select(self, bodies, cursor=0):
        messages = Messages(bodies)
        pending = [(ident + '-complete-bytes', ident, 'peer') for ident in bodies]
        before = copy.deepcopy((bodies, pending))
        result = carriage_batch(messages, pending, 13, cursor)
        self.assertEqual((bodies, pending), before)
        self.assertLessEqual(len(result), 4)
        self.assertEqual(len(result), len(set(result)))
        self.assertTrue(all(pair in pending for pair in result))
        return result

    def test_current_proposal_gets_slots_ahead_of_unpublished_history(self):
        bodies = {str(i): vote(i) for i in range(12)}
        bodies.update({'current1': proposal(14), 'current2': vote(13), 'current3': vote(13)})
        selected = self.select(bodies, 32)
        self.assertEqual(sum(pair[1].startswith('current') for pair in selected), 2)
        self.assertEqual(sum(not pair[1].startswith('current') for pair in selected), 2)

    def test_both_stable_classes_rotate_without_even_length_stride_starvation(self):
        bodies = {f'old{i}': vote(1) for i in range(10)}
        bodies.update({f'new{i}': vote(13) for i in range(8)})
        selected = set()
        for n in range(10):
            batch = self.select(bodies, 4 * n)
            self.assertEqual(sum(pair[1].startswith('new') for pair in batch), 2)
            selected.update(pair[1] for pair in batch)
        self.assertEqual(selected, set(bodies))

    def test_short_class_donates_capacity_and_three_recipients_fit(self):
        bodies = {'new': proposal(14), **{f'old{i}': vote(1) for i in range(8)}}
        self.assertEqual(len(self.select(bodies)), 4)
        messages = Messages({'new': proposal(14)})
        pending = [('exact-complete-envelope', 'new', peer) for peer in ('a', 'b', 'c')]
        self.assertEqual(carriage_batch(messages, pending, 13, 32), pending[2:] + pending[:2])

    def test_future_wrong_parent_and_historical_proposals_use_history(self):
        bodies = {'new': vote(13), 'future': proposal(15), 'old': proposal(13), 'other': vote(12)}
        self.assertEqual(len(self.select(bodies)), 4)
        self.assertEqual(carriage_batch(Messages({}), [], 13, 0), [])

    def test_epoch_signed_is_current_and_historical_finality_keeps_history_slots(self):
        bodies = {'epoch': {'EpochSigned': {'message': {'Timeout': {'context': {'parent_height': 13}}}}},
                  'vote': vote(13),
                  'final': {'Finalized': {'statement': {'height': 12}}},
                  **{f'old{i}': vote(1) for i in range(8)}}
        selected = self.select(bodies)
        self.assertEqual([pair[1] for pair in selected[:2]], ['epoch', 'vote'])
        self.assertIn('final', [pair[1] for pair in selected[2:]])

    def test_latest_complete_finality_reaches_three_peers_without_history_starvation(self):
        bodies = {f'old{i}': vote(1) for i in range(40)}
        bodies['final'] = {'Finalized': {'statement': {'height': 13}}}
        messages = Messages(bodies)
        pending = [(ident + '-complete-bytes', ident, peer)
                   for ident in bodies for peer in ('a', 'b', 'c')]
        before = copy.deepcopy((bodies, pending))
        delivered = set()
        for cursor in (32, 36):
            batch = carriage_batch(messages, pending, 13, cursor)
            self.assertEqual(len(batch), 4)
            self.assertEqual(sum(pair[1] == 'final' for pair in batch), 2)
            self.assertEqual(sum(pair[1] != 'final' for pair in batch), 2)
            delivered.update(pair[2] for pair in batch if pair[1] == 'final')
        self.assertEqual(delivered, {'a', 'b', 'c'})
        self.assertEqual((bodies, pending), before)

    def test_current_finality_and_votes_both_rotate_within_original_current_slots(self):
        bodies = {f'vote{i}': vote(13) for i in range(8)}
        bodies['final'] = {'Finalized': {'statement': {'height': 13}}}
        bodies.update({f'old{i}': vote(1) for i in range(10)})
        selected = set()
        for n in range(10):
            batch = self.select(bodies, 4 * n)
            self.assertEqual(sum(pair[1].startswith('old') for pair in batch), 2)
            selected.update(pair[1] for pair in batch)
        self.assertEqual(selected, set(bodies))

    def test_future_finality_stays_in_history_and_only_exact_observed_height_is_current(self):
        bodies = {'current': {'Finalized': {'statement': {'height': 13}}},
                  'future': {'Finalized': {'statement': {'height': 14}}},
                  'past': {'Finalized': {'statement': {'height': 12}}},
                  **{f'old{i}': vote(1) for i in range(8)}}
        selected = self.select(bodies)
        self.assertEqual(selected[0][1], 'current')
        self.assertNotIn('current', [pair[1] for pair in selected[1:]])

    def test_history_only_still_uses_all_four_slots_and_rotates(self):
        bodies = {f'old{i}': vote(1) for i in range(8)}
        self.assertEqual([pair[1] for pair in self.select(bodies, 4)], ['old1', 'old2', 'old3', 'old4'])

    def test_capacity_is_bounded_at_full_message_and_recipient_population(self):
        bodies = {str(i): vote(13 if i % 2 else 1) for i in range(512)}
        messages = Messages(bodies)
        pending = [(ident, ident, peer) for ident in bodies for peer in range(32)]
        batch = carriage_batch(messages, pending, 13, 2 ** 63 - 4)
        self.assertEqual(len(batch), 4)
        self.assertEqual(sum(int(pair[1]) % 2 for pair in batch), 2)


if __name__ == '__main__':
    unittest.main()
