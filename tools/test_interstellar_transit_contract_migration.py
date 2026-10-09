"""Negative witnesses for the eight migrated no-value carriage obligations.

Inject scheduling faults after ordinary preparation. No Native, sockets or value;
these witnesses prove assertion sensitivity, not transport authentication.
"""
import copy
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from test_interstellar_transit_scheduler import TransitSchedulerTests


class MigrationNegativeWitnessTests(unittest.TestCase):
    def test_each_migrated_case_detects_fifo_cursor_or_other_peer_fault(self):
        cases = {
            'actual_completed_archive_removal_does_not_skip_next_waiting_batch': 'fifo',
            'failed_sends_spend_full_four_slots_on_distinct_pending_packets': 'fifo',
            'insertion_before_last_id_does_not_repeat_or_skip_original_successors': 'fifo',
            'peer_isolation_public_exchange_readonly_and_global_cursor_not_active_authority': 'fifo',
            'single_frame_budget_covers_complete_pool_from_largest_retained_cursor': 'cursor',
            'verified_hop_suppression_retains_evidence_and_only_advances_requested_peer': 'cursor',
            'wire_trim_keeps_one_position_step_and_eventually_covers_all_packets': 'cursor',
            'failed_spool_write_still_rotates_only_that_peer_and_keeps_all_packets': 'peer',
        }
        real_prepare = mesh.Node.prepare_exchange
        for name, mutation in cases.items():
            with self.subTest(case=name, mutation=mutation):
                def broken(node, peer, *args, **kwargs):
                    value = real_prepare(node, peer, *args, **kwargs)
                    if mutation == 'fifo':
                        value = copy.deepcopy(value)
                        rows = value['body']['transits']
                        if len(rows) >= 2: rows[0], rows[1] = rows[1], rows[0]
                    elif mutation == 'cursor':
                        if value['body']['transits']:
                            node.state['transit_cursors'][peer] = mesh.digest(value['body']['transits'][0]['packet'])
                            node.save()
                    else:
                        other = next(p for p in node.state['transit_cursors'] if p != peer)
                        node.state['transit_cursors'][other] = mesh.digest(value['body']['transits'][0]['packet'])
                        node.save()
                    return value
                result = unittest.TestResult()
                with patch.object(mesh.Node, 'prepare_exchange', broken):
                    TransitSchedulerTests('test_' + name).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [])
                self.assertEqual(len(result.failures), 1,
                                 'migrated obligation did not reject injected ' + mutation)


if __name__ == '__main__': unittest.main()
