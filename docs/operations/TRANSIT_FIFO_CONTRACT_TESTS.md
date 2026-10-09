# Transit FIFO contract tests

The ground scheduler offers at most two of four original transit slots in
durable arrival order. Ordinary recent/history slots retain their own positions;
retained history may be offered again before custody acknowledgment. Complete
atomic preparation removes every actually carried arrival from both waiting
lists. First-only service does not advance ordinary positions. A full four-item
retry leaves all admission and ordinary positions unchanged.

The eight methods below remain in
`tools/test_interstellar_transit_scheduler.py`. Their former sorted-rank
expectations are replaced by the owner-authorized FIFO/history contract. The
input scenarios and compatible safety requirements remain. Original source
versions and source-bound outcomes remain historical; a revised assertion never
retroactively qualifies them.

| Method suffix | Current assertion and retained obligation |
|---|---|
| `actual_completed_archive_removal_does_not_skip_next_waiting_batch` | Actual destination receipt archives exactly the carried four. The next first pair follows surviving arrival order; archived IDs are excluded from active carriage and their exact complete transit/receipt evidence survives cold open. |
| `failed_sends_spend_full_four_slots_on_distinct_pending_packets` | Each batch uses four distinct bounded slots. Its first pair follows unoffered arrivals, never repeating a first offer; this twenty-five-item pool is covered within thirteen preparations. Ordinary history may repeat. All source bytes remain and no receipt or payment authority appears. |
| `insertion_before_last_id_does_not_repeat_or_skip_original_successors` | A lower-hash insertion cannot skip older waiting arrivals. Every original and inserted ID remains and receives bounded coverage; ordinary historical repeats do not imply delivery. |
| `peer_isolation_public_exchange_readonly_and_global_cursor_not_active_authority` | Public exchange remains read-only. Only actual ordinary selections advance that peer's position; all other peer metadata remains exact. An unrelated global cursor cannot change the other peer's exchange or grant payment authority. |
| `single_frame_budget_covers_complete_pool_from_largest_retained_cursor` | A retained maximal ordinary cursor cannot override FIFO first offers. One-frame batches cover the complete arrival sequence once, preserve original evidence, and leave all ordinary/class positions unchanged. |
| `verified_hop_suppression_retains_evidence_and_only_advances_requested_peer` | Exactly the unsuppressed fifth packet remains eligible. Its first-only preparation does not advance ordinary positions; exact packets and other-peer metadata remain, with no custody receipt. |
| `wire_trim_keeps_one_position_step_and_eventually_covers_all_packets` | Every actual one-frame signed batch respects the byte bound and complete FIFO coverage. First-only preparation preserves ordinary/class positions, all original evidence and absence of custody. |
| `failed_spool_write_still_rotates_only_that_peer_and_keeps_all_packets` | An outgoing write failure preserves all packets after actual complete preparation. The requested peer retains the actual prepared ordinary cursor, rather than a predicted sorted rank; other peers remain exact, and cold open preserves the state without granting custody. |

`tools/test_interstellar_transit_contract_migration.py` injects a scheduling
fault into each method: swapped FIFO first offers, ordinary advancement after
first-only service, or another peer's cursor movement. Each revised obligation
must reject its corresponding fault. These negative witnesses test assertion
sensitivity; their deliberately altered bundles grant no authentication rights.

The separate current-contract suite retains continuous-arrival history coverage,
full retry, publication failure and cold metadata checks. Original private-format,
count/byte-capacity and atomic-publication refusal tests remain required. This
mapping does not replace those guards, full Native verification, fault profiles,
independent custody, broader liveness or physical-route qualification.
