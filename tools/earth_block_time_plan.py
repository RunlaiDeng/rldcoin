#!/usr/bin/env python3
"""Exact parameter comparison only; never writes node configuration or contacts a chain."""
import argparse
import json

BASE_INTERVAL_MS = 600_000
BASE_COUNTS = {
    'reward_maturity': 100,
    'contest_window': 2016,
    'emission_era': 200_000,
    'retained_entries': 100_000,
}


def compare(interval_ms):
    if type(interval_ms) is not int or not 1 <= interval_ms <= 86_400_000:
        raise ValueError('interval_ms must be an integer from 1 to 86400000')
    parameters = {}
    for name, count in BASE_COUNTS.items():
        baseline_ms = count * BASE_INTERVAL_MS
        preserve_count = (baseline_ms + interval_ms - 1) // interval_ms
        parameters[name] = {
            'current_blocks_or_entries': count,
            'current_target_duration_ms': baseline_ms,
            'unchanged_count_target_duration_ms': count * interval_ms,
            'count_to_preserve_at_least_current_target_duration': preserve_count,
            'preserved_target_duration_ms': preserve_count * interval_ms,
        }
    return {
        'classification': 'parameter comparison; proposed interval is not deployed or qualified',
        'proposed_interval_ms': interval_ms,
        'baseline_interval_ms': BASE_INTERVAL_MS,
        'parameters': parameters,
        'production_changed': False,
        'production_interval_selected': False,
        'qualified_network_throughput': False,
        'consensus_millisecond_timestamps_implemented': False,
        'existing_channel_deadline_changed': False,
        'limitations': [
            'PoW interval is a target average, not a deadline or exact timer.',
            'Retention comparison assumes one retained entry per block; forks use extra entries.',
            'Preserving maturity or finality time does not prove equal attack cost or security.',
            'A height count chosen before an interval upgrade also needs transition-specific protection.',
            'Current integer-second headers cannot express a millisecond target without a new protocol.',
            'Cross-region evidence delivery and regional consensus timing are separate decisions.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interval-ms', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.interval_ms), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
