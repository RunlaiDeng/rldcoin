#!/usr/bin/env python3
"""Deterministic planning bounds; no network, payment, or consensus mutations.

One FIFO batch per direction, no departures during blackout, no competing traffic
beyond the supplied usable bandwidth, fixed frame size, stationary light delay.
All arrivals through the next contact must be included in the supplied rate.
Queue copies remain retained after transmission, as in interstellar_transfer.py.
"""
import argparse
import json
from pathlib import Path

import interstellar_transfer as courier

DAY = 86400
YEAR = 31557600
FIELDS = {'payload_bytes', 'evidence_frames', 'additional_frames_per_day',
          'blackout_seconds', 'backlog_frames', 'backlog_bytes',
          'usable_bytes_per_second', 'contact_window_seconds', 'one_way_seconds'}


def integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= 10**30:
        raise ValueError(f'{name} must be a bounded integer >= {minimum}')
    return value


def ceil_div(n, d):
    return (n + d - 1) // d


def direction(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('direction fields missing or unknown')
    for name in FIELDS:
        integer(value[name], name)
    payload = integer(value['payload_bytes'], 'payload_bytes', 1)
    if payload > courier.MAX_PAYLOAD:
        raise ValueError('payload exceeds actual courier limit')
    if value['evidence_frames'] < 1 or value['usable_bytes_per_second'] < 1:
        raise ValueError('positive evidence count and usable bandwidth required')
    if ((value['backlog_frames'] == 0) != (value['backlog_bytes'] == 0)
            or value['backlog_bytes'] < value['backlog_frames']):
        raise ValueError('inconsistent backlog counts')
    # The longest supported kind gives a conservative canonical frame size.
    frame_bytes = max(len(courier.make_frame(kind, '1'*64, '2'*64, '3'*64, b'x'*payload))
                      for kind in courier.KINDS)
    arrivals = ceil_div(value['additional_frames_per_day'] * value['blackout_seconds'], DAY)
    batch_frames = value['evidence_frames'] + arrivals
    retained_frames = value['backlog_frames'] + batch_frames
    retained_bytes = value['backlog_bytes'] + batch_frames * frame_bytes
    reasons = []
    if retained_frames > courier.MAX_QUEUE_FILES:
        reasons.append('QUEUE_FRAME_LIMIT')
    if retained_bytes > courier.MAX_QUEUE_BYTES:
        reasons.append('QUEUE_BYTE_LIMIT')
    # Includes the backlog in FIFO serialization; nothing is silently evicted.
    serialization = ceil_div(retained_bytes, value['usable_bytes_per_second'])
    if serialization > value['contact_window_seconds']:
        reasons.append('CONTACT_WINDOW_TOO_SHORT')
    return {'frame_bytes': frame_bytes, 'new_frames_during_blackout': arrivals,
            'peak_retained_frames': retained_frames, 'peak_retained_bytes': retained_bytes,
            'serialization_seconds': serialization, 'blocking_constraints': reasons,
            'queue_copies_after_send': retained_frames,
            'arrival_after_phase_start_seconds': None if reasons else
                value['blackout_seconds'] + serialization + value['one_way_seconds']}


def evaluate(value):
    if not isinstance(value, dict) or set(value) != {'name','forward','return','maturity_blocks','assumed_block_seconds'}:
        raise ValueError('scenario fields missing or unknown')
    if not isinstance(value['name'], str) or not 0 < len(value['name']) <= 120:
        raise ValueError('invalid scenario name')
    blocks = integer(value['maturity_blocks'], 'maturity_blocks', 6)
    interval = integer(value['assumed_block_seconds'], 'assumed_block_seconds', 1)
    forward, back = direction(value['forward']), direction(value['return'])
    fits = not forward['blocking_constraints'] and not back['blocking_constraints']
    estimated = (forward['arrival_after_phase_start_seconds'] + blocks*interval
                 + back['arrival_after_phase_start_seconds']) if fits else None
    return {'name': value['name'], 'result': 'BUDGET_FITS_ASSUMPTIONS' if fits else 'BUDGET_CONSTRAINTS_EXCEEDED',
            'route_qualified': False, 'production_rules_changed': False,
            'limits': {'max_payload_bytes': courier.MAX_PAYLOAD,
                       'max_queue_bytes': courier.MAX_QUEUE_BYTES, 'max_queue_frames': courier.MAX_QUEUE_FILES},
            'forward': forward, 'return': back,
            'conditional_round_trip_seconds': estimated,
            'conditional_round_trip_years': estimated/YEAR if estimated is not None else None,
            'scope': 'stationary one-batch planning estimate; excludes source finalization, destination inclusion delay, outages after contact, retries and node replay time; block interval is an assumption, not a deadline; courier retains sent copies'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', type=Path)
    args = parser.parse_args()
    value = courier.decode_json(courier.read_file(args.scenario, 65536))
    print(json.dumps(evaluate(value), ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
