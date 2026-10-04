"""Bounded process-local ground timing; never consensus or custody input.

Only public byte identities and scalar observations enter this ring. Restart
starts a new sequence; eviction is explicit. No keys, requests, proofs, native
heads or decoded ledgers are retained. Observations never restore runtime state.
"""
from collections import deque
import os
import time

import interstellar_transfer as wire

FORMAT = 'RLD-BFT-PROCESS-OBSERVATION-V1'
MAX_EVENTS = 128
MAX_EVENT_BYTES = 1024
MAX_BYTES = 192 * 1024
MAX_OPERATIONS = 32


class Observation:
    def __init__(self):
        self.started = time.monotonic()
        self.events = deque(maxlen=MAX_EVENTS)
        self.sequence = self.dropped = self.rejected = 0
        self.operations = {}

    def event(self, kind, started=None, **fields):
        # Strict primitives prevent a diagnostic from retaining mutable native
        # authorization or an unbounded peer-supplied object.
        now = time.monotonic()
        if (type(kind) is not str or len(kind) > 48 or len(fields) > 16
                or any(type(k) is not str or len(k) > 48
                       or type(v) not in (str, int, float, bool, type(None))
                       or (type(v) is str and len(v) > 128)
                       for k, v in fields.items())):
            self.rejected += 1
            return
        row = dict(sequence=self.sequence + 1, kind=kind,
                   elapsed_seconds=round(now-self.started, 6), **fields)
        if started is not None:
            row['duration_seconds'] = round(max(0, now-started), 6)
        if len(wire.canonical(row)) > MAX_EVENT_BYTES:
            self.rejected += 1
            return
        self.sequence += 1
        if len(self.events) == MAX_EVENTS:
            self.dropped += 1
        self.events.append(row)

    def operation(self, name, started, succeeded):
        if name not in self.operations:
            if len(self.operations) == MAX_OPERATIONS:
                self.rejected += 1
                return
            self.operations[name] = dict(calls=0, failures=0, total_seconds=0.0, max_seconds=0.0)
        row = self.operations[name]
        duration = max(0, time.monotonic()-started)
        row['calls'] += 1
        row['failures'] += int(not succeeded)
        row['total_seconds'] += duration
        row['max_seconds'] = max(row['max_seconds'], duration)

    def snapshot(self):
        value = dict(format=FORMAT, process_id=os.getpid(), sequence=self.sequence,
                     dropped_events=self.dropped, rejected_events=self.rejected,
                     process_local_only=True, timing_is_authority=False,
                     events=[dict(row) for row in self.events],
                     operations={name: {k: round(v, 6) if type(v) is float else v
                                        for k, v in row.items()}
                                 for name, row in self.operations.items()})
        # Fixed cardinalities/primitive lengths keep this below the independent
        # diagnostic bound; do not change a native capacity or authority gate.
        if len(wire.canonical(value)) > MAX_BYTES:
            return dict(format=FORMAT, process_id=os.getpid(), observation_available=False,
                        diagnostic='diagnostic capacity', timing_is_authority=False)
        return value
