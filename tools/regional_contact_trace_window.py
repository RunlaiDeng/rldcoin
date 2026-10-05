"""Finite controller trace retention; telemetry never grants Native authority.

The caller must independently bind each live owned process/status to its pinned
configuration. This window accepts only its exact PID and trace scope, retains
validated scalar deltas, and treats missing observations as unknown. It never
opens a node, reads custody, starts/recover/signs, or authorizes ledger progress.
"""
import math
from pathlib import Path
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import TraceCursor

MAX_WINDOW_EVENTS = 8192
MAX_WINDOW_BYTES = 8 * 1024 * 1024


class TraceWindow:
    def __init__(self, network, slots, *, deadline):
        mesh.require(type(slots) is dict and set(slots) == set(range(4)),
                     'exact four trace slots required')
        mesh.require(type(deadline) in (int, float) and math.isfinite(deadline),
                     'finite trace deadline required')
        self.deadline = deadline
        self.slots = {}
        self.cursors = {}
        for index, (pid, node_id) in slots.items():
            mesh.require(type(pid) is int and pid > 1, 'actual owned trace PID required')
            self.slots[index] = (pid, mesh.hex32(node_id))
            self.cursors[index] = TraceCursor(network, node_id)
        mesh.require(len({p for p, _ in self.slots.values()}) == 4
                     and len({n for _, n in self.slots.values()}) == 4,
                     'distinct trace owners and identities required')
        self.events = []
        self.event_bytes = 2
        self.unknown = {i: 0 for i in slots}
        self.samples = {i: 0 for i in slots}
        self.complete = {i: True for i in slots}
        self.failed = False

    def sample(self, index, status, *, now):
        mesh.require(not self.failed, 'failed trace window cannot resume')
        try:
            mesh.require(type(index) is int and index in self.slots, 'trace slot differs')
            mesh.require(type(now) in (int, float) and math.isfinite(now)
                         and now < self.deadline, 'original trace deadline reached')
            pid, _ = self.slots[index]
            if status is None:
                self.unknown[index] += 1
                return {'available': False, 'events': None, 'authority': False,
                        'this_interval_complete': False}
            mesh.require(type(status) is dict and type(status.get('process_id')) is int
                         and status['process_id'] == pid, 'trace producer PID differs')
            if 'contact_trace' not in status:
                self.unknown[index] += 1
                return {'available': False, 'events': None, 'authority': False,
                        'this_interval_complete': False}
            delta = self.cursors[index].drain(status['contact_trace'])
            self.samples[index] += 1
            self.complete[index] &= delta['this_interval_complete']
            rows = [dict(slot=index, **row) for row in (delta['events'] or [])]
            mesh.require(len(self.events) + len(rows) <= MAX_WINDOW_EVENTS,
                         'finite trace event capacity reached')
            size = self.event_bytes + sum(len(wire.canonical(row)) for row in rows)
            size += len(rows) - int(bool(rows) and not self.events)
            mesh.require(size <= MAX_WINDOW_BYTES, 'finite trace byte capacity reached')
            self.events.extend(rows)
            self.event_bytes = size
            return delta
        except BaseException:
            # A cursor may have advanced before capacity/publication refusal.
            # Do not reuse that observation as an intact successful interval.
            self.failed = True
            raise

    @classmethod
    def attach(cls, controller):
        """After the original driver launches four actual owned Popen children."""
        mesh.require(set(controller.processes) == {('proxima', i) for i in range(4)},
                     'exact four live controller owners required')
        slots = {}
        for i in range(4):
            process = controller.processes['proxima', i]
            mesh.require(process.poll() is None, 'trace owner already terminal')
            slots[i] = (process.pid, controller.pins[i]['node_id'])
        return cls(controller.currency, slots, deadline=controller.deadline)

    def collect(self, controller):
        """Run after the driver's normal PID/TLS/native status validation.

        Read only ordinary status files; never Native or private custody. A
        missing status remains unknown. Producer exit or changed bytes/scope
        refuse; neither can cause launch, recovery, signing or head adoption.
        """
        from regional_paged_fault_scope import document
        mesh.require(not self.failed, 'failed trace window cannot resume')
        try:
            for i in range(4):
                controller.remaining()
                process = controller.processes['proxima', i]
                mesh.require(process.pid == self.slots[i][0] and process.poll() is None,
                             'live trace producer differs')
                path = Path(controller.transport[i]['state']) / 'regional-contact-status.json'
                try:
                    status = document(path)
                except FileNotFoundError:
                    status = None
                mesh.require(process.poll() is None, 'trace producer exited while reading')
                self.sample(i, status, now=time.monotonic())
        except BaseException:
            self.failed = True
            raise

    def snapshot(self):
        return dict(format='RLD-FOUR-CLI-TRACE-WINDOW-V1',
                    events=[dict(row) for row in self.events], event_bytes=self.event_bytes,
                    samples=dict(self.samples), unknown=dict(self.unknown),
                    intervals_complete=dict(self.complete), failed=self.failed,
                    all_four_streams_observed=all(self.samples.values()),
                    authority=False, ledger_acceptance_known=False,
                    actual_live_schedule_reconstructed=False)
