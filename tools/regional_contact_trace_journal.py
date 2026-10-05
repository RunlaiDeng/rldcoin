"""Opt-in streaming diagnostic profile; never a custody or ledger journal.

The V1 in-memory window still has its original 8192-row lifetime limit. This
separate profile retains exact validated deltas on disk, at most one producer
ring in memory, with the same 8 MiB aggregate canonical-event byte limit. It
does not repair lost producer events or resume failed/closed observations.
"""
import hashlib
import os
from pathlib import Path

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace_window import TraceWindow, MAX_WINDOW_BYTES


class TraceJournal(TraceWindow):
    def __init__(self, network, slots, *, deadline, path):
        super().__init__(network, slots, deadline=deadline)
        self.network = network
        self.path = Path(path)
        self.closed = False
        self.persisted_events = 0
        self.canonical_bytes = 2
        self.journal_bytes = 0
        self.digest = hashlib.sha256()
        # Never truncate/reopen an old trace or follow a final-component link.
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | os.O_NOFOLLOW, 0o600)

    def sample(self, index, status, *, now):
        mesh.require(not self.closed, 'closed trace journal cannot resume')
        try:
            delta = super().sample(index, status, now=now)
            encoded = [wire.canonical(row) for row in self.events]
            size = self.canonical_bytes + sum(map(len, encoded)) + len(encoded)
            size -= int(bool(encoded) and self.persisted_events == 0)
            mesh.require(size <= MAX_WINDOW_BYTES, 'finite trace byte capacity reached')
            if encoded:
                data = b''.join(row + b'\n' for row in encoded)
                offset = 0
                while offset < len(data):
                    written = os.write(self.fd, data[offset:])
                    mesh.require(type(written) is int and written > 0,
                                 'trace journal write made no progress')
                    offset += written
                os.fsync(self.fd)
                # A partial write/fsync failure never advances the committed
                # digest/count and permanently refuses this collector.
                self.digest.update(data)
                self.journal_bytes += len(data)
                self.persisted_events += len(encoded)
                self.canonical_bytes = size
                self.events.clear()
                self.event_bytes = 2
            return delta
        except BaseException:
            self.failed = True
            raise

    @classmethod
    def attach(cls, controller, *, path):
        owned = TraceWindow.attach(controller)
        return cls(controller.currency, owned.slots, deadline=controller.deadline, path=path)

    def close(self):
        if not self.closed:
            try:
                os.fsync(self.fd)
            except BaseException:
                self.failed = True
                raise
            finally:
                try:
                    os.close(self.fd)
                finally:
                    self.closed = True

    def snapshot(self):
        # Deliberately no complete-history list. Readers must independently
        # verify the exact byte commitment, binding, sequences and coverage.
        return dict(format='RLD-FOUR-CLI-TRACE-JOURNAL-V1',
                    network=self.network, slots=dict(self.slots),
                    journal_path=str(self.path), journal_sha256=self.digest.hexdigest(),
                    journal_bytes=self.journal_bytes, canonical_event_bytes=self.canonical_bytes,
                    persisted_events=self.persisted_events, closed=self.closed,
                    samples=dict(self.samples), unknown=dict(self.unknown),
                    intervals_complete=dict(self.complete), failed=self.failed,
                    uncommitted_resident_events=len(self.events),
                    all_four_streams_observed=all(self.samples.values()),
                    lifetime_row_limit_applies=False, canonical_byte_limit=MAX_WINDOW_BYTES,
                    authority=False, ledger_acceptance_known=False,
                    actual_live_schedule_reconstructed=False)
