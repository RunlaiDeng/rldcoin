"""Opt-in streaming diagnostic profile; never a custody or ledger journal.

The V1 in-memory window still has its original 8192-row lifetime limit. This
separate profile retains exact validated deltas on disk, at most one producer
ring in memory, with the same 8 MiB aggregate canonical-event byte limit. It
does not repair lost producer events or resume failed/closed observations.
"""
import hashlib
import math
import os
import threading
import time
from pathlib import Path

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace_window import TraceWindow, MAX_WINDOW_BYTES
from regional_contact_trace import FIELDS, MAX_EVENT_BYTES, check_fields


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
                    through_sequence={i: cursor.sequence for i, cursor in self.cursors.items()},
                    samples=dict(self.samples), unknown=dict(self.unknown),
                    intervals_complete=dict(self.complete), failed=self.failed,
                    uncommitted_resident_events=len(self.events),
                    all_four_streams_observed=all(self.samples.values()),
                    lifetime_row_limit_applies=False, canonical_byte_limit=MAX_WINDOW_BYTES,
                    authority=False, ledger_acceptance_known=False,
                    actual_live_schedule_reconstructed=False)


class IndependentTraceJournal(TraceJournal):
    """One owned reader for four bounded primitive publications, not Native.

    Uses the same row/schema/cursor/fsync/8-MiB verifier. It does not claim a
    missing publisher/reader interval or an old observation is complete.
    """
    @classmethod
    def attach(cls, controller, *, path):
        owned=TraceWindow.attach(controller)
        paths=tuple(Path(c['state'])/'regional-contact-trace-status.json' for c in controller.transport)
        mesh.require(len(paths)==4,'exact four diagnostic publication paths required')
        journal=cls(controller.currency,owned.slots,deadline=controller.deadline,path=path)
        journal.guard=threading.RLock();journal.stop_event=threading.Event();journal.error=None
        journal.owners=tuple(controller.processes['proxima',i] for i in range(4))
        journal.paths=paths
        journal.thread=threading.Thread(target=journal.run,daemon=True,name='contact-trace-collection')
        try:journal.thread.start()
        except BaseException:
            journal.close()
            raise
        return journal

    def read_once(self, *, require_live=True):
        with self.guard:
            try:self._read_once(require_live)
            except BaseException:
                self.failed=True
                raise

    def _read_once(self, require_live):
        from regional_contact_trace import MAX_BYTES,PUBLICATION_FORMAT
        with self.guard:
            for i in range(4):
                terminal=self.owners[i].poll()
                mesh.require(self.owners[i].pid==self.slots[i][0]
                             and (terminal is None if require_live else terminal==0),
                             'owned trace producer differs')
                try:value=mesh.load(self.paths[i],MAX_BYTES)
                except FileNotFoundError:value=None
                mesh.require(require_live or value is not None,'stopped diagnostic publication missing')
                if value is not None:
                    mesh.require(set(value)=={'format','process_id','contact_trace','publisher_failed'}
                                 and value['format']==PUBLICATION_FORMAT
                                 and value['publisher_failed'] is False,'diagnostic publisher failed or differs')
                self.sample(i,value,now=time.monotonic())

    def run(self):
        from regional_contact_trace import PUBLICATION_INTERVAL
        while not self.stop_event.is_set():
            try:self.read_once()
            except BaseException as error:
                # Keep a bounded primitive failure, never exception tracebacks
                # retaining decoded snapshots or other mutable call locals.
                with self.guard:self.error=type(error).__name__[:48];self.failed=True
                return
            self.stop_event.wait(PUBLICATION_INTERVAL)

    def collect(self, controller):
        # Native height observation never serializes this independent reader.
        with self.guard:
            if self.error is not None:raise ValueError('independent trace collector failed: '+self.error)
            mesh.require(not self.failed,'failed trace journal cannot resume')

    def stop_collection(self):
        self.stop_event.set()
        if self.thread.ident is not None:self.thread.join(timeout=3)
        mesh.require(not self.thread.is_alive(),'diagnostic collector did not stop')

    def close(self):
        try:self.stop_collection()
        finally:super().close()

    def snapshot(self):
        with self.guard:
            return dict(super().snapshot(),collection_profile='RLD-FOUR-CLI-INDEPENDENT-PUBLICATION-JOURNAL-V1')


def verify_journal(path, snapshot, *, network, slots):
    """Bounded readback of closed diagnostics under independently pinned owners.

    A matching hash alone does not establish contiguous per-producer coverage.
    This reader checks every exact scalar row, count, byte total and sequence,
    using constant-size per-slot state. It never opens Native or a mesh node.
    Missing samples remain explicit even when later samples filled the ring.
    """
    from regional_paged_fault_scope import safe
    path = safe(path)
    mesh.require(type(snapshot) is dict and snapshot.get('format') == 'RLD-FOUR-CLI-TRACE-JOURNAL-V1'
                 and snapshot.get('network') == mesh.hex32(network)
                 and snapshot.get('journal_path') == str(path), 'trace journal scope differs')
    mesh.require(snapshot.get('closed') is True and snapshot.get('failed') is False
                 and snapshot.get('uncommitted_resident_events') == 0
                 and snapshot.get('authority') is False
                 and snapshot.get('ledger_acceptance_known') is False
                 and snapshot.get('actual_live_schedule_reconstructed') is False
                 and snapshot.get('lifetime_row_limit_applies') is False
                 and snapshot.get('canonical_byte_limit') == MAX_WINDOW_BYTES,
                 'closed successful diagnostic profile required')

    def four(value):
        mesh.require(type(value) is dict and
                     (set(value) == set(range(4)) or set(value) == {str(i) for i in range(4)})
                     and len(value) == 4, 'exact four journal slots required')
        return {i: value[i] if i in value else value[str(i)] for i in range(4)}

    expected = four(slots)
    observed = four(snapshot['slots'])
    # Reuse exactly the original typed/distinct owner/binding requirements.
    pinned = TraceWindow(network, expected, deadline=0)
    mesh.require(all(tuple(observed[i]) == pinned.slots[i] for i in range(4)),
                 'trace journal owners differ')
    samples, unknown, complete = (four(snapshot[k]) for k in
                                 ('samples', 'unknown', 'intervals_complete'))
    through = four(snapshot['through_sequence'])
    mesh.require(all(type(samples[i]) is int and 0 < samples[i] < 2**63
                     and type(unknown[i]) is int and 0 <= unknown[i] < 2**63
                     and type(through[i]) is int and 0 <= through[i] < 2**63
                     and complete[i] is True for i in range(4))
                 and snapshot.get('all_four_streams_observed') is True,
                 'complete four-stream prefix required; gaps cannot be repaired')
    for name in ('persisted_events', 'journal_bytes', 'canonical_event_bytes'):
        mesh.require(type(snapshot[name]) is int and 0 <= snapshot[name] <= MAX_WINDOW_BYTES,
                     'bounded exact journal counters required')
    mesh.require(path.is_file() and path.stat().st_size == snapshot['journal_bytes']
                 and snapshot['journal_bytes'] <= MAX_WINDOW_BYTES, 'journal byte inventory differs')
    digest = hashlib.sha256()
    sequences = {i: 0 for i in range(4)}
    times = {i: None for i in range(4)}
    count = size = 0
    with path.open('rb') as stream:
        while True:
            raw = stream.readline(MAX_EVENT_BYTES + 33)
            if not raw:
                break
            mesh.require(raw.endswith(b'\n') and len(raw) <= MAX_EVENT_BYTES + 32,
                         'bounded complete journal line required')
            size += len(raw)
            mesh.require(size <= MAX_WINDOW_BYTES, 'finite trace byte capacity reached')
            row = wire.decode_json(raw[:-1])
            mesh.require(type(row) is dict and raw[:-1] == wire.canonical(row)
                         and not set(row) - (FIELDS | {'slot', 'sequence', 'monotonic_seconds', 'stage', 'peer'}),
                         'exact canonical scalar journal row required')
            i = row['slot']
            mesh.require(type(i) is int and i in sequences and type(row['sequence']) is int
                         and row['sequence'] == sequences[i] + 1,
                         'trace journal sequence gap or duplicate')
            now = row['monotonic_seconds']
            mesh.require(type(now) in (int, float) and math.isfinite(now) and now >= 0
                         and (times[i] is None or now >= times[i]), 'trace journal clock differs')
            check_fields(row['stage'], row['peer'], {k: row[k] for k in FIELDS if k in row})
            producer_row = {k: v for k, v in row.items() if k != 'slot'}
            mesh.require(len(wire.canonical(producer_row)) <= MAX_EVENT_BYTES, 'producer row bound differs')
            sequences[i], times[i] = row['sequence'], now
            digest.update(raw)
            count += 1
    mesh.require(count == snapshot['persisted_events'] and size == snapshot['journal_bytes']
                 and sequences == through
                 and (size + 1 if count else 2) == snapshot['canonical_event_bytes']
                 and digest.hexdigest() == snapshot['journal_sha256'],
                 'trace journal byte commitment or count differs')
    return dict(format='RLD-FOUR-CLI-TRACE-JOURNAL-READBACK-V1',
                events=count, canonical_event_bytes=snapshot['canonical_event_bytes'],
                through_sequence=sequences, missing_status_samples=unknown,
                complete_collected_prefix=True, complete_future_or_live_schedule=False,
                authority=False, native_ledger_authority=False)
