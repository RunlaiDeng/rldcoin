"""Separate finite diagnostic disk profile; no Native or transport authority.

Every original scalar event is retained. Each immutable shard is at most the
old 8-MiB diagnostic allowance; at most four shards may be sealed. The writer
retains one bounded producer delta, and the reader retains one bounded row.
Old journal formats and all protocol input/state/evidence limits are unchanged.
"""
import hashlib
import math
import os
import stat
from pathlib import Path

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_trace import FIELDS, MAX_EVENTS, MAX_EVENT_BYTES, check_fields
from regional_contact_trace_journal import IndependentTraceJournal
from regional_contact_trace_window import TraceWindow, MAX_WINDOW_BYTES
from regional_paged_fault_scope import safe, raw

FORMAT = 'RLD-FOUR-CLI-TRACE-SHARDS-V1'
MAX_SHARDS = 4
MAX_DIAGNOSTIC_BYTES = MAX_SHARDS * MAX_WINDOW_BYTES
MAX_MANIFEST_BYTES = 16 * 1024


class TraceShards(IndependentTraceJournal):
    def __init__(self, network, slots, *, deadline, path):
        TraceWindow.__init__(self, network, slots, deadline=deadline)
        self.network = mesh.hex32(network)
        self.path = safe(path)
        self.path.mkdir(mode=0o700)  # Existing/interrupted destinations refuse.
        self.closed = False
        self.fd = None
        self.parts = []
        self.part_bytes = self.part_events = 0
        self.part_digest = hashlib.sha256()
        self.digest = hashlib.sha256()
        self.journal_bytes = self.persisted_events = 0
        self.canonical_bytes = 2
        self.manifest_sha256 = None
        self.maximum_resident_rows = 0

    def _open_part(self):
        mesh.require(len(self.parts) < MAX_SHARDS, 'diagnostic shard capacity reached')
        self.fd = os.open(self.path / f'part-{len(self.parts):02d}.jsonl',
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.part_bytes = self.part_events = 0
        self.part_digest = hashlib.sha256()

    def _seal_part(self):
        if self.fd is None:
            return
        try:
            os.fsync(self.fd)
        finally:
            os.close(self.fd)
            self.fd = None
        self.parts.append(dict(name=f'part-{len(self.parts):02d}.jsonl',
                               bytes=self.part_bytes, events=self.part_events,
                               sha256=self.part_digest.hexdigest()))

    def sample(self, index, status, *, now):
        mesh.require(not self.closed, 'closed diagnostic shards cannot resume')
        try:
            delta = TraceWindow.sample(self, index, status, now=now)
            mesh.require(len(self.events) <= MAX_EVENTS, 'one producer delta required')
            self.maximum_resident_rows = max(self.maximum_resident_rows, len(self.events))
            encoded = [wire.canonical(row) + b'\n' for row in self.events]
            size = sum(map(len, encoded))
            mesh.require(all(len(row) <= MAX_EVENT_BYTES + 32 for row in encoded)
                         and self.journal_bytes + size + 1 <= MAX_DIAGNOSTIC_BYTES,
                         'finite diagnostic disk capacity reached')
            # Refuse before writing if this whole batch cannot fit the remaining
            # four-shard inventory. No partial batch is acknowledged as complete.
            simulated = self.part_bytes
            parts = len(self.parts) + int(self.fd is not None)
            for row in encoded:
                if not parts or simulated + len(row) > MAX_WINDOW_BYTES:
                    parts += 1
                    simulated = 0
                simulated += len(row)
            mesh.require(parts <= MAX_SHARDS, 'diagnostic shard capacity reached')
            for row in encoded:
                if self.fd is None:
                    self._open_part()
                if self.part_bytes + len(row) > MAX_WINDOW_BYTES:
                    self._seal_part()
                    self._open_part()
                offset = 0
                while offset < len(row):
                    written = os.write(self.fd, row[offset:])
                    mesh.require(type(written) is int and written > 0,
                                 'diagnostic write made no progress')
                    offset += written
                self.part_digest.update(row)
                self.part_bytes += len(row)
                self.part_events += 1
            if encoded:
                os.fsync(self.fd)
                for row in encoded:
                    self.digest.update(row)
                self.journal_bytes += size
                self.persisted_events += len(encoded)
                self.canonical_bytes = self.journal_bytes + 1
            self.events.clear()
            self.event_bytes = 2
            return delta
        except BaseException:
            self.failed = True
            raise

    def _view(self):
        return dict(format=FORMAT, network=self.network, directory=str(self.path),
                    slots=dict(self.slots), parts=[dict(p) for p in self.parts],
                    journal_sha256=self.digest.hexdigest(), journal_bytes=self.journal_bytes,
                    canonical_event_bytes=self.canonical_bytes,
                    persisted_events=self.persisted_events, closed=self.closed, failed=self.failed,
                    through_sequence={i: c.sequence for i, c in self.cursors.items()},
                    samples=dict(self.samples), unknown=dict(self.unknown),
                    intervals_complete=dict(self.complete),
                    uncommitted_resident_events=len(self.events),
                    all_four_streams_observed=all(self.samples.values()),
                    maximum_resident_rows=self.maximum_resident_rows,
                    shard_byte_limit=MAX_WINDOW_BYTES, shard_count_limit=MAX_SHARDS,
                    diagnostic_disk_byte_limit=MAX_DIAGNOSTIC_BYTES,
                    authority=False, ledger_acceptance_known=False,
                    actual_live_schedule_reconstructed=False)

    def snapshot(self):
        guard = getattr(self, 'guard', None)
        if guard is None:
            return dict(self._view(), manifest_sha256=self.manifest_sha256)
        with guard:
            return dict(self._view(), manifest_sha256=self.manifest_sha256)

    def close(self):
        if self.closed:
            return
        if hasattr(self, 'thread'):
            self.stop_collection()
        try:
            self._seal_part()
            self.closed = True
            view = self._view()
            mesh.require(len(wire.canonical(view)) <= MAX_MANIFEST_BYTES,
                         'diagnostic manifest capacity reached')
            mesh.atomic(self.path / 'manifest.json', view)
            self.manifest_sha256 = hashlib.sha256(
                raw(self.path / 'manifest.json', MAX_MANIFEST_BYTES)).hexdigest()
        except BaseException:
            self.failed = True
            self.closed = True
            raise


def verify_shards(path, snapshot, *, network, slots, expected_format=FORMAT):
    """Exact external seal/owners plus scalar checks; never open a Native store."""
    path = safe(path)
    allowed_stages=None
    if expected_format!=FORMAT:
        from regional_submission_trace import SHARDS,STAGES
        mesh.require(expected_format==SHARDS,'unknown diagnostic shard profile')
        allowed_stages=STAGES
    encoded = raw(path / 'manifest.json', MAX_MANIFEST_BYTES)
    mesh.require(type(snapshot) is dict and
                 hashlib.sha256(encoded).hexdigest() == mesh.hex32(snapshot['manifest_sha256']),
                 'independently retained diagnostic seal differs')
    view = wire.decode_json(encoded)
    mesh.require(type(view) is dict and set(view) == {
        'format', 'network', 'directory', 'slots', 'parts', 'journal_sha256',
        'journal_bytes', 'canonical_event_bytes', 'persisted_events', 'closed', 'failed',
        'through_sequence', 'samples', 'unknown', 'intervals_complete',
        'uncommitted_resident_events', 'all_four_streams_observed', 'maximum_resident_rows',
        'shard_byte_limit', 'shard_count_limit', 'diagnostic_disk_byte_limit',
        'authority', 'ledger_acceptance_known', 'actual_live_schedule_reconstructed'},
        'exact diagnostic manifest fields required')
    mesh.require(encoded == wire.canonical(view) and
                 wire.canonical({k: v for k, v in snapshot.items() if k != 'manifest_sha256'}) == encoded,
                 'exact canonical diagnostic manifest differs')
    mesh.require(view['format'] == expected_format and view['network'] == mesh.hex32(network)
                 and view['directory'] == str(path) and view['closed'] is True
                 and view['failed'] is False and view['uncommitted_resident_events'] == 0
                 and view['authority'] is False and view['ledger_acceptance_known'] is False
                 and view['actual_live_schedule_reconstructed'] is False
                 and view['shard_byte_limit'] == MAX_WINDOW_BYTES
                 and view['shard_count_limit'] == MAX_SHARDS
                 and view['diagnostic_disk_byte_limit'] == MAX_DIAGNOSTIC_BYTES,
                 'closed successful diagnostic shard profile required')

    def four(value):
        mesh.require(type(value) is dict and (set(value) == set(range(4)) or
                     set(value) == {str(i) for i in range(4)}), 'exact four diagnostic slots required')
        return {i: value[i] if i in value else value[str(i)] for i in range(4)}

    pinned = TraceWindow(network, four(slots), deadline=0)
    observed = four(view['slots'])
    mesh.require(all(tuple(observed[i]) == pinned.slots[i] for i in range(4)),
                 'diagnostic owners differ')
    samples, unknown, complete, through = (four(view[k]) for k in
                                          ('samples', 'unknown', 'intervals_complete', 'through_sequence'))
    mesh.require(all(type(samples[i]) is int and 0 < samples[i] < 2**63
                     and type(unknown[i]) is int and 0 <= unknown[i] < 2**63
                     and type(through[i]) is int and 0 <= through[i] < 2**63
                     and complete[i] is True for i in range(4))
                 and view['all_four_streams_observed'] is True,
                 'complete four-stream prefix required; gaps cannot be repaired')
    mesh.require(type(view['parts']) is list and 1 <= len(view['parts']) <= MAX_SHARDS
                 and type(view['maximum_resident_rows']) is int
                 and 0 < view['maximum_resident_rows'] <= MAX_EVENTS,
                 'bounded diagnostic inventory required')
    mesh.require(all(type(view[k]) is int and 0 <= view[k] <= MAX_DIAGNOSTIC_BYTES
                     for k in ('persisted_events', 'journal_bytes', 'canonical_event_bytes')),
                 'bounded exact diagnostic counters required')
    expected = {'manifest.json'} | {f'part-{i:02d}.jsonl' for i in range(len(view['parts']))}
    mesh.require({p.name for p in path.iterdir()} == expected, 'exact diagnostic file inventory differs')
    sequences = {i: 0 for i in range(4)}
    times = {i: None for i in range(4)}
    digest = hashlib.sha256()
    count = size = 0
    for n, part in enumerate(view['parts']):
        mesh.require(type(part) is dict and set(part) == {'name', 'bytes', 'events', 'sha256'}
                     and part['name'] == f'part-{n:02d}.jsonl'
                     and type(part['bytes']) is int and 0 < part['bytes'] <= MAX_WINDOW_BYTES
                     and type(part['events']) is int and 0 < part['events'] < 2**63,
                     'bounded ordered diagnostic shard required')
        fd = os.open(safe(path / part['name']), os.O_RDONLY | os.O_NOFOLLOW)
        part_hash = hashlib.sha256()
        part_size = part_count = 0
        try:
            info = os.fstat(fd)
            mesh.require(stat.S_ISREG(info.st_mode) and info.st_size == part['bytes'],
                         'diagnostic shard size differs')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                while True:
                    row_bytes = stream.readline(MAX_EVENT_BYTES + 33)
                    if not row_bytes:
                        break
                    mesh.require(row_bytes.endswith(b'\n') and len(row_bytes) <= MAX_EVENT_BYTES + 32,
                                 'bounded complete diagnostic line required')
                    part_size += len(row_bytes)
                    size += len(row_bytes)
                    mesh.require(part_size <= MAX_WINDOW_BYTES and size + 1 <= MAX_DIAGNOSTIC_BYTES,
                                 'diagnostic byte capacity reached')
                    row = wire.decode_json(row_bytes[:-1])
                    mesh.require(type(row) is dict and row_bytes[:-1] == wire.canonical(row)
                                 and not set(row) - (FIELDS | {'slot', 'sequence', 'monotonic_seconds', 'stage', 'peer'}),
                                 'exact canonical diagnostic row required')
                    i = row['slot']
                    mesh.require(type(i) is int and i in sequences and type(row['sequence']) is int
                                 and row['sequence'] == sequences[i] + 1, 'diagnostic sequence gap or duplicate')
                    now = row['monotonic_seconds']
                    mesh.require(type(now) in (int, float) and math.isfinite(now) and now >= 0
                                 and (times[i] is None or now >= times[i]), 'diagnostic clock differs')
                    check_fields(row['stage'], row['peer'], {k: row[k] for k in FIELDS if k in row})
                    mesh.require(allowed_stages is None or row['stage'] in allowed_stages,
                                 'unselected stage in narrow diagnostic archive')
                    mesh.require(len(wire.canonical({k: v for k, v in row.items() if k != 'slot'}))
                                 <= MAX_EVENT_BYTES, 'producer row bound differs')
                    sequences[i], times[i] = row['sequence'], now
                    part_hash.update(row_bytes)
                    digest.update(row_bytes)
                    part_count += 1
                    count += 1
        finally:
            os.close(fd)
        mesh.require(part_size == part['bytes'] and part_count == part['events']
                     and part_hash.hexdigest() == mesh.hex32(part['sha256']), 'diagnostic shard commitment differs')
    mesh.require(count == view['persisted_events'] and size == view['journal_bytes']
                 and sequences == through and size + 1 == view['canonical_event_bytes']
                 and digest.hexdigest() == mesh.hex32(view['journal_sha256']),
                 'diagnostic aggregate commitment differs')
    return dict(format=expected_format + '-READBACK', events=count, shard_count=len(view['parts']),
                canonical_event_bytes=size + 1, through_sequence=sequences,
                missing_status_samples=unknown, complete_collected_prefix=True,
                complete_future_or_live_schedule=False, authority=False, native_ledger_authority=False)
