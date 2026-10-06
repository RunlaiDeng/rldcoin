"""Fixture-only complete primitive first-service journal; no ledger authority.

Bounded no-follow publications are read by one owned thread. Missing startup
files remain unknown; a gap, foreign owner, partial write or failed sync makes
the collector permanently incomplete. It cannot resume or signal producers.
"""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import threading
import time

PROJECT = Path('/Users/galaxy/GitHub/rldcoin')
BASE = PROJECT/'tmp/default-relay-20260930'
OBSERVER = BASE/'first_service_diagnostic_observer_v6_20261007.py'
OBSERVER_SHA = '93d98f912f69a6238ee5666a650cab24a44ac9780c81c81efd7bad4e8dc56bc7'
if hashlib.sha256(OBSERVER.read_bytes()).hexdigest() != OBSERVER_SHA:
    raise ValueError('first-service observer source changed')
spec = importlib.util.spec_from_file_location('first_service_collector_observer', OBSERVER)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)
require, encode = diag.require, diag.encode
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
FORMAT = 'RLD-FIRST-SERVICE-CLOSED-JOURNAL-V1'

def safe(path):
    from regional_paged_fault_scope import safe as checked
    return checked(path)

def read_json(path, maximum):
    from regional_paged_fault_scope import raw
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'first-service duplicate JSON field')
            value[key] = item
        return value
    return json.loads(raw(path, maximum), object_pairs_hook=unique)

class Journal:
    def __init__(self, bindings, deadline, path):
        require(type(bindings) is dict and set(bindings) == set(range(4))
                and all(type(i) is int for i in bindings), 'exact four typed slots')
        require(type(deadline) in (int,float) and math.isfinite(deadline), 'finite original deadline')
        self.bindings = {i: diag.Ring(value).binding for i,value in bindings.items()}
        require(all(value['slot'] == i for i,value in self.bindings.items())
                and len({v['process_id'] for v in self.bindings.values()}) == 4
                and len({v['scope'] for v in self.bindings.values()}) == 1
                and len({v['contract_sha256'] for v in self.bindings.values()}) == 1,
                'distinct producers, same exact scope and contract')
        self.deadline, self.path = deadline, safe(path)
        self.cursors = {i: diag.Cursor(value) for i,value in self.bindings.items()}
        self.samples = {i: 0 for i in range(4)}
        self.unknown = {i: 0 for i in range(4)}
        self.failed = self.closed = False
        self.events = self.bytes = 0
        self.digest = hashlib.sha256()
        self.guard = threading.RLock()
        self.fd = os.open(self.path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)

    def sample(self, slot, value, now):
        with self.guard:
            require(not self.failed and not self.closed, 'failed/closed journal never resumes')
            try:
                require(type(slot) is int and slot in self.bindings
                        and type(now) in (int,float) and math.isfinite(now)
                        and now < self.deadline, 'slot or original deadline differs')
                if value is None:
                    self.unknown[slot] += 1
                    require(self.unknown[slot] < diag.MAX_COUNTER, 'unknown counter exhausted')
                    return 0
                rows = self.cursors[slot].drain(value)
                data = b''.join(encode(dict(slot=slot, record=row))+b'\n' for row in rows)
                require(self.bytes + len(data) <= MAX_JOURNAL_BYTES, 'first-service journal byte capacity')
                if data:
                    offset = 0
                    while offset < len(data):
                        written = os.write(self.fd, data[offset:])
                        require(type(written) is int and written > 0, 'journal write made no progress')
                        offset += written
                    os.fsync(self.fd)
                    # Failed write/sync never advances the committed counters.
                    self.digest.update(data)
                    self.bytes += len(data)
                    self.events += len(rows)
                self.samples[slot] += 1
                require(self.samples[slot] < diag.MAX_COUNTER, 'sample counter exhausted')
                return len(rows)
            except BaseException:
                self.failed = True
                raise

    def close(self):
        with self.guard:
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
        with self.guard:
            return dict(format=FORMAT, bindings=json.loads(encode(self.bindings)), path=str(self.path),
                        journal_sha256=self.digest.hexdigest(), journal_bytes=self.bytes,
                        events=self.events, samples=dict(self.samples), unknown=dict(self.unknown),
                        through_sequence={i:v.sequence for i,v in self.cursors.items()},
                        all_four_streams_observed=all(self.samples.values()),
                        failed=self.failed, closed=self.closed, byte_capacity=MAX_JOURNAL_BYTES,
                        authority=False, ledger_acceptance_known=False)

class Collector(Journal):
    @classmethod
    def attach(cls, controller, *, contract, contract_sha256, entry):
        require(Path.cwd() == PROJECT and controller.project == PROJECT
                and safe(controller.root) == safe(contract['root']), 'exact migrated fresh controller')
        require(set(controller.processes) == {('proxima',i) for i in range(4)}, 'four actual owned Popen objects')
        bindings, paths, owners = {}, [], []
        for i in range(4):
            owner = controller.processes['proxima',i]
            require(owner.poll() is None and os.getpgid(owner.pid) == owner.pid,
                    'original owned live process group required')
            config = controller.configs['ordinary','proxima',i]
            values = dict(zip(config.argv[1::2],config.argv[2::2]))
            require(values['--transport-python'] == str(entry)
                    and config.argv[0] == contract['binary'], 'exact diagnostic entry and actual binary')
            root = safe(controller.transport[i]['state'])
            require(root == safe(contract['root'])/'mesh'/str(i), 'exact fresh publication path')
            paths.append(root/'first-service-diag-status.json')
            owners.append(owner)
            bindings[i] = dict(process_id=owner.pid,scope=contract['root'],slot=i,
                               contract_sha256=contract_sha256)
        instance = cls(bindings, controller.deadline, controller.output/'first-service-events.jsonl')
        instance.paths, instance.owners = tuple(paths), tuple(owners)
        instance.stop_event = threading.Event()
        instance.error = None
        instance.thread = threading.Thread(target=instance.run,daemon=True,name='first-service-collection')
        try:
            instance.thread.start()
        except BaseException:
            instance.close()
            raise
        return instance

    def read_once(self, require_live=True):
        with self.guard:
            try:
                for i,owner in enumerate(self.owners):
                    terminal = owner.poll()
                    require(owner.pid == self.bindings[i]['process_id']
                            and (terminal is None if require_live else type(terminal) is int and terminal == 0),
                            'original first-service producer changed or failed')
                    if require_live:
                        require(os.getpgid(owner.pid) == owner.pid, 'owned producer group changed')
                    try:
                        value = read_json(self.paths[i], diag.MAX_BYTES)
                    except FileNotFoundError:
                        value = None
                    require(require_live or value is not None, 'stopped publication missing')
                    if value is not None:
                        receipt = read_json(self.paths[i].parent/'first-service-observer-owner.json', 192*1024)
                        expected = {k:self.bindings[i][k] for k in ('process_id','slot','contract_sha256')}
                        require(encode(receipt) == encode(expected), 'once-only observer owner differs')
                    current = owner.poll()
                    require(current is None if require_live else type(current) is int and current == 0,
                            'producer exited during live observation')
                    self.sample(i,value,time.monotonic())
            except BaseException:
                self.failed = True
                raise

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.read_once()
            except BaseException as error:
                with self.guard:
                    self.failed = True
                    self.error = type(error).__name__[:48]
                return
            self.stop_event.wait(.25)

    def collect(self):
        with self.guard:
            require(not self.failed and self.error is None, 'independent first-service collection failed')

    def stop_collection(self):
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
        require(not self.thread.is_alive(), 'owned first-service collector did not stop')

    def close(self):
        try:
            if hasattr(self,'thread'):
                self.stop_collection()
        finally:
            super().close()

def verify(path, snapshot, bindings):
    require(type(snapshot) is dict and snapshot['format'] == FORMAT
            and snapshot['closed'] is True and snapshot['failed'] is False
            and snapshot['authority'] is False and snapshot['ledger_acceptance_known'] is False
            and snapshot['all_four_streams_observed'] is True,
            'closed complete four-stream diagnostic journal required')
    require(type(bindings) is dict and set(bindings) == set(range(4))
            and all(type(i) is int for i in bindings), 'exact independently pinned four slots')
    pinned = {str(i):diag.Ring(value).binding for i,value in bindings.items()}
    require(all(v['slot'] == int(i) for i,v in pinned.items())
            and len({v['process_id'] for v in pinned.values()}) == 4
            and len({v['scope'] for v in pinned.values()}) == 1
            and len({v['contract_sha256'] for v in pinned.values()}) == 1,
            'closed copied or foreign producer binding')
    require(len(pinned) == 4 and set(pinned) == {str(i) for i in range(4)}
            and encode(snapshot['bindings']) == encode(pinned), 'closed owner binding differs')
    require(str(safe(path)) == snapshot['path'] and snapshot['byte_capacity'] == MAX_JOURNAL_BYTES,
            'closed path/capacity differs')
    for name in ('samples','unknown','through_sequence'):
        values = {str(i):v for i,v in snapshot[name].items()}
        require(set(values) == set(pinned) and all(type(v) is int and 0 <= v < diag.MAX_COUNTER
                for v in values.values()), 'closed typed stream inventory')
        if name == 'samples': require(all(values.values()), 'missing first-service stream')
    for name in ('journal_bytes','events'):
        require(type(snapshot[name]) is int and 0 <= snapshot[name] <= MAX_JOURNAL_BYTES,
                'closed typed byte/event inventory')
    from regional_paged_fault_scope import raw
    data = raw(path, MAX_JOURNAL_BYTES)
    require(len(data) == snapshot['journal_bytes']
            and hashlib.sha256(data).hexdigest() == snapshot['journal_sha256'], 'closed bytes changed')
    sequences, count = {i:0 for i in range(4)}, 0
    for line in data.splitlines(keepends=True):
        require(line.endswith(b'\n') and len(line) <= diag.MAX_EVENT_BYTES+128,
                'closed bounded complete row')
        value = json.loads(line)
        require(type(value) is dict and set(value) == {'slot','record'}
                and type(value['slot']) is int and value['slot'] in sequences
                and encode(value)+b'\n' == line, 'closed exact canonical primitive row')
        slot, row = value['slot'], value['record']
        diag.check_record(row, sequenced=True)
        require(row['sequence'] == sequences[slot]+1, 'closed per-slot gap')
        sequences[slot] += 1
        count += 1
    require(count == snapshot['events'] and encode(sequences) == encode(snapshot['through_sequence']),
            'closed prefix does not match all streams')
    return dict(completed=True,events=count,bytes=len(data),complete_collected_prefix=True,
                authority=False,ledger_acceptance_known=False)
