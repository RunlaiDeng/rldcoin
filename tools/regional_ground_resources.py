"""Bounded, read-only ground resource sampling; no ledger or custody authority.

Runs beside an explicitly selected fresh controller. It never starts, stops,
locks, opens or recovers a node, signer, wallet or native journal. Output stays
private. Samples are observations, not continuous peaks or qualification.
"""
import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import time
from pathlib import Path

FORMAT = 'RLD-GROUND-RESOURCE-SAMPLES-V1'
CHILD_CPU_FORMAT = 'RLD-GROUND-RESOURCE-SAMPLES-V2'
MAX_RECORDS = 4096
MAX_LOG = 32 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_ENTRIES = 4096
HEX = re.compile(r'[0-9a-f]{64}\Z')
LABEL = re.compile(r'[a-z][a-z0-9_-]{0,47}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(path, limit=256 * 1024 * 1024):
    require(not path.is_symlink() and path.is_file(), 'regular pinned file required')
    result = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            size += len(chunk)
            require(size <= limit, 'pinned file exceeds observation bound')
            result.update(chunk)
    return result.hexdigest(), size


def source_binding(manifest, source, binary, expected_source, expected_binary):
    require(HEX.fullmatch(expected_source) is not None and HEX.fullmatch(expected_binary) is not None,
            'explicit frozen source and binary commitments required')
    require(manifest.stat().st_size <= 1024 * 1024, 'manifest observation bound exceeded')
    value = json.loads(manifest.read_bytes())
    rows = value['files']
    require(type(rows) is list and 1 <= len(rows) <= MAX_ENTRIES,
            'bounded complete source inventory required')
    require(HEX.fullmatch(value['source_set_sha256']) is not None and
            hashlib.sha256(canonical(rows)).hexdigest() == value['source_set_sha256'] == expected_source,
            'source inventory commitment differs')
    seen = set()
    for row in rows:
        name = row['path']
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and
                name not in seen and name != '.', 'unique relative source entry required')
        seen.add(name)
        candidate = source / relative
        require(candidate.resolve().is_relative_to(source.resolve()), 'source entry escapes root')
        require(all(not (source / Path(*relative.parts[:i])).is_symlink()
                    for i in range(1, len(relative.parts) + 1)), 'source symlink refused')
        actual, size = digest(candidate)
        require(actual == row['sha256'] and size == row['size_bytes'], 'frozen source bytes differ')
    binary_sha, _ = digest(binary)
    require(binary_sha == expected_binary, 'frozen binary bytes differ')
    return dict(source_set_sha256=value['source_set_sha256'], source_files=len(rows),
                binary_sha256=binary_sha, sampler_sha256=digest(Path(__file__))[0])


def cpu_seconds(value):
    days = 0
    if '-' in value:
        prefix, value = value.split('-', 1)
        days = int(prefix)
    parts = value.split(':')
    require(len(parts) in (2, 3), 'CPU time shape differs')
    numbers = [float(part) for part in parts]
    require(days >= 0 and all(math.isfinite(number) and number >= 0 for number in numbers),
            'invalid CPU time refused')
    return days * 86400 + (numbers[0] * 3600 if len(parts) == 3 else 0) + numbers[-2] * 60 + numbers[-1]


def process_read(pid):
    require(type(pid) is int and 0 < pid < 2**31, 'explicit positive PID required')
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'time=',
                             '-o', 'rss=', '-o', 'args='], capture_output=True, text=True,
                            timeout=2, env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0 and 0 < len(result.stdout) <= MAX_LINE, 'process observation unavailable')
    pieces = result.stdout.strip().split(None, 7)
    require(len(pieces) == 8, 'process observation incomplete')
    rss = int(pieces[6])
    require(rss >= 0, 'negative RSS refused')
    # Do not retain argv, which can contain private paths or credentials.
    return dict(start=' '.join(pieces[:5]), command_sha256=hashlib.sha256(pieces[7].encode()).hexdigest(),
                cpu_seconds=cpu_seconds(pieces[5]), rss_bytes=rss * 1024)


class Process:
    def __init__(self, label, pid):
        require(LABEL.fullmatch(label) is not None, 'bounded public process label required')
        self.label, self.pid = label, pid
        first = process_read(pid)
        self.identity = (first['start'], first['command_sha256'])
        self.previous = None

    def sample(self):
        try:
            current = process_read(self.pid)
            require((current['start'], current['command_sha256']) == self.identity, 'process identity changed')
            at = time.monotonic()
            percent = None
            if self.previous is not None:
                before, old_cpu = self.previous
                require(at > before and current['cpu_seconds'] >= old_cpu, 'CPU observation regressed')
                percent = 100 * (current['cpu_seconds'] - old_cpu) / (at - before)
            self.previous = (at, current['cpu_seconds'])
            return dict(label=self.label, available=True, cpu_lifetime_seconds=current['cpu_seconds'],
                        cpu_one_core_percent=percent, rss_bytes=current['rss_bytes'])
        except (OSError, ValueError, subprocess.SubprocessError):
            self.previous = None
            return dict(label=self.label, available=False, reason='absent_changed_or_unavailable',
                        cpu_lifetime_seconds=None, cpu_one_core_percent=None, rss_bytes=None)


class Storage:
    def __init__(self, label, path):
        require(LABEL.fullmatch(label) is not None and not path.is_symlink() and path.is_dir(),
                'explicit regular storage directory required')
        self.label, self.path = label, path.resolve()
        stat = self.path.stat()
        self.identity = (stat.st_dev, stat.st_ino)

    def sample(self):
        entries = files = size = 0
        try:
            stat = self.path.stat()
            require(not self.path.is_symlink() and (stat.st_dev, stat.st_ino) == self.identity,
                    'storage root changed')
            pending = [self.path]
            while pending:
                with os.scandir(pending.pop()) as children:
                    for child in children:
                        entries += 1
                        require(entries <= MAX_ENTRIES and not child.is_symlink(), 'storage scan bound or symlink')
                        if child.is_dir(follow_symlinks=False):
                            pending.append(Path(child.path))
                        else:
                            require(child.is_file(follow_symlinks=False), 'nonregular storage entry')
                            files += 1
                            size += child.stat(follow_symlinks=False).st_size
            return dict(label=self.label, available=True, entries=entries, files=files,
                        logical_file_bytes=size, atomic_snapshot=False)
        except (OSError, ValueError):
            return dict(label=self.label, available=False, reason='changed_unavailable_or_scan_bound',
                        entries=None, files=None, logical_file_bytes=None, atomic_snapshot=False)


class Recorder:
    def __init__(self, output, binding, processes, stores, interval, *, exited_child_cpu=False):
        require(type(binding) is dict and set(binding) == {'source_set_sha256', 'source_files',
                'binary_sha256', 'sampler_sha256'} and type(binding['source_files']) is int
                and 0 < binding['source_files'] <= MAX_ENTRIES
                and all(type(binding[key]) is str and HEX.fullmatch(binding[key]) is not None
                        for key in ('source_set_sha256', 'binary_sha256', 'sampler_sha256')),
                'bounded public source binding required')
        require(1 <= interval <= 60 and len(processes) <= 32 and len(stores) <= 32
                and len(processes) + len(stores) > 0, 'bounded sampler scope required')
        require(type(exited_child_cpu) is bool,'explicit child CPU observation mode required')
        labels = [item.label for item in processes + stores]
        require(len(labels) == len(set(labels)), 'duplicate sample labels')
        require(all(not output.resolve().is_relative_to(item.path) for item in stores),
                'sample log cannot be inside observed storage')
        self.processes, self.stores, self.interval = processes, stores, interval
        self.exited_child_cpu,self.child_observers=exited_child_cpu,{}
        observer_binding={}
        if exited_child_cpu:
            from regional_ground_child_cpu import ExitedChildCpu
            self.child_cpu_factory=ExitedChildCpu
            observer_binding={'exited_child_cpu_sha256':digest(Path(__file__).with_name('regional_ground_child_cpu.py'))[0]}
        self.stream = None
        self.records, self.size, self.previous_digest, self.previous_end = 0, 0, None, None
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        self.stream = os.fdopen(fd, 'wb')
        try:
            directory_fd = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.write(dict(kind='header', format=CHILD_CPU_FORMAT if exited_child_cpu else FORMAT, binding=binding,
                observer_binding=observer_binding,
                interval_seconds=interval, fixture_only=True, live_rld=False,
                scope={'processes':[p.label for p in processes], 'storage':[s.label for s in stores]},
                measured={'explicit_process_cpu_rss':True, 'storage_metadata_samples':True,
                          'native_value':False, 'wire_bytes':False, 'fsync_latency':False,
                          'own_plus_exited_child_cpu_requested':exited_child_cpu,
                          'continuous_peaks':False, 'child_process_tree':False},
                qualification=False, native_authority=False))
        except BaseException:
            self.close()
            raise

    def write(self, value):
        require(self.records < MAX_RECORDS, 'sample record bound reached')
        record = dict(value, sequence=self.records, predecessor_sha256=self.previous_digest)
        line = canonical(record) + b'\n'
        require(len(line) <= MAX_LINE and self.size + len(line) <= MAX_LOG, 'sample output bound reached')
        self.stream.write(line)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.previous_digest = hashlib.sha256(line).hexdigest()
        self.records += 1
        self.size += len(line)

    def sample(self):
        labels=[item.label for item in self.processes+self.stores]
        require(len(self.processes)<=32 and len(self.stores)<=32 and len(labels)==len(set(labels))
                and all(LABEL.fullmatch(label) is not None for label in labels),'bounded registered sample scope required')
        start = time.monotonic()
        gap = None if self.previous_end is None else start - self.previous_end
        processes = [p.sample() for p in self.processes]
        stores = [s.sample() for s in self.stores]
        extra={}
        if self.exited_child_cpu:
            children=[]
            for process in self.processes:
                retained=self.child_observers.get(process.label)
                if retained is None:
                    require(len(self.child_observers)<32,'child CPU registration bound reached')
                    retained=(process,self.child_cpu_factory(process))
                    self.child_observers[process.label]=retained
                require(retained[0] is process,'child CPU label cannot adopt another process anchor')
                children.append(retained[1].sample())
            extra['own_plus_exited_child_cpu']=children
        end = time.monotonic()
        self.write(dict(kind='sample', monotonic_start=start, monotonic_end=end,
                        elapsed_sampling_seconds=end-start, unsampled_gap_seconds=gap,
                        interval_overrun=end-start > self.interval or (gap is not None and gap > self.interval * 1.5),
                        processes=processes, storage=stores, native_value_observation=None,**extra))
        self.previous_end = end

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--expected-binary', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--process', action='append', default=[], metavar='LABEL=PID')
    parser.add_argument('--storage', action='append', default=[], metavar='LABEL=DIRECTORY')
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--exited-child-cpu',action='store_true',
                        help='Request macOS parent plus exited-child CPU; live-child CPU/RSS remain incomplete')
    args = parser.parse_args()
    require(0 < args.duration <= 3600, 'bounded standalone observation duration required')
    binding = source_binding(args.manifest, args.source, args.binary, args.expected_source, args.expected_binary)
    processes = [Process(label, int(pid)) for label, pid in (item.split('=', 1) for item in args.process)]
    stores = [Storage(label, Path(path)) for label, path in (item.split('=', 1) for item in args.storage)]
    recorder = Recorder(args.output, binding, processes, stores, args.interval,exited_child_cpu=args.exited_child_cpu)
    started = time.monotonic()
    try:
        while True:
            before = time.monotonic()
            recorder.sample()
            remaining = args.duration - (time.monotonic() - started)
            if remaining <= 0:
                break
            time.sleep(min(remaining, max(0, args.interval - (time.monotonic() - before))))
        recorder.write(dict(kind='terminal', observation_completed=True,
                            elapsed_seconds=time.monotonic()-started, campaign_passed=None,
                            native_value_authenticated=False, qualification=False))
    finally:
        recorder.close()


if __name__ == '__main__':
    main()
