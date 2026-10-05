#!/usr/bin/env python3
"""Bounded private logs and atomic, expiring observations for the node launcher."""
import fcntl
import json
import os
from pathlib import Path
import stat
import threading

LOG_BYTES = 2 * 1024 * 1024
LOG_BACKUPS = 3


def regular_file(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('runtime file must be a regular unshared file')
        os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def lock_state(state):
    handle = os.fdopen(regular_file(state / 'mining-supervisor.lock', os.O_CREAT | os.O_RDWR), 'a')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        handle.close()
        raise ValueError('another supervisor is already using this state')
    return handle


def snapshot(path, value):
    pending = Path(str(path) + '.pending')
    if pending.exists() or pending.is_symlink():
        pending.unlink()  # only our fixed temporary filename, never its target
    fd = regular_file(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    with os.fdopen(fd, 'w') as file:
        json.dump(value, file, sort_keys=True, allow_nan=False)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    os.replace(pending, path)


class BoundedLog:
    def __init__(self, path, limit=LOG_BYTES, backups=LOG_BACKUPS):
        self.path, self.limit, self.backups = path, limit, backups
        self.error, self.thread = None, None
        for name in [path, *(Path(str(path) + f'.{n}') for n in range(1, backups + 1))]:
            if name.exists() or name.is_symlink():
                fd = regular_file(name, os.O_RDONLY)
                info = os.fstat(fd)
                os.close(fd)
                if info.st_size > limit:
                    raise ValueError('existing log exceeds size limit; archive it outside operator-logs first')
        self.file = os.fdopen(regular_file(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND), 'ab', buffering=0)
        self.size = self.file.tell()
        if self.size > self.limit:
            # Existing oversized logs came from older versions. Do not quietly
            # delete that evidence or let it defeat the new disk bound.
            self.file.close()
            raise ValueError('existing log exceeds 2 MiB; archive it outside operator-logs first')

    def rotate(self):
        self.file.close()
        for number in range(self.backups, 0, -1):
            previous = self.path if number == 1 else Path(str(self.path) + f'.{number - 1}')
            if previous.exists():
                os.replace(previous, Path(str(self.path) + f'.{number}'))
        self.file = os.fdopen(regular_file(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY), 'ab', buffering=0)
        self.size = 0

    def write(self, data):
        while data:
            if self.size >= self.limit:
                self.rotate()
            part, data = data[:self.limit - self.size], data[self.limit - self.size:]
            self.file.write(part)
            self.size += len(part)

    def capture(self, pipe):
        def pump():
            try:
                with pipe:
                    while chunk := pipe.read1(8192):
                        self.write(chunk)
            except Exception as error:
                self.error = str(error)
            finally:
                self.file.close()
        self.thread = threading.Thread(target=pump, daemon=True)
        self.thread.start()

    def close(self):
        if self.thread:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self.error = 'log reader did not stop'
        else:
            self.file.close()
