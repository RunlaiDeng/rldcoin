"""Independent original Python file/queue syscall oracle for explicit tests."""
import os
import stat
import re
import fcntl
from pathlib import Path
import interstellar_transfer as wire
from interstellar_frame_reference import inspect_frame
canonical=wire.canonical
decode_json=wire.decode_json
hex32=wire.hex32
MAX_FRAME=wire.MAX_FRAME
MAX_QUEUE_FILES=wire.MAX_QUEUE_FILES
MAX_QUEUE_BYTES=wire.MAX_QUEUE_BYTES

def read_file(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > limit:
        raise ValueError(f'unsafe or oversized file: {path}')
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'file grew beyond bound: {path}')
    return data


def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise ValueError(f'unsafe directory: {path}')


def write_new(path, data):
    ensure_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_same_or_new(path, data):
    try:
        write_new(path, data)
    except FileExistsError:
        if read_file(path, MAX_FRAME) != data:
            raise ValueError(f'existing evidence differs: {path}')


def queue_receive(root, data, source, destination):
    frame, _ = inspect_frame(data, source, destination)
    ensure_dir(root)
    lock_path = root / '.lock'
    if lock_path.exists() and lock_path.is_symlink():
        raise ValueError('unsafe queue lock')
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        files = [item for item in root.iterdir() if item.name != '.lock']
        if any(not re.fullmatch(r'[0-9a-f]{64}\.json', item.name) or item.is_symlink()
               or not item.is_file() for item in files):
            raise ValueError('unexpected queue file')
        target = root / (frame['message_id'] + '.json')
        if target.exists():
            if read_file(target, MAX_FRAME) != data:
                raise ValueError('queued message ID collision')
            return frame['message_id'], False
        if len(files) >= MAX_QUEUE_FILES or sum(item.stat().st_size for item in files) + len(data) > MAX_QUEUE_BYTES:
            raise ValueError('queue capacity reached; retain existing evidence')
        write_new(target, data)
        return frame['message_id'], True
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def queue_carry(root, message_id, output, source, destination):
    hex32(message_id, 'message ID')
    data = read_file(root / (message_id + '.json'), MAX_FRAME)
    frame, _ = inspect_frame(data, source, destination)
    if frame['message_id'] != message_id:
        raise ValueError('queue filename differs from frame')
    write_new(output, data)
    return frame
