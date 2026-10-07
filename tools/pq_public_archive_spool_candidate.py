"""Owned bounded public-packet spool. Durable byte receipt only; no ledger rights.

A caller supplies the independently retained manifest root on every cold open.
Failed staging residues remain, count toward capacity, and are never pruned here.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import stat
import uuid

import pq_public_archive_candidate as archive
import pq_public_carriage_candidate as carriage

MAX_FILES = 256
MAX_STORE_BYTES = MAX_FILES * carriage.MAX_PACKET_BYTES + 64


class PublicArchiveSpool:
    def __init__(self, directory: Path, expected_manifest: bytes, *, create: bool = False):
        if not isinstance(expected_manifest, bytes) or len(expected_manifest) != 64:
            raise ValueError('independently retained manifest SHA512 required')
        self.expected = expected_manifest
        self.fd = None
        self.lock = None
        try:
            self.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self.fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('owned private spool directory required')
            if create:
                if os.listdir(self.fd):
                    raise ValueError('fresh empty public spool required')
                for leaf, raw in (('expected-root', self.expected), ('lock', b'')):
                    fd = self._new(leaf)
                    try:
                        self._write(fd, raw)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.fsync(self.fd)
            self.lock = self._open('lock')
            if os.fstat(self.lock).st_size != 0:
                raise ValueError('spool lock file differs')
            self._binding()
            self._inventory()
        except Exception:
            self.close()
            raise

    def close(self):
        for field in ('lock', 'fd'):
            fd = getattr(self, field, None)
            if fd is not None:
                os.close(fd)
                setattr(self, field, None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _open(self, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > carriage.MAX_PACKET_BYTES):
            os.close(fd)
            raise ValueError('bounded owned private regular packet required')
        return fd

    def _new(self, leaf):
        return os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=self.fd)

    @staticmethod
    def _write(fd, raw):
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise OSError('incomplete packet write')
            offset += count

    def _read(self, leaf):
        fd = self._open(leaf)
        try:
            raw = bytearray()
            while len(raw) <= carriage.MAX_PACKET_BYTES:
                chunk = os.read(fd, carriage.MAX_PACKET_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > carriage.MAX_PACKET_BYTES:
                raise ValueError('packet grew beyond bound')
            return bytes(raw)
        finally:
            os.close(fd)

    def _binding(self):
        if not hmac.compare_digest(self._read('expected-root'), self.expected):
            raise ValueError('caller expected root differs; never recover trust from local state')

    def _inventory(self):
        names = []
        total = 0
        with os.scandir(self.fd) as entries:
            for item in entries:
                info = item.stat(follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_size > carriage.MAX_PACKET_BYTES):
                    raise ValueError('spool has unsafe or oversized retained file')
                names.append(item.name)
                total += info.st_size
                if len(names) > MAX_FILES or total > MAX_STORE_BYTES:
                    raise ValueError('all retained spool residue counts toward capacity')
        return names, total

    @contextmanager
    def _locked(self):
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            self._binding()
            yield
        finally:
            fcntl.flock(self.lock, fcntl.LOCK_UN)

    def _manifest(self):
        packet = self._read('manifest.packet')
        raw = carriage.reassemble_public_bytes((packet,), self.expected)
        return archive.decode_manifest(raw)

    def accept(self, packet: bytes) -> dict:
        size, count, index, digest, _ = carriage.parse_public_fragment(packet)
        with self._locked():
            names, total = self._inventory()
            if hmac.compare_digest(digest, self.expected):
                if count != 1 or index != 0:
                    raise ValueError('bounded archive manifest fits exactly one packet')
                archive.decode_manifest(carriage.reassemble_public_bytes((packet,), self.expected))
                leaf = 'manifest.packet'
            else:
                try:
                    records = self._manifest()
                except FileNotFoundError:
                    raise carriage.IncompletePublicCarriage('trusted manifest must arrive before entry custody') from None
                if (size, digest) not in records:
                    raise ValueError('packet not bound by retained ordered manifest')
                leaf = 'part-' + digest.hex() + '-' + str(index)
            if leaf in names:
                if self._read(leaf) != packet:
                    raise ValueError('existing custody bytes differ; retain both caller input and old evidence')
                fd = self._open(leaf)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(self.fd)
            else:
                if len(names) + 2 > MAX_FILES or total + 2 * len(packet) > MAX_STORE_BYTES:
                    raise ValueError('staging plus final custody exceeds retained capacity')
                partial = 'partial-' + uuid.uuid4().hex
                fd = self._new(partial)
                try:
                    self._write(fd, packet)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                # Link publishes a complete immutable file without replacing any old bytes.
                os.link(partial, leaf, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                os.fsync(self.fd)
                # Only this operation's successfully committed temporary link is removed.
                # Any earlier failure residue remains and is charged on every operation.
                os.unlink(partial, dir_fd=self.fd)
                os.fsync(self.fd)
            return dict(packet_sha512=hashlib.sha512(packet).hexdigest(), durable_bytes=True,
                        monetary_authority=False, installed=False)

    def complete(self) -> tuple[bytes, ...]:
        with self._locked():
            names, _ = self._inventory()
            try:
                manifest = self._read('manifest.packet')
            except FileNotFoundError:
                raise carriage.IncompletePublicCarriage('archive manifest unavailable') from None
            parts = tuple(self._read(name) for name in sorted(names) if name.startswith('part-'))
            return archive.reassemble_archive((manifest,), parts, self.expected)


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expected-root', required=True, help='independently retained manifest SHA512, canonical128hex')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    accept = sub.add_parser('accept')
    accept.add_argument('packet', type=Path, nargs='+')
    complete = sub.add_parser('complete')
    complete.add_argument('--output', type=Path, required=True, help='fresh public-entry directory; never overwrite')
    args = parser.parse_args()
    if len(args.expected_root) != 128 or any(c not in '0123456789abcdef' for c in args.expected_root):
        raise ValueError('independent root requires canonical SHA512')
    expected = bytes.fromhex(args.expected_root)
    if args.command == 'init':
        args.root.mkdir(mode=0o700)
    with PublicArchiveSpool(args.root, expected, create=args.command == 'init') as store:
        if args.command == 'accept':
            count = 0
            for path in args.packet:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(fd, 'rb') as file:
                    info = os.fstat(file.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or info.st_mode & 0o077 or info.st_size > carriage.MAX_PACKET_BYTES):
                        raise ValueError('owned bounded packet input required')
                    packet = file.read(carriage.MAX_PACKET_BYTES + 1)
                store.accept(packet)
                count += 1
            print(json.dumps(dict(durable_packet_count=count, monetary_authority=False, installed=False)))
        elif args.command == 'complete':
            entries = store.complete()  # No output directory/files before complete root verification.
            args.output.mkdir(mode=0o700)
            for index, raw in enumerate(entries):
                path = args.output / f'renewal-{index:03}-public.json'
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    store._write(fd, raw)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            fd = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            print(json.dumps(dict(complete_entries=len(entries), bytes=sum(map(len, entries)),
                                  monetary_authority=False, installed=False)))
        else:
            print(json.dumps(dict(fresh_public_spool=True, monetary_authority=False, installed=False)))


if __name__ == '__main__':
    main()
