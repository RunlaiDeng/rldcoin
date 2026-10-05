#!/usr/bin/env python3
"""Bounded-memory, lossless public block archive; not a consensus validator.

SQLite transactions preserve complete block bytes and forks. Exported history
must be replayed by the pinned node. This does not remove its 100,000-entry cap,
replace wallet backups, authorize pruning, or select a branch by itself.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path

FORMAT = 'RLD-EARTH-HISTORY-ARCHIVE-1'
MAX_BLOCK_BYTES = 8 * 1024 * 1024
ARTIFACTS = {'anchor.json', 'identity.json', 'HEAD', 'FINALITY', 'CHECKPOINT', 'HALTED'}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, why):
    if not ok:
        raise ValueError(why)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def decode(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read(path, limit=MAX_BLOCK_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'unsafe/oversized archive input')
        data = f.read(limit + 1)
    require(len(data) <= limit, 'archive input grew beyond bound')
    return data


def number(value, bits):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,38}', value), 'noncanonical number')
    out = int(value)
    require(out < 2**bits, 'integer overflow')
    return out


def hash_bytes(value):
    require(isinstance(value, str) and HEX.fullmatch(value), 'invalid hash')
    return bytes.fromhex(value)


def block_metadata(raw, role, chain_id):
    require(0 < len(raw) <= MAX_BLOCK_BYTES, 'block byte bound')
    block = decode(raw)
    require(isinstance(block, dict) and set(block) == {'header', 'commands'}, 'block fields differ')
    h = block['header']
    require(set(h) == {'chain_id','parent','height','timestamp','target','miner','commands_root','state_root','nonce'},
            'header fields differ')
    require(h['chain_id'] == chain_id, 'archive chain differs')
    height = number(h['height'], 128)
    require(height > 0 and type(h['timestamp']) is int and 0 <= h['timestamp'] < 2**64, 'invalid block time/height')
    domain = {'source': b'RLD-EARTH-UNIFIED-SUCCESSOR-HEADER\0',
              'destination': b'RLD-EARTH-DESTINATION-POW-HEADER\0'}[role]
    header = (domain + hash_bytes(h['chain_id']) + hash_bytes(h['parent']) + height.to_bytes(16, 'big')
              + h['timestamp'].to_bytes(8, 'big') + hash_bytes(h['target']) + hash_bytes(h['miner'])
              + hash_bytes(h['commands_root']) + hash_bytes(h['state_root'])
              + number(h['nonce'], 128).to_bytes(16, 'big'))
    identifier = digest(hashlib.sha256(header).digest())
    return identifier, h['parent'], f'{height:039d}', digest(raw)


class Archive:
    def __init__(self, root, identity=None):
        self.root = Path(root)
        self.db = None
        self.lock = None
        if identity is not None:
            require(set(identity) == {'role','chain_id','anchor','source_commitment'}, 'identity fields differ')
            require(identity['role'] in ('source','destination'), 'unknown archive role')
            for key in ('chain_id','anchor','source_commitment'):
                hash_bytes(identity[key])
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        require(self.root.is_dir() and not self.root.is_symlink(), 'unsafe archive directory')
        try:
            self.lock = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            dbpath = self.root / 'history.sqlite3'
            if identity is None:
                require(dbpath.is_file() and not dbpath.is_symlink(), 'missing archive database')
            else:
                require(not dbpath.exists(), 'archive already initialized')
            self.db = sqlite3.connect(dbpath, timeout=1)
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA cache_size=-8192')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=WAL')
            if identity is not None:
                with self.db:
                    self.db.executescript('''
                      CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                      CREATE TABLE blocks (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                        parent TEXT NOT NULL, height TEXT NOT NULL, sha256 TEXT NOT NULL,
                        raw BLOB NOT NULL, rolling TEXT NOT NULL);
                      CREATE INDEX replay_order ON blocks(height,id);
                      CREATE TABLE artifacts (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, raw BLOB NOT NULL);
                    ''')
                    self.db.executemany('INSERT INTO meta VALUES (?,?)',
                        [('format', FORMAT), ('identity', canonical(identity))])
            require(self.db.execute('SELECT value FROM meta WHERE key=?', ('format',)).fetchone() == (FORMAT,),
                    'archive format differs')
            self.identity = decode(self.db.execute('SELECT value FROM meta WHERE key=?', ('identity',)).fetchone()[0])
            if identity is not None:
                require(self.identity == identity, 'archive identity differs')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def seed(self):
        return digest(FORMAT.encode() + b'\0' + canonical(self.identity))

    def append(self, blocks):
        """One bounded caller-supplied batch is atomic, including on disk-full."""
        count = 0
        with self.db:
            row = self.db.execute('SELECT seq,rolling FROM blocks ORDER BY seq DESC LIMIT 1').fetchone()
            seq, rolling = row if row else (0, self.seed())
            for raw in blocks:
                identifier, parent, height, sha = block_metadata(raw, self.identity['role'], self.identity['chain_id'])
                previous = self.db.execute('SELECT sha256,raw FROM blocks WHERE id=?', (identifier,)).fetchone()
                if previous is not None:
                    require(previous == (sha, raw), 'same block ID has different bytes')
                    continue
                predecessor = self.db.execute('SELECT height FROM blocks WHERE id=?', (parent,)).fetchone()
                require((parent == self.identity['anchor'] and int(height) == 1)
                        or (predecessor is not None and int(predecessor[0]) + 1 == int(height)),
                        'missing parent or inconsistent height')
                seq += 1
                rolling = digest(bytes.fromhex(rolling) + canonical([seq,identifier,parent,height,sha]))
                self.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?,?)',
                                (seq,identifier,parent,height,sha,raw,rolling))
                count += 1
        return count

    def artifact(self, name, raw):
        require(name in ARTIFACTS and len(raw) <= 64*1024*1024, 'artifact bound/name')
        with self.db:
            self.db.execute('INSERT INTO artifacts VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET sha256=excluded.sha256,raw=excluded.raw',
                            (name,digest(raw),raw))

    def verify(self, expected_commitment=None):
        require(self.db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SQLite integrity failure')
        rolling, count, total = self.seed(), 0, 0
        for seq, identifier, parent, height, sha, raw, stored in self.db.execute('SELECT * FROM blocks ORDER BY seq'):
            count += 1
            require(seq == count, 'archive sequence gap')
            require(block_metadata(raw, self.identity['role'], self.identity['chain_id']) == (identifier,parent,height,sha),
                    'block integrity mismatch')
            predecessor = self.db.execute('SELECT height,seq FROM blocks WHERE id=?', (parent,)).fetchone()
            require((parent == self.identity['anchor'] and int(height) == 1)
                    or (predecessor is not None and int(predecessor[0])+1 == int(height) and predecessor[1] < seq),
                    'archive ancestry mismatch')
            rolling = digest(bytes.fromhex(rolling) + canonical([seq,identifier,parent,height,sha]))
            require(rolling == stored, 'archive rolling digest mismatch')
            total += len(raw)
        artifacts = {}
        for name, sha, raw in self.db.execute('SELECT * FROM artifacts ORDER BY name'):
            require(name in ARTIFACTS and digest(raw) == sha, 'archive artifact integrity mismatch')
            artifacts[name] = sha
            if name == 'HEAD':
                tip = raw.decode()
                require(tip == self.identity['anchor'] or self.db.execute('SELECT 1 FROM blocks WHERE id=?', (tip,)).fetchone(),
                        'archive HEAD block missing')
        report = {'format': FORMAT, 'identity': self.identity, 'records': count, 'payload_bytes': total,
                  'rolling_sha256': rolling, 'artifacts': artifacts}
        commitment = digest(canonical(report))
        if expected_commitment is not None:
            require(commitment == expected_commitment, 'archive does not match pinned commitment')
        return {**report, 'commitment': commitment, 'consensus_replay_verified': False,
                'active_node_capacity_upgraded': False}

    def export(self, output, expected_commitment):
        report = self.verify(expected_commitment)
        output = Path(output)
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        (output / 'blocks').mkdir(mode=0o700)
        for identifier, raw in self.db.execute('SELECT id,raw FROM blocks ORDER BY height,id'):
            with (output / 'blocks' / (identifier + '.json')).open('xb') as handle:
                handle.write(raw)
        for name, raw in self.db.execute('SELECT name,raw FROM artifacts'):
            with (output / name).open('xb') as handle:
                handle.write(raw)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    pack = commands.add_parser('pack')
    pack.add_argument('--input', type=Path, required=True, help='quiescent public node-history copy')
    pack.add_argument('--identity', type=Path, required=True)
    pack.add_argument('--archive', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--archive', type=Path, required=True)
    verify.add_argument('--commitment', required=True)
    export = commands.add_parser('export')
    export.add_argument('--archive', type=Path, required=True)
    export.add_argument('--commitment', required=True)
    export.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'pack':
        identity = decode(read(args.identity, 4096))
        with Archive(args.archive, identity) as archive:
            # Disk-backed sort index avoids retaining decoded history in RAM.
            archive.db.execute('PRAGMA temp_store=FILE')
            archive.db.execute('CREATE TEMP TABLE scan(height TEXT,id TEXT,path TEXT)')
            with archive.db:
                for path in (args.input / 'blocks').iterdir():
                    if path.name.endswith('.pending'):
                        continue
                    raw = read(path)
                    identifier, _, height, _ = block_metadata(raw, identity['role'], identity['chain_id'])
                    require(path.name == identifier + '.json', 'input block filename differs')
                    archive.db.execute('INSERT INTO scan VALUES (?,?,?)', (height,identifier,str(path)))
            cursor = archive.db.execute('SELECT path FROM scan ORDER BY height,id')
            while batch := cursor.fetchmany(256):
                archive.append(read(Path(row[0])) for row in batch)
            for name in ARTIFACTS:
                path = args.input / name
                if path.exists():
                    archive.artifact(name, read(path, 64*1024*1024))
            report = archive.verify()
    else:
        with Archive(args.archive) as archive:
            report = (archive.export(args.output, args.commitment) if args.action == 'export'
                      else archive.verify(args.commitment))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
