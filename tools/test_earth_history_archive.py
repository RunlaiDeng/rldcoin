"""Archive byte/ancestry integrity only; synthetic records are not PoW evidence."""
import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import earth_history_archive as a

IDENTITY = dict(role='source', chain_id='1'*64, anchor='1'*64, source_commitment='2'*64)


def block(parent, height, nonce=0):
    return a.canonical({'header': {'chain_id': IDENTITY['chain_id'], 'parent': parent,
        'height': str(height), 'timestamp': 1000+height, 'target': 'f'*64, 'miner': '3'*64,
        'commands_root': '4'*64, 'state_root': '5'*64, 'nonce': str(nonce)}, 'commands': []})


def identifier(raw):
    return a.block_metadata(raw, 'source', IDENTITY['chain_id'])[0]


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)/'archive'
        self.archive = a.Archive(self.root, IDENTITY)
        self.first = block(IDENTITY['anchor'], 1)
        self.second = block(identifier(self.first), 2)

    def tearDown(self):
        self.archive.close()
        self.tmp.cleanup()

    def test_reopen_export_preserves_every_byte_and_fork(self):
        fork = block(identifier(self.first), 2, 1)
        self.archive.append([self.first, self.second, fork])
        self.archive.artifact('HEAD', identifier(self.second).encode())
        report = self.archive.verify()
        self.archive.close()
        self.archive = a.Archive(self.root)
        out = Path(self.tmp.name)/'restored'
        self.archive.export(out, report['commitment'])
        for raw in (self.first,self.second,fork):
            self.assertEqual((out/'blocks'/(identifier(raw)+'.json')).read_bytes(), raw)
        self.assertFalse(report['consensus_replay_verified'])
        self.assertFalse(report['active_node_capacity_upgraded'])

    def test_duplicate_is_idempotent_but_changed_bytes_rejected(self):
        self.assertEqual(self.archive.append([self.first, self.first]), 1)
        alternate=json.dumps(json.loads(self.first), indent=2).encode()
        with self.assertRaisesRegex(ValueError, 'different bytes'):
            self.archive.append([alternate])
        self.assertEqual(self.archive.verify()['records'], 1)

    def test_batch_failure_rolls_back_preceding_valid_insert(self):
        with self.assertRaisesRegex(ValueError, 'missing parent'):
            self.archive.append([self.first, block('9'*64, 3)])
        self.assertEqual(self.archive.verify()['records'], 0)

    def test_transaction_io_failure_rolls_back(self):
        def failing_reader():
            yield self.first
            raise OSError('simulated disk full/input failure')
        with self.assertRaises(OSError):
            self.archive.append(failing_reader())
        self.assertEqual(self.archive.verify()['records'], 0)

    def test_actual_sqlite_full_rolls_back(self):
        pages=self.archive.db.execute('PRAGMA page_count').fetchone()[0]
        self.archive.db.execute(f'PRAGMA max_page_count={pages}')
        large=json.loads(self.second); large['commands']=['x'*1048576]
        with self.assertRaisesRegex(sqlite3.OperationalError, 'full'):
            self.archive.append([self.first,a.canonical(large)])
        self.assertEqual(self.archive.verify()['records'], 0)

    def test_process_death_rolls_back_uncommitted_tail(self):
        self.archive.append([self.first]); pin=self.archive.verify()['commitment']
        self.archive.close()
        program='import sqlite3,os,sys; d=sqlite3.connect(sys.argv[1]); d.execute("BEGIN IMMEDIATE"); d.execute("DELETE FROM blocks"); os._exit(91)'
        p=subprocess.run([sys.executable,'-c',program,str(self.root/'history.sqlite3')],check=False)
        self.assertEqual(p.returncode,91)
        self.archive=a.Archive(self.root)
        self.assertEqual(self.archive.verify(pin)['records'],1)

    def test_missing_parent_wrong_height_and_chain(self):
        changed = json.loads(self.first); changed['header']['chain_id']='6'*64
        for raw in (block('9'*64,1), block(IDENTITY['anchor'],2), a.canonical(changed)):
            with self.assertRaises(ValueError): self.archive.append([raw])

    def test_changed_payload_detected(self):
        self.archive.append([self.first])
        with self.archive.db:
            self.archive.db.execute('UPDATE blocks SET raw=?', (self.first+b' ',))
        with self.assertRaisesRegex(ValueError, 'integrity mismatch'): self.archive.verify()

    def test_truncated_suffix_detected_by_pinned_commitment(self):
        self.archive.append([self.first,self.second])
        pin=self.archive.verify()['commitment']
        with self.archive.db: self.archive.db.execute('DELETE FROM blocks WHERE seq=2')
        with self.assertRaisesRegex(ValueError, 'pinned commitment'): self.archive.verify(pin)

    def test_manifest_and_head_tampering(self):
        self.archive.append([self.first])
        pin=self.archive.verify()['commitment']
        self.archive.artifact('HEAD',identifier(self.first).encode())
        with self.assertRaisesRegex(ValueError, 'pinned commitment'): self.archive.verify(pin)
        self.archive.artifact('HEAD',b'9'*64)
        with self.assertRaisesRegex(ValueError, 'HEAD block missing'): self.archive.verify()

    def test_symlink_and_missing_database_do_not_reinitialize(self):
        self.archive.close()
        path=self.root/'history.sqlite3'; path.rename(self.root/'saved.sqlite3')
        with self.assertRaisesRegex(ValueError, 'missing archive database'): a.Archive(self.root)
        path.symlink_to(self.root/'saved.sqlite3')
        with self.assertRaisesRegex(ValueError, 'missing archive database'): a.Archive(self.root)

    def test_concurrent_writer_rejected(self):
        with self.assertRaises(BlockingIOError): a.Archive(self.root)

    def test_export_never_overwrites_existing_directory(self):
        with self.assertRaises(FileExistsError):
            self.archive.export(Path(self.tmp.name), self.archive.verify()['commitment'])

    def test_duplicate_json_fields_and_bad_number_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'): a.decode(b'{"x":1,"x":2}')
        for value in (True,'01','-1',str(2**128)):
            with self.assertRaises(ValueError): a.number(value,128)


if __name__ == '__main__': unittest.main()
