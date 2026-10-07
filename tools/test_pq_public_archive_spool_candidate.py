import hashlib
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

import pq_public_archive_candidate as archive
import pq_public_carriage_candidate as carriage
import pq_public_archive_spool_candidate as spool


class PublicSpoolTests(unittest.TestCase):
    def fixture(self):
        entries = (b'a' * 24707, b'b' * 24707)
        manifest, parts = archive.split_archive(entries)
        return entries, manifest[0], parts, hashlib.sha512(archive.encode_manifest(entries)).digest()

    def test_reverse_incremental_cold_restart_and_duplicate_exact_custody(self):
        entries, manifest, parts, expected = self.fixture()
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t)
            with spool.PublicArchiveSpool(directory, expected, create=True) as store:
                with self.assertRaises(carriage.IncompletePublicCarriage):
                    store.accept(parts[0])
                self.assertFalse(store.accept(manifest)['monetary_authority'])
                for packet in parts[:2]:
                    store.accept(packet)
            with spool.PublicArchiveSpool(directory, expected) as cold:
                with self.assertRaises(carriage.IncompletePublicCarriage):
                    cold.complete()
                for packet in parts[2:][::-1]:
                    cold.accept(packet)
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                self.assertTrue(cold.accept(parts[0])['durable_bytes'])
                self.assertEqual(cold.complete(), entries)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)

    def test_real_directory_sync_failure_releases_no_receipt_then_cold_retry(self):
        _, manifest, _, expected = self.fixture()
        original = os.fsync
        def refuse_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('fixture directory sync unavailable')
            return original(fd)
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t)
            with spool.PublicArchiveSpool(directory, expected, create=True) as store:
                with patch.object(spool.os, 'fsync', side_effect=refuse_directory):
                    with self.assertRaisesRegex(OSError, 'directory sync unavailable'):
                        store.accept(manifest)
            residues = {p.name: p.read_bytes() for p in directory.iterdir() if p.name.startswith('partial-')}
            self.assertEqual(len(residues), 1)
            with spool.PublicArchiveSpool(directory, expected) as cold:
                self.assertTrue(cold.accept(manifest)['durable_bytes'])
            self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir() if p.name.startswith('partial-')}, residues)

    def test_real_write_failure_keeps_residue_and_never_publishes_packet(self):
        _, manifest, _, expected = self.fixture()
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t)
            with spool.PublicArchiveSpool(directory, expected, create=True) as store:
                with patch.object(store, '_write', side_effect=OSError('fixture write unavailable')):
                    with self.assertRaisesRegex(OSError, 'write unavailable'):
                        store.accept(manifest)
            self.assertFalse((directory/'manifest.packet').exists())
            self.assertEqual(len(list(directory.glob('partial-*'))), 1)

    def test_wrong_caller_root_foreign_input_symlink_and_capacity_refuse(self):
        _, manifest, parts, expected = self.fixture()
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t)
            with spool.PublicArchiveSpool(directory, expected, create=True) as store:
                store.accept(manifest)
                foreign = carriage.split_public_bytes(b'x')[0]
                with self.assertRaises(ValueError):
                    store.accept(foreign)
                (directory/'foreign-link').symlink_to(directory/'expected-root')
                with self.assertRaises(ValueError):
                    store.accept(parts[0])
                (directory/'foreign-link').unlink()  # This test's own deliberately created symlink only.
                with patch.object(spool, 'MAX_FILES', 3):
                    with self.assertRaises(ValueError):
                        store.accept(parts[0])
            with self.assertRaises(ValueError):
                spool.PublicArchiveSpool(directory, b'0'*64)


if __name__ == '__main__':
    unittest.main()
