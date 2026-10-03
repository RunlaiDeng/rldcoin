import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import source_snapshot as source


class SourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "Cargo.toml").write_text('[package]\nname="fixture"\n')
        (self.root / "run.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.root / "run.sh").chmod(0o755)
        self.output = Path(self.temp.name) / "snapshot"

    def capture(self):
        return source.create(self.root, self.output)

    def test_snapshot_is_complete_stable_and_independent_of_working_tree(self):
        (self.root / ".gitignore").write_text("target/\n.env\n")
        (self.root / "target").mkdir()
        (self.root / "target" / "discard").write_text("generated")
        (self.root / ".env").write_text("local-only")
        first = self.capture()
        second = source.create(self.root, Path(self.temp.name) / "second")
        self.assertEqual(first, second)
        (self.root / "Cargo.toml").write_text("changed after capture")
        self.assertEqual(first, source.verify(self.output, first["manifest_sha256"]))
        self.assertFalse((self.output / "tree/.env").exists())
        self.assertFalse((self.output / "tree/target").exists())
        with self.assertRaises(ValueError):
            self.capture()

    def test_secret_detection_does_not_save_or_echo_content(self):
        marker = "ghp_" + "A" * 36
        (self.root / "settings.txt").write_text(marker)
        with self.assertRaises(ValueError) as failure:
            self.capture()
        self.assertNotIn(marker, str(failure.exception))
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.output.parent.glob(".source-snapshot-*")))

    def test_sensitive_paths_and_symlinks_fail_before_capture(self):
        for name in [".env.production", "wallet-main.json", "test.key"]:
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("private")
                with self.assertRaises(ValueError):
                    self.capture()
                path.unlink()
        (self.root / "alias").symlink_to(self.root / "Cargo.toml")
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.output.exists())

    def test_missing_extra_changed_files_modes_and_directory_links_rejected(self):
        self.capture()
        tree = self.output / "tree"
        original = (tree / "Cargo.toml").read_bytes()
        (tree / "Cargo.toml").write_bytes(original + b"tamper")
        with self.assertRaises(ValueError):
            source.verify(self.output)
        (tree / "Cargo.toml").unlink()
        with self.assertRaises(OSError):
            source.verify(self.output)
        (tree / "Cargo.toml").write_bytes(original)
        (tree / "extra").write_text("extra")
        with self.assertRaises(ValueError):
            source.verify(self.output)
        (tree / "extra").unlink()
        (tree / "run.sh").chmod(0o644)
        with self.assertRaises(ValueError):
            source.verify(self.output)
        (tree / "run.sh").chmod(0o755)
        (tree / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            source.verify(self.output)

    def test_manifest_pin_duplicates_traversal_and_size_limits(self):
        self.capture()
        manifest = self.output / "manifest.json"
        original = manifest.read_bytes()
        with self.assertRaises(ValueError):
            source.verify(self.output, "0" * 64)
        manifest.write_bytes(original.replace(b'{"files":', b'{"format":"duplicate","files":', 1))
        with self.assertRaises(ValueError):
            source.verify(self.output)
        for mutate in [
            lambda rows: rows[0].update(path="../outside"),
            lambda rows: rows[0].update(size_bytes=source.MAX_FILE_BYTES + 1),
            lambda rows: rows.append(rows[0]),
        ]:
            document = json.loads(original)
            mutate(document["files"])
            document["tree_sha256"] = hashlib.sha256(source.canonical(document["files"])).hexdigest()
            manifest.write_bytes(source.canonical(document))
            with self.assertRaises(ValueError):
                source.verify(self.output)


if __name__ == "__main__":
    unittest.main()
