#!/usr/bin/env python3
"""Retain and verify exact local source. Hashes are not release authorization."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile

FORMAT = "RLD-SOURCE-SNAPSHOT-V1"
MAX_FILES = 10_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
CACHE_PARTS = {".git", "target", "node_modules", ".next", "__pycache__"}
PRIVATE_PARTS = {"keys", "state", "logs", "run", "data", "m0-mainnet-data"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})"),
    re.compile(rb'"(?:secret_key|private_key|mnemonic|seed_phrase|password|api_key)"\s*:\s*"[^"\n]{8,}"'),
)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_path(name):
    require(isinstance(name, str), "source path must be text")
    path = PurePosixPath(name)
    require(bool(name) and not path.is_absolute() and path.as_posix() == name
            and all(p not in {".", ".."} for p in path.parts)
            and not any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in name),
            "unsafe source path")
    require(not (set(path.parts) & (CACHE_PARTS | PRIVATE_PARTS)), "excluded source path: " + name)
    require(not path.name.startswith(".env") and not (path.name.startswith("wallet") and path.suffix == ".json")
            and path.suffix.lower() not in {".pem", ".key", ".p12", ".pfx", ".pyc", ".log", ".sqlite"},
            "sensitive source path: " + name)
    return path


def regular(root, name):
    path = root
    for part in checked_path(name).parts:
        path /= part
        require(not path.is_symlink(), "symlink in source path: " + name)
    require(stat.S_ISREG(path.stat(follow_symlinks=False).st_mode), "nonregular source: " + name)
    return path


def digest_file(path, output=None, scan=False):
    digest = hashlib.sha256()
    size = 0
    tail = b""
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            require(size <= MAX_FILE_BYTES, "source file size limit exceeded")
            if scan:
                require(not any(p.search(tail + block) for p in SECRET_PATTERNS),
                        "possible credential material; source snapshot refused (content redacted)")
                tail = block[-4096:]
            digest.update(block)
            if output is not None:
                output.write(block)
    return digest.hexdigest(), size


def git(root, *args, optional=False):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if optional and result.returncode:
        return None
    require(result.returncode == 0, "source inventory requires a Git worktree")
    return result.stdout


def source_paths(root):
    raw = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths = sorted(set(name.decode("utf-8") for name in raw.split(b"\0") if name))
    paths = [name for name in paths if not (set(PurePosixPath(name).parts) & CACHE_PARTS)
             and not name.endswith(".pyc")]
    require(0 < len(paths) <= MAX_FILES, "source file count outside bounds")
    for name in paths:
        checked_path(name)
    return paths


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create(root, destination):
    root = root.resolve(strict=True)
    require(not destination.exists() and not destination.is_symlink(), "refusing to overwrite source snapshot")
    # Take the inventory before creating staging files inside a workspace.
    names = source_paths(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".source-snapshot-", dir=destination.parent))
    try:
        (temporary / "tree").mkdir()
        rows = []
        total = 0
        for name in names:
            source = regular(root, name)
            target = temporary / "tree" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = "0755" if source.stat().st_mode & 0o111 else "0644"
            with target.open("xb") as output:
                digest, size = digest_file(source, output, scan=True)
                total += size
                require(total <= MAX_TOTAL_BYTES, "source total size limit exceeded")
                output.flush()
                os.fsync(output.fileno())
            target.chmod(int(mode, 8))
            rows.append(dict(path=name, sha256=digest, size_bytes=size, mode=mode))
        commit = git(root, "rev-parse", "--verify", "HEAD", optional=True)
        document = dict(format=FORMAT, scope="LOCAL_CANDIDATE_NOT_RELEASE_AUTHORIZATION",
                        git_commit=commit.decode().strip() if commit else "UNCOMMITTED",
                        git_tree="DIRTY" if git(root, "status", "--porcelain", "--untracked-files=normal") else "CLEAN",
                        tree_sha256=hashlib.sha256(canonical(rows)).hexdigest(), files=rows)
        with (temporary / "manifest.json").open("xb") as output:
            output.write(canonical(document))
            output.flush()
            os.fsync(output.fileno())
        verify(temporary)
        for directory, _, _ in os.walk(temporary, topdown=False):
            fsync_directory(directory)
        require(not destination.exists(), "source snapshot destination appeared during capture")
        temporary.rename(destination)
        fsync_directory(destination.parent)
        return summary(destination, document)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def summary(snapshot, document):
    return dict(format=FORMAT, manifest_sha256=digest_file(snapshot / "manifest.json")[0],
                tree_sha256=document["tree_sha256"], file_count=len(document["files"]),
                total_bytes=sum(row["size_bytes"] for row in document["files"]))


def verify(snapshot, expected_manifest=None):
    require(snapshot.is_dir() and not snapshot.is_symlink(), "missing or unsafe source snapshot")
    require(sorted(p.name for p in snapshot.iterdir()) == ["manifest.json", "tree"], "unexpected snapshot entries")
    manifest = snapshot / "manifest.json"
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= MAX_MANIFEST_BYTES,
            "missing, unsafe or oversized source manifest")
    data = manifest.read_bytes()
    if expected_manifest is not None:
        require(re.fullmatch("[0-9a-f]{64}", expected_manifest) is not None
                and hashlib.sha256(data).hexdigest() == expected_manifest, "source manifest binding differs")
    document = json.loads(data)
    require(canonical(document) == data, "noncanonical or duplicate-key source manifest")
    require(set(document) == {"format", "scope", "git_commit", "git_tree", "tree_sha256", "files"}
            and document["format"] == FORMAT and document["scope"] == "LOCAL_CANDIDATE_NOT_RELEASE_AUTHORIZATION"
            and (document["git_commit"] == "UNCOMMITTED" or re.fullmatch("[0-9a-f]{40}", document["git_commit"]))
            and document["git_tree"] in {"CLEAN", "DIRTY"}, "invalid source manifest context")
    rows = document["files"]
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_FILES, "invalid source file count")
    require(hashlib.sha256(canonical(rows)).hexdigest() == document["tree_sha256"], "source tree digest differs")
    tree = snapshot / "tree"
    require(tree.is_dir() and not tree.is_symlink(), "unsafe source tree")
    names = []
    total = 0
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "sha256", "size_bytes", "mode"}, "invalid source record")
        name = row["path"]
        source = regular(tree, name)
        require(row["mode"] in {"0644", "0755"} and stat.S_IMODE(source.stat().st_mode) == int(row["mode"], 8),
                "source mode differs: " + name)
        require(type(row["size_bytes"]) is int and 0 <= row["size_bytes"] <= MAX_FILE_BYTES,
                "invalid source length")
        digest, size = digest_file(source)
        require(digest == row["sha256"] and size == row["size_bytes"], "source hash or size differs: " + name)
        total += size
        require(total <= MAX_TOTAL_BYTES, "source total size limit exceeded")
        names.append(name)
    require(names == sorted(set(names)), "duplicate or unordered source path")
    actual = []
    for directory, children, files in os.walk(tree, followlinks=False):
        for name in children:
            require(not (Path(directory) / name).is_symlink(), "source directory symlink")
        for name in files:
            actual.append((Path(directory) / name).relative_to(tree).as_posix())
    require(sorted(actual) == names, "source inventory does not exactly cover retained files")
    return summary(snapshot, document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("create")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--snapshot", type=Path, required=True)
    check.add_argument("--manifest-sha256")
    args = parser.parse_args()
    try:
        result = create(args.root, args.output) if args.command == "create" else verify(args.snapshot, args.manifest_sha256)
    except (ValueError, OSError, TypeError, KeyError) as error:
        print("source evidence rejected: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
