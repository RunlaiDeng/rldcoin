#!/usr/bin/env python3
"""Run only the public, stdlib source-commitment tests from a fixed export.

This is an environment/source transfer check, not protocol qualification.
No installation, network, private fixtures or production service access.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("full Git commit required")
    if not re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256):
        parser.error("SHA-256 required")
    source = args.source.resolve(strict=True)
    names = ["test_verify.py", "verify.py", "verify_cli.py"]
    directory = source / "tools/implementation-source"
    if directory.is_symlink() or directory.resolve(strict=True) != directory:
        parser.error("source path must contain no symlink")
    if sorted(p.name for p in directory.iterdir()) != names:
        parser.error("expected exactly the three reviewed source files")
    hashes = {}
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            parser.error("only ordinary source files allowed")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    evidence = args.evidence.absolute()
    evidence.parent.resolve(strict=True)
    evidence.mkdir(exist_ok=False)
    work = evidence / "work"
    work.mkdir()
    command = [sys.executable, "-B", "-m", "unittest", "discover", "-s",
               "tools/implementation-source", "-v"]
    env = os.environ.copy()
    env["TMPDIR"] = str(work)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    before = time.monotonic()
    timed_out = False
    with (evidence / "test.log").open("wb") as log:
        try:
            result = subprocess.run(command, cwd=source, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=30)
            code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            code = 124
    report = {
        "format": "RLD-HYBRID-SOURCE-SMOKE-1", "started_at_utc": started,
        "source_commit": args.commit, "source_archive_sha256": args.archive_sha256,
        "source_files_sha256": hashes, "controller_sha256": hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest(),
        "command": command, "budget_seconds": 30, "attempts": 1,
        "duration_seconds": time.monotonic() - before, "exit_code": code,
        "timed_out": timed_out, "platform": platform.platform(),
        "architecture": platform.machine(), "python": platform.python_version(),
        "cache": "fresh source export; no compilation; OS caches uncontrolled",
        "qualifies": "source transfer and stdlib test compatibility only",
        "heavy_test_qualified": False, "whole_goal_completed": False,
    }
    (evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
