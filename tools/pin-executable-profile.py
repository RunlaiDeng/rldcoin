#!/usr/bin/env python3
"""Bind reviewed native/proof source to an actually built real prover.

Creates no currency, keys, monetary genesis, receipts or network. Rebuild the real
prover first. Final publication must compare actual CLI/prover profiles and bind
the full compiled source independently. This helper is not that verification.
"""
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
files = [root / n for n in (
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates/protocol/Cargo.toml",
    "methods/Cargo.toml", "methods/build.rs", "methods/guest/Cargo.toml",
    "methods/guest/Cargo.lock",
)]
for directory in ("crates/protocol/src", "methods/src", "methods/guest/src"):
    files.extend((root / directory).rglob("*.rs"))
digest = hashlib.sha256()
inventory = []
for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
    name = path.relative_to(root).as_posix().encode()
    data = path.read_bytes()
    digest.update(len(name).to_bytes(8, "big")); digest.update(name)
    digest.update(len(data).to_bytes(8, "big")); digest.update(data)
    inventory.append({"path": name.decode(), "sha256": hashlib.sha256(data).hexdigest()})
profile = json.loads(subprocess.check_output([str(root / "target/release/rld-prover"), "profile"], cwd=root))
binding = {"format": "RLD-EXECUTABLE-PROFILE-1", "source_digest": digest.hexdigest(),
           "proof_profile": profile, "source_files": inventory}
(root / "spec/EXECUTABLE_PROFILE.json").write_text(json.dumps(binding, indent=2) + "\n")
print(json.dumps({"source_digest": digest.hexdigest(), "proof_profile": profile}, indent=2))
