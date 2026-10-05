#!/usr/bin/env python3
"""Verify the pinned protocol, then install only these supplemental test tools."""
import argparse
import shutil
import subprocess
from pathlib import Path

COMMITMENT = 'd4fdaf6dbb05d00e1820f585dc7ddeb5f0d10f927b003d4551c0429a92d66b54'


def prepare(root, manifest):
    root = root.resolve(strict=True)
    here = Path(__file__).resolve().parent
    subprocess.run(['python3', str(root / 'tools/implementation-source/verify.py'),
                    '--root', str(root), '--manifest', str(manifest.resolve(strict=True)),
                    '--expected-commitment', COMMITMENT], check=True)
    targets = [root / 'tools/earth-testnet', root / 'tools/earth-wallet']
    if any(p.exists() for p in targets):
        raise ValueError('extract into a new directory; supplemental directories already exist')
    for relative in ['Cargo.toml', 'Cargo.lock', 'src']:
        source, target = here / relative, targets[0] / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    shutil.copytree(here / 'wallet', targets[1])
    support = root / 'tools/earth-payment-tools/src/compatibility.rs'
    support.parent.mkdir(parents=True, exist_ok=True)
    # Supplemental code is outside the verified consensus commitment.
    shutil.copyfile(here / 'compatibility.rs', support)
    print('Verified protocol and installed supplemental fresh-testnet tools.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.root, args.manifest)
