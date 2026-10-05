#!/usr/bin/env python3
"""Run the local test wallet with both exact signed chain identities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import run as testnet


def main(base):
    base = base.resolve(strict=True)
    # Reuse native executable, fixture metadata and zero-issuance checks.
    testnet.command(base, 'observer', 'http://127.0.0.1:48530')
    records = base / 'records'
    pins = json.loads((records / 'testnet.json').read_text())
    binary = base / 'bin/rld-earth-wallet'
    hashes = json.loads((base / 'binary-hashes.json').read_text())
    if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != hashes[binary.name]:
        raise ValueError('test wallet executable hash differs')
    for source, target in [('adoption.json', 'pow-adoption.json'),
                           ('earth-adoption.json', 'value-adoption.json'),
                           ('transition-preview.json', 'preview.json')]:
        (records / target).write_bytes((records / source).read_bytes())
    (records / 'pins.json').write_text(json.dumps({
        'manifest_pin': pins['manifest_pin'], 'pow_adoption_id': pins['adoption_id']}))
    config = records / 'wallet-destination.json'
    config.write_text(json.dumps({'context': str(records / 'destination-context.json'),
                                  'authorization': str(records / 'destination-authorization.json'),
                                  'node': 'http://127.0.0.1:48531'}))
    os.umask(0o077)
    args = [str(binary), '--records', str(records), '--data', str(base / 'wallet'),
            '--node', 'http://127.0.0.1:48520', '--port', '48550',
            '--destination-config', str(config), '--accept-destination-authorization',
            pins['destination_authorization_id'], '--destination-signer', pins['destination_signer']]
    os.execv(args[0], args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    main(parser.parse_args().root)
