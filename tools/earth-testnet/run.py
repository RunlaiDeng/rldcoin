#!/usr/bin/env python3
"""Pinned fixture-only source, destination or observer; never launches mainnet."""
import argparse
import hashlib
import json
import os
from pathlib import Path

IMPLEMENTATION = 'd4fdaf6dbb05d00e1820f585dc7ddeb5f0d10f927b003d4551c0429a92d66b54'


def command(base, mode, peer=None, no_mining=False, mine_interval_ms=10000):
    if isinstance(mine_interval_ms, bool) or not 1000 <= mine_interval_ms <= 600000:
        raise RuntimeError('test mining polling interval is outside its resource budget')
    base = Path(base).resolve(strict=True)
    records = base / 'records'
    pins = json.loads((records / 'testnet.json').read_text())
    if any(pins.get(k) is not v for k, v in {
        'test_only': True, 'has_monetary_value': False,
        'mainnet_authorized': False, 'old_balances_migrate': False,
    }.items()) or pins.get('implementation_source') != IMPLEMENTATION:
        raise RuntimeError('only the exact public-key fresh testnet is accepted')
    if pins['initial_source_height'] != '0' or pins['initial_source_issued'] != '0':
        raise RuntimeError('inherited issuance is forbidden')
    binary = base / 'bin' / ('rld-earth-destination-node' if mode == 'destination' else 'rld-earth-node')
    expected = json.loads((base / 'binary-hashes.json').read_text())[binary.name]
    if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != expected:
        raise RuntimeError('testnet executable differs from accepted bytes')
    data = base / 'data'
    data.mkdir(mode=0o700, exist_ok=True)
    args = [str(binary)]
    if mode != 'destination':
        args += ['run-adopted']
    for flag, name in [('genesis','genesis.json'),('history','history.json'),('adoption','adoption.json'),
                       ('transition-preview','transition-preview.json'),('earth-adoption','earth-adoption.json')]:
        args += ['--'+flag, str(records / name)]
    for flag, key in [('manifest-pin','manifest_pin'),('accept-adoption','adoption_id'),
                      ('pinned-v1-source','implementation_source'),('accept-transition-preview','preview_id'),
                      ('accept-earth-adoption','earth_adoption_id')]:
        args += ['--'+flag, pins[key]]
    args += ['--v1-data-dir', str(data / (mode+'-v1'))]
    if mode == 'destination':
        args += ['--source-candidate-dir', str(data / 'destination-source'), '--source-node', 'http://127.0.0.1:48500',
                 '--destination-context', str(records / 'destination-context.json'),
                 '--destination-authorization', str(records / 'destination-authorization.json'),
                 '--accept-destination-authorization', pins['destination_authorization_id'],
                 '--destination-signer', pins['destination_signer'],
                 '--destination-dir', str(data / 'destination'), '--listen', '127.0.0.1:48510']
    else:
        args += ['--data-dir', str(data / mode), '--listen', '127.0.0.1:'+('48520' if mode == 'observer' else '48500')]
    if mode == 'observer':
        if peer != 'http://127.0.0.1:48530':
            raise RuntimeError('observer requires the bounded private loopback bridge')
        args += ['--peer', peer]
    elif not no_mining:
        args += ['--mine-to', pins['miner'], '--mine-interval-ms', str(mine_interval_ms)]
    return args


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--mode', choices=['source','destination','observer'], required=True)
    parser.add_argument('--peer')
    parser.add_argument('--no-mining', action='store_true')
    parser.add_argument('--mine-interval-ms', type=int, default=10000)
    args = parser.parse_args()
    os.umask(0o077)
    argv = command(args.root, args.mode, args.peer, args.no_mining, args.mine_interval_ms)
    os.execv(argv[0], argv)
