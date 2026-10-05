#!/usr/bin/env python3
"""Compare replayed test-chain heads across real process restarts on both hosts."""
import json
import argparse
import subprocess
import time
import urllib.request
from pathlib import Path

SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
       '-o', 'StrictHostKeyChecking=yes', 'galaxy@35.200.194.179']
PREFIX = 'rldcoin-testnet-20260930'


def remote(command):
    return subprocess.check_output(SSH + [command], timeout=55).decode()


def get(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)


def snapshot():
    return {name: get(f'http://127.0.0.1:{port}/v1/earth/status')
            for name, port in [('source', 48530), ('observer', 48520)]}


def head(status):
    return {key: status[key] for key in
            ['chain_id', 'height', 'tip', 'chainwork', 'state_root',
             'implementation_source_sha256', 'storage_healthy']}


def wait_equal():
    for _ in range(20):
        try:
            values = snapshot()
            if head(values['source']) == head(values['observer']):
                return values
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise RuntimeError('two-host testnet replay did not converge')


def main(output):
    try:
        # The caller installs this temporary override before the drill. It is
        # always removed below, including after an assertion failure.
        before = wait_equal()
        assert before['source']['chain_id'] == 'e8a8dd66eac5a8fe70816901c6b06035fc92b2193213d8fa0f00d2f10a32438e', 'unexpected fixture chain'
        remote(f'sudo systemctl restart {PREFIX}-source.service')
        subprocess.run(['launchctl', 'kickstart', '-k',
                        f'gui/{subprocess.check_output(["id", "-u"]).decode().strip()}/com.rldcoin.testnet-20260930-observer'], check=True)
        after = wait_equal()
        assert head(before['source']) == head(after['source']), 'source changed while mining was paused'
        result = {'test_only': True, 'has_monetary_value': False,
                  'independent_operators': False, 'passed': True,
                  'before': {k: head(v) for k, v in before.items()},
                  'after': {k: head(v) for k, v in after.items()},
                  'checks': ['remote source restart', 'local observer restart',
                             'identical chain, height, tip, work and state root',
                             'storage healthy on both hosts']}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'passed': True, 'height': after['source']['height']}))
    finally:
        remote(f'sudo rm -f /etc/systemd/system/{PREFIX}-source.service.d/restart-drill.conf && sudo systemctl daemon-reload && sudo systemctl restart {PREFIX}-source.service && systemctl is-active {PREFIX}-source.service')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('restart-drill.json'))
    main(parser.parse_args().output)
