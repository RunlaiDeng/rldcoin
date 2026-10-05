#!/usr/bin/env python3
"""Bounded process-crash drill for ground contact archive custody.

Uses fresh private fixture identities, no native ledger/value, and an optional
exact runtime tools directory. SIGKILL models process loss, not power loss or
cross-device custody. Keep the fixture directory private; only the report is
sanitized. Runtime evidence is never deleted or repaired by this controller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys

POINTS = ('after_link_before_sync', 'after_payload_before_index', 'after_index')
NETWORK = 'a' * 64
REGION = '1' * 64


def child(tools, config_path, point):
    sys.path.insert(0, str(tools))
    import interstellar_mesh as mesh
    config = mesh.load(config_path, 65536)
    with mesh.Node(config) as node:
        original_write, original_atomic, original_sync = mesh.archive_write, mesh.atomic, mesh.sync_retained

        def boundary():
            print('ARCHIVE_CRASH_BOUNDARY', flush=True)
            # The parent kills only this owned child after observing the
            # selected transaction boundary. No acknowledgment is released.
            sys.stdin.readline()
            raise RuntimeError('parent did not terminate the crash child')

        def write(path, raw):
            original_write(path, raw)
            if point == 'after_payload_before_index':
                boundary()

        def atomic(path, value):
            original_atomic(path, value)
            if point == 'after_index' and path == node.path:
                boundary()

        def sync(path):
            if point == 'after_link_before_sync' and path.parent == node.archive_root:
                boundary()
            original_sync(path)

        mesh.archive_write, mesh.atomic, mesh.sync_retained = write, atomic, sync
        mesh.ARCHIVE_HIGH_WATER = 1
        node.archive_completed()
    raise RuntimeError('selected crash boundary was not reached')


def run(tools, root, report_path):
    if root.exists():
        raise ValueError('fresh private fixture directory required')
    root.mkdir(parents=True, mode=0o700)
    sys.path.insert(0, str(tools))
    import interstellar_mesh as mesh
    import interstellar_transfer as wire
    if mesh.VERSION != 'RLD-CONTACT-MESH-V3':
        raise ValueError('archive V3 runtime required; no legacy rewrite')
    frame = wire.make_frame('source-finality', REGION, '3' * 64, '4' * 64,
                            b'{"ground_fixture":"not_native_value_authorization"}')
    observations = []
    for point in POINTS:
        state_root = root / point
        mesh.initialize(state_root, NETWORK, REGION, 'archive-crash-fixture')
        config = {'format': mesh.VERSION, 'state': str(state_root), 'network': NETWORK, 'contacts': []}
        config_path = root / (point + '-config.json')
        mesh.atomic(config_path, config)
        with mesh.Node(config) as node:
            ident = node.enqueue(frame, node.id)
            state_path = node.path
            before = state_path.read_bytes()
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child',
                                    str(tools), str(config_path), point],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=20):
                    raise ValueError('crash child did not reach the named boundary')
            if process.stdout.readline().strip() != b'ARCHIVE_CRASH_BOUNDARY':
                raise ValueError('unexpected crash child response')
            process.kill()
            process.wait(timeout=10)
            if process.returncode != -signal.SIGKILL:
                raise ValueError('owned child was not terminated by SIGKILL')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        before_restart = state_path.read_bytes()
        if point != 'after_index' and before_restart != before:
            raise ValueError('crash before index commit changed active custody')
        with mesh.Node(config) as node:
            if point == 'after_index':
                if ident not in node.state['archives'] or ident in node.state['messages']:
                    raise ValueError('durable index commit did not retain archived custody')
            else:
                if ident not in node.state['messages']:
                    raise ValueError('pre-index crash lost active original evidence')
                mesh.ARCHIVE_HIGH_WATER = 1
                if node.archive_completed() != 1:
                    raise ValueError('exact orphan recovery did not complete')
            _, retained, _ = mesh.transit_check(node.transit(ident), NETWORK)
            if retained != frame:
                raise ValueError('recovered archive payload changed')
            if ident not in node.receipts() or node.status()['payment_authorized']:
                raise ValueError('receipt custody or value boundary changed')
            files = list(node.archive_root.iterdir())
            observations.append({'boundary': point, 'owned_child_sigkill_verified': True,
                                 'before_index_active_state_unchanged': point != 'after_index',
                                 'exact_payload_recovered': True, 'scoped_receipt_retained': True,
                                 'archive_files_retained': len(files),
                                 'staging_files_retained': sum(p.name.startswith('.archive-write-') for p in files),
                                 'no_payment_authority': True})
    result = {'format': 'RLD-CONTACT-ARCHIVE-PROCESS-CRASH-CAMPAIGN-V1', 'fixture_only': True,
              'live_rld': False, 'mesh_format': mesh.VERSION, 'same_host_same_controller': True,
              'native_ledger_exercised': False, 'power_loss_qualified': False,
              'cross_device_custody_qualified': False,
              'runtime_sha256': {name: hashlib.sha256((tools/name).read_bytes()).hexdigest()
                                 for name in ('interstellar_mesh.py', 'interstellar_transfer.py')},
              'drill_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'observations': observations, 'owned_process_cleanup_verified': True}
    report_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'process_crash_boundaries_passed': len(observations), 'exact_custody_retained': True}))


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--child':
        child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-tools', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--root', type=Path, required=True, help='Fresh private fixture directory')
    parser.add_argument('--report', type=Path, required=True, help='Sanitized report')
    args = parser.parse_args()
    run(args.runtime_tools.resolve(), args.root.resolve(), args.report.resolve())


if __name__ == '__main__':
    main()
