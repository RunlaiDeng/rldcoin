#!/usr/bin/env python3
"""Exercise three real local mesh daemons, a stopped relay and durable recovery."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as evidence


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.05)
    raise ValueError('ground process drill deadline reached')


def run_drill():
    with tempfile.TemporaryDirectory(prefix='rld-mesh-drill-') as temporary:
        root = Path(temporary).resolve()
        names = ['earth', 'proxima', 'andromeda']
        network = mesh.digest({'ground_fixture': 'interstellar-mesh-20260930'})
        ids = {n: mesh.initialize(root / n, network, mesh.digest({'fixture_region': n}), n)['node_id'] for n in names}
        configs, processes, logs = {}, {}, []
        script = Path(__file__).with_name('interstellar_mesh.py')
        for i, name in enumerate(names):
            contacts = [{'peer': ids[other], 'inbox': str(root / 'contact' / (other + '-' + name)),
                         'outbox': str(root / 'contact' / (name + '-' + other))}
                        for j, other in enumerate(names) if abs(i-j) == 1]
            configs[name] = {'format': mesh.VERSION, 'state': str(root / name), 'network': network, 'contacts': contacts}
            evidence.write_new(root / (name + '.config.json'), evidence.canonical(configs[name]))

        def start(name):
            log = (root / (name + '.log')).open('ab')
            logs.append(log)
            processes[name] = subprocess.Popen([sys.executable, str(script), 'run', '--config',
                str(root / (name + '.config.json')), '--interval', '0.1'], stdout=log, stderr=log)

        def stop(name):
            process = processes.pop(name, None)
            if process:
                process.terminate()
                process.wait(timeout=5)

        def status(name):
            for process in processes.values():
                mesh.require(process.poll() is None, 'mesh daemon exited unexpectedly')
            return mesh.load(root / name / 'status.json', mesh.MAX_STATE)

        try:
            for name in names:
                start(name)
            wait_for(lambda: all(status(n)['nodes'] == 3 for n in names))
            route = status('earth')['routes'][ids['andromeda']]
            mesh.require(route == [ids[n] for n in names], 'unexpected discovered route')
            stop('proxima')
            frame = evidence.make_frame('source-finality', '1' * 64, '3' * 64, '4' * 64,
                b'{"fixture_only":true,"ledger_acceptance_not_exercised":true}')
            with mesh.Node(configs['earth']) as source:
                packet = source.enqueue(frame, ids['andromeda'])
            wait_for(lambda: status('earth')['messages'].get(packet) == 'QUEUED_WAITING_CONTACT_OR_ROUTE')
            stop('earth')
            with mesh.Node(configs['earth']) as source:
                mesh.require(packet in source.state['messages'] and packet not in source.state['receipts'], 'queued message lost on restart')
            start('earth')
            start('proxima')
            wait_for(lambda: status('earth')['messages'].get(packet) == 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            with mesh.Node(configs['andromeda']) as destination:
                path = root / 'received.frame.json'
                destination.export_received(packet, path)
                mesh.require(path.read_bytes() == frame, 'payload bytes changed')
                hops = len(destination.state['messages'][packet]['hops'])
            stop('andromeda')
            start('andromeda')
            wait_for(lambda: status('andromeda')['messages'].get(packet) == 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            return {'format': 'RLD-MESH-GROUND-DRILL-V1', 'date': '2026-09-30', 'result': 'PASS',
                'logical_regions': names, 'physical_scope': 'three processes on one Earth host with paired directory contacts',
                'automatic_discovered_nodes_per_process': 3, 'configured_adjacent_edges': 2,
                'discovered_route': names, 'evidence_forward_hops': hops, 'exact_payload_preserved': True,
                'relay_stop_and_resume_passed': True, 'sender_restart_with_pending_evidence_passed': True,
                'destination_restart_passed': True, 'signed_destination_transport_receipt_returned': True,
                'ledger_acceptance_exercised': False, 'physical_interstellar_route_verified': False,
                'mainnet_authorized': False, 'independent_operators': False,
                'packet_id': packet, 'frame_id': evidence.inspect_frame(frame)[0]['message_id']}
        finally:
            for name in list(processes):
                stop(name)
            for log in logs:
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run_drill()
    evidence.write_new(args.output, evidence.canonical(result))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
