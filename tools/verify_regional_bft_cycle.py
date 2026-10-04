#!/usr/bin/env python3
"""Read-only stopped-fixture checks for the exact native three-region cycle.

This supplemental verifier is separately committed from its runtime manifest.
It signs nothing and never installs native or transport evidence.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_terminal(run):
    require(run.get('completed') is True and run.get('failure') is None
            and run.get('owned_process_cleanup_verified') is True
            and run.get('owned_process_shutdown_clean') is True,
            'completed clean terminal cycle required before private inspection')


def inspection_anchors(root,run, *, path_name='mesh-inspection-anchors.json'):
    import interstellar_mesh as mesh
    require(path_name in ('mesh-inspection-anchors.json', 'fault-mesh-inspection-anchors.json'),
            'unknown setup inspection anchor entry')
    path=root/path_name
    require(sha(path)==run['mesh_inspection_anchors_sha256'],'setup inspection anchors changed')
    value=mesh.load(path,65536)
    names={f'{region}-{replica}' for region in ('earth','proxima','andromeda') for replica in range(4)}
    require(set(value)=={'format','network','nodes'}
            and value['format']=='RLD-MULTIREGION-MESH-INSPECTION-ANCHORS-V1'
            and value['network']==run['currency'] and set(value['nodes'])==names
            and len({row['node_id'] for row in value['nodes'].values()})==12,
            'setup inspection domain or carrier inventory differs')
    return value


def verify(args, joint=False):
    stage, root, binary = args.source.absolute(), args.root.absolute(), args.binary.absolute()
    run = json.loads(args.run_report.read_text())
    verify_terminal(run)
    manifest = json.loads(args.manifest.read_text())
    commitment = hashlib.sha256(json.dumps(manifest['files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(commitment == manifest['source_set_sha256'], 'source commitment differs')
    for entry in manifest['files']:
        path = stage / entry['path']
        require(path.resolve().is_relative_to(stage.resolve()) and not any(p.is_symlink() for p in [path, *path.parents])
                and path.is_file() and path.stat().st_size == entry['size_bytes'] and sha(path) == entry['sha256'],
                'named source changed: ' + entry['path'])
    expected_format = ('RLD-BFT-JOINT-MULTIREGION-GROUND-CAMPAIGN-V1' if joint
                       else 'RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1')
    require(run['format'] == expected_format
            and run['fixture_only'] is True and run['live_rld'] is False
            and run['same_host_same_controller'] is True
            and type(run['regions']) is int and run['regions'] == 3
            and type(run['native_replicas_per_region']) is int and run['native_replicas_per_region'] == 4
            and run['implementation'] == manifest['native_implementation'], 'completed exact fixture cycle required')
    for field in ['controller_generated_consensus_messages', 'controller_carried_payment_proofs',
                  'controller_installed_checkpoints', 'remote_execution_earth_calls']:
        require(type(run[field]) is int and run[field] == 0, 'controller authority/carriage exceeds cycle scope')
    for field in ['every_earth_node_stopped_during_onward_and_return_exports', 'initial_debit_never_released',
                  'return_uses_new_export_and_import', 'actual_two_hop_return_carriage',
                  'queued_owner_submissions_did_not_debit', 'transport_receipt_did_not_credit']:
        require(run[field] is True, 'cycle observation incomplete: ' + field)
    require(run['replica_heights'] == {'earth': [11 if joint else 7]*4, 'proxima': [4]*4, 'andromeda': [4]*4}, 'cycle tip heights differ')
    require(len(run['conservation_checks']) == (16 if joint else 15) and all(row['conserved'] is True
            and int(row['issued']) == int(row['liquid']) + int(row['pending_exports'])
            for row in run['conservation_checks']), 'recorded cycle conservation differs')
    for phase in run['observed_ground_phases']:
        elapsed, bound = phase['elapsed_seconds'], phase['observation_bound_seconds']
        require(type(elapsed) in (int, float) and type(bound) in (int, float)
                and math.isfinite(elapsed) and math.isfinite(bound) and 0 <= elapsed <= bound and bound > 0,
                'cycle observation outside recorded bounds')
    require(binary.is_file() and not binary.is_symlink(), 'regular native binary required')
    for line in subprocess.check_output(['ps', '-A', '-o', 'args='], text=True).splitlines():
        require(not (str(root) in line and (line.startswith(str(binary)) or
                    (line.split() and Path(line.split()[0]).name.lower().startswith('python')
                     and 'regional_contact_node.py' in line))), 'fixture is still running')

    sys.path.insert(0, str(stage / 'tools'))
    import interstellar_mesh as mesh
    from regional_contact_node import Native
    from verify_regional_bft_sustained import files
    from regional_bft_retention import verify_stopped_state
    from interstellar_mesh_inspection import MeshInspection
    if joint:
        from verify_regional_bft_joint_cycle import verify_run, verify_custody
        verify_run(run)

    before = files(root)
    anchors=inspection_anchors(root,run)
    bootstrap = json.loads((root / 'bootstrap.json').read_text())
    implementation, authority = bootstrap['currency']['implementation'], bootstrap['currency']['authority']
    require(implementation == manifest['native_implementation'], 'native implementation differs')
    currency = bootstrap['admissions'][0]['currency']
    require(currency == run['currency'], 'fixture currency differs')
    requests = {'proxima': ('first_recipient', '96', False), 'andromeda': ('onward_recipient', '91', False),
                'earth': ('return_recipient', '86', True)}
    states, rows, archive_rows, recipient_rows, retention_rows, custody_rows = [], [], [], [], [], []
    with tempfile.TemporaryDirectory(prefix='rld-cycle-expectations-') as scratch:
        for name in ['earth', 'proxima', 'andromeda']:
            key, amount, spendable = requests[name]
            expected = run[key]['expected']
            require(expected['currency'] == currency and expected['net_amount'] == amount, 'original payment binding differs')
            expectation = Path(scratch) / (name + '.json')
            expectation.write_text(json.dumps(expected))
            regional = []
            for replica in range(4):
                require((root / f'{name}-{replica}' / 'INCIDENT_GUARD').read_bytes() == bytes(32),
                        'pending incident recovery requires a separate mutating operation')
                native = Native(binary, root / f'{name}-{replica}', authority, currency)
                state = native.call('status')
                require(state['fixture_only'] is True and state['live_rld'] is False
                        and state['height'] == run['replica_heights'][name][replica]
                        and state['currency'] == currency and state['region'] == expected['destination'], 'native state domain/tip differs')
                config = mesh.load(root / f'bft-config-{name}-{replica}.json', 65536)
                require(all(Path(config[field]).resolve().is_relative_to(root.resolve())
                            for field in ['head_file', 'signer_dir']), 'signer/caller path escapes private fixture')
                head = mesh.load(Path(config['head_file']), 8*1024*1024)
                signer = native.call('bft-status', '--signer-dir', config['signer_dir'])
                binding = {'currency': currency, 'region': state['region'], 'key': config['key']}
                require(signer['binding'] == head['binding'] == binding and signer['head'] == head['head']
                        and head['pending'] is None and head['outbox'] is None, 'signer/caller head is unresolved')
                if joint and name == 'earth':
                    custody_rows.append(verify_custody(native, config, state, signer, head, root, replica, run))
                retention_rows.append(dict(verify_stopped_state(native, config, state, root), region=name, replica=replica))
                receipt = native.call('wallet-receipt', '--file', expectation)
                require(receipt['expected'] == expected and receipt['import_accepted'] is True
                        and receipt['maturity_reached'] is True and receipt['local_finality_covers_import'] is True
                        and receipt['quarantined'] is False and receipt['original_output_spendable_now'] is spendable
                        and receipt['original_output_remaining'] == (amount if spendable else '0'), 'native historical recipient differs')
                regional.append(state)
                recipient_rows.append({'region': name, 'replica': replica, 'net_amount': amount,
                                       'original_output_remaining': receipt['original_output_remaining'],
                                       'native_state': receipt['state'], 'import_height': receipt['import_height'],
                                       'mature_height': receipt['mature_height'], 'finality_covers_import': True})
                rows.append({'region': name, 'replica': replica, 'height': state['height'], 'tip': state['tip'],
                             'separate_head_matches': True})
                with MeshInspection(mesh.load(root / f'mesh-config-{name}-{replica}.json', 65536),
                                    **anchors['nodes'][f'{name}-{replica}']) as node:
                    inventory, total = node.archive_inventory()
                    archive_rows.append({'region': name, 'replica': replica, 'archived_records': len(node.state['archives']),
                                         'retained_files': len(inventory), 'retained_bytes': total, 'full_cold_authentication': True})
            require(all(state == regional[0] for state in regional), 'regional native replicas disagree')
            states.append(regional[0])
    exports, imports = {}, set()
    issued = liquid = 0
    for state in states:
        ledger = state['ledger']
        issued += int(ledger['minted'])
        liquid += sum(int(coin['payment']['amount']) for coin in ledger['coins'].values())
        for ident, record in ledger['exports'].items():
            require(ident not in exports, 'duplicate export identity')
            exports[ident] = record
        for ident in ledger['imports']:
            require(ident not in imports, 'duplicate import identity')
            imports.add(ident)
    require(imports <= exports.keys(), 'import lacks retained export')
    expected_ids = {run[key]['expected']['export'] for key, _, _ in requests.values()}
    require(len(expected_ids) == 3 and expected_ids == set(exports) == imports,
            'original cycle export/import identities differ')
    pending = sum(int(record['recipient']['amount']) for ident, record in exports.items() if ident not in imports)
    require(issued == liquid + pending == 300 and pending == 0 and len(exports) == len(imports) == 3,
            'native cycle conservation/export/import differs')
    require(files(root) == before, 'private fixture changed during cold reads')
    report = {'format': 'RLD-NATIVE-JOINT-CYCLE-COLD-VERIFICATION-V1' if joint else 'RLD-NATIVE-CYCLE-COLD-VERIFICATION-V1', 'fixture_only': True, 'live_rld': False,
              'same_host_same_controller': True, 'source_set_sha256': commitment,
              'native_implementation': manifest['native_implementation'], 'binary_sha256': sha(binary),
              'verifier_sha256': sha(Path(__file__)), 'run_report_sha256': sha(args.run_report),
              'native_replays': rows, 'regional_replicas_agree': True, 'recipient_checks': recipient_rows,
              'archive_reads': archive_rows, 'native_conservation': {'issued': str(issued), 'liquid': str(liquid), 'in_transit': str(pending)},
              'bft_retention_reads': retention_rows,
              'joint_custody_reads': custody_rows,
              'mesh_inspection_anchors_sha256':sha(root/'mesh-inspection-anchors.json'),
              'strict_transport_read_only_entry_used':True,
              'all_private_fixture_files_unchanged': True, 'owned_process_cleanup_verified': True,
              'cross_host_qualified': False, 'independent_operators_qualified': False,
              'long_term_history_qualified': False, 'physical_route_qualified': False}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'native_replays': len(rows), 'recipient_checks': len(recipient_rows),
                      'archives_authenticated': sum(row['archived_records'] for row in archive_rows), 'private_files_unchanged': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'manifest', 'run-report', 'binary', 'root', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    verify(parser.parse_args())
