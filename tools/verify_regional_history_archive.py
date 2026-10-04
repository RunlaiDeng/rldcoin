#!/usr/bin/env python3
"""Stopped fixture: private ledger images, fresh targets and full native replay.

Generated images and independently retained observations stay private. This
same-host audit signs nothing and restores no signer, caller or wallet custody.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(root):
    result = {}
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'private fixture symlink refused')
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path)
    return result


def verify(args):
    source, root, binary = args.source.absolute(), args.root.absolute(), args.binary.absolute()
    manifest = json.loads(args.manifest.read_text())
    require(hashlib.sha256(json.dumps(manifest['files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            == manifest['source_set_sha256'], 'source commitment differs')
    def source_check():
        for entry in manifest['files']:
            path = source / entry['path']
            require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents])
                    and path.stat().st_size == entry['size_bytes'] and sha(path) == entry['sha256'],
                    'named source changed: ' + entry['path'])
    source_check()
    run = json.loads(args.run_report.read_text())
    bootstrap = json.loads((root / 'bootstrap.json').read_text())
    currency = bootstrap['admissions'][0]['currency']
    implementation = bootstrap['currency']['implementation']
    if run['format'] == 'RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1':
        run_implementation = run['implementation']
        require(run['replica_heights'] == {'earth': [7] * 4, 'proxima': [4] * 4, 'andromeda': [4] * 4}
                and len(run['conservation_checks']) == 15
                and all(row['conserved'] is True for row in run['conservation_checks']),
                'complete fixture cycle required')
    else:
        require(run['completed'] is True and run['fresh_fault_profile_completed'] is True
                and run['failure'] is None and run['runtime_source_set_sha256'] == manifest['source_set_sha256'],
                'complete exact-source fresh fault profile required')
        run_implementation = run['native_implementation']
    require(run['fixture_only'] is True and run['live_rld'] is False
            and run_implementation == implementation == manifest['native_implementation'],
            'fixture report/native binding differs')
    require(run.get('currency', currency) == currency, 'fixture currency differs')
    for line in subprocess.check_output(['ps', '-A', '-o', 'args='], text=True).splitlines():
        require(not (str(root) in line and (line.startswith(str(binary)) or
                    (line.split() and Path(line.split()[0]).name.lower().startswith('python')
                     and 'regional_contact_node.py' in line))), 'fixture is still running')
    authority = bootstrap['currency']['authority']
    before = files(root)
    image_root = args.images.absolute()
    require(not image_root.exists() and not image_root.is_relative_to(root)
            and not root.is_relative_to(image_root), 'fresh separate private image root required')
    image_root.mkdir(mode=0o700)
    anchors = image_root / 'separately-retained-observations'
    anchors.mkdir(mode=0o700)

    def call(directory, *command):
        result = subprocess.run([str(binary), '--dir', str(directory), '--authority', authority,
                                 '--currency', currency, *map(str, command)],
                                capture_output=True, timeout=60)
        require(result.returncode == 0, 'native image audit failure: ' + result.stderr.decode(errors='replace')[:1000])
        return json.loads(result.stdout)

    rows = []
    for region in ['earth', 'proxima', 'andromeda']:
        for replica in range(4):
            name = f'{region}-{replica}'
            node = root / name
            head = call(node, 'history-head')
            expected = head['history_head']
            # A same-host separately stored observation is not an independent anchor.
            anchor = anchors / (name + '.json')
            descriptor = os.open(anchor, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(head, stream)
                stream.flush()
                os.fsync(stream.fileno())
            original = call(node, 'history-check', '--expected-head', expected)
            status = call(node, 'status')
            image, target = image_root / (name + '-image'), image_root / (name + '-restored')
            sealed = call(node, 'history-archive', '--archive', image, '--expected-head', expected)
            image_before = files(image)
            restored = call(target, 'history-restore', '--archive', image, '--expected-head', expected)
            require(restored == sealed and restored['complete_native_replay_verified'] is True
                    and restored['keys_restored'] is False
                    and restored['signer_or_caller_heads_restored'] is False
                    and restored['wallet_pending_reviews_restored'] is False,
                    'restore scope differs')
            restored_before = files(target)
            require(call(target, 'history-check', '--expected-head', expected) == original
                    and call(target, 'status') == status, 'restored native history/value differs')
            require(files(target) == restored_before and files(image) == image_before,
                    'post-restore verification mutated image or target')
            index = json.loads((image / 'archive.json').read_text())
            require(set(restored_before) == set(index['files']) | {'LOCK'}
                    and 'RESTORING' not in restored_before, 'restored file scope differs')
            require(all(restored_before[path] == row['sha256'] for path, row in index['files'].items()),
                    'restored retained bytes differ')
            rows.append({'region': region, 'replica': replica, 'height': status['height'],
                         'history_head': expected, 'archive_commitment': sealed['archive_commitment'],
                         'retained_files': sealed['retained_files'], 'retained_bytes': sealed['retained_bytes'],
                         'permanent_import_entries': original['permanent_import_entries'],
                         'full_native_replay_and_latest_observation_match': True,
                         'restored_value_and_incidents_exact': True, 'image_and_verified_target_unchanged': True})
    require(files(root) == before, 'source private files changed')
    source_check()
    return {'format': 'RLD-NATIVE-HISTORY-PRIVATE-IMAGE-AUDIT-V1',
            'fixture_only': True, 'live_rld': False, 'same_host_same_controller': True,
            'source_set_sha256': manifest['source_set_sha256'], 'native_implementation': implementation,
            'binary_sha256': sha(binary), 'run_report_sha256': sha(args.run_report),
            'currency': currency, 'native_images_and_fresh_target_restores': len(rows), 'rows': rows,
            'all_source_private_files_unchanged': True, 'frozen_source_unchanged': True,
            'owned_process_cleanup_verified': True, 'private_images_published': False,
            'keys_signers_wallets_caller_heads_restored': False,
            'independent_latest_anchor_qualified': False, 'power_loss_qualified': False,
            'cross_device_custody_qualified': False, 'long_history_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'manifest', 'root', 'binary', 'run-report', 'images', 'report']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    report = verify(args)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'native_images_and_fresh_target_restores': report['native_images_and_fresh_target_restores'],
                      'all_source_private_files_unchanged': True, 'frozen_source_unchanged': True}))


if __name__ == '__main__':
    main()
