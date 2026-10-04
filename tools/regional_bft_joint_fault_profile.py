"""Explicit joint-cycle fault scope; no native authority or state conversion."""
import hashlib
import json
import time
from pathlib import Path

import interstellar_mesh as mesh
from regional_bft_joint_epoch import FORMAT
from verify_regional_bft_joint_cycle import verify_run, verify_custody


RUNTIME = {'tools/' + name for name in (
    'regional_contact_node.py', 'regional_bft_node.py', 'regional_bft_joint_epoch.py',
    'regional_bft_retention.py', 'interstellar_mesh.py', 'interstellar_tcp.py',
    'interstellar_transfer.py', 'interstellar_route_budget.py')}
FORBIDDEN = {'sign-handoff', 'install-epoch', 'propose-epoch', 'sign-checkpoint',
             'signer-recover-handoff', 'bft-epoch-combine', 'bft-epoch-activate',
             'bft-epoch-activate-observed'}
READ_ONLY = {'status', 'proof', 'bft-context', 'bft-status', 'signer-status',
             'bft-retained-messages', 'wallet-receipt'}
LOCK_REFUSAL = 'regional candidate rejected: lock acquisition failed because the operation would block'


def bounded_read(call, *args, on_retry=None, attempts=8):
    """Retry only an exact OS-lock refusal of an explicitly read-only command.

    Each native invocation retains its original timeout. There is no cached
    response, signing, recovery, head adoption or successful timeout result.
    """
    mesh.require(args and args[0] in READ_ONLY and type(attempts) is int
                 and 1 <= attempts <= 8, 'bounded native read required')
    for attempt in range(attempts):
        try:
            return call(*args)
        except ValueError as error:
            if str(error) not in {'native rejected: ' + LOCK_REFUSAL,
                                 'native BFT CLI result differs: ' + LOCK_REFUSAL + '\n'}:
                raise
            if attempt + 1 == attempts:
                raise
            if on_retry is not None:
                on_retry()
            time.sleep(0.2)


def commitment(manifest):
    return hashlib.sha256(json.dumps(manifest['files'], sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def missing_leader_gate(height, keys, absent):
    mesh.require(type(height) is int and 0 <= height < 24 and isinstance(keys, list)
                 and len(keys) == 4 and keys == sorted(set(keys)) and absent in keys,
                 'bounded current native height and exact four-member order required')
    # Native round-zero leadership uses parent_height modulo four. The gate is
    # its successor block, never a height already reached by the sealed source.
    parent = height
    while keys[parent % 4] != absent:
        parent += 1
    mesh.require(parent + 1 <= 24, 'missing-leader successor exceeds ground cap')
    return parent + 1


class Profile:
    def __init__(self, previous, cold, cycle_manifest, runtime_manifest, run_sha):
        verify_run(previous)
        mesh.require(previous['format'] == 'RLD-BFT-JOINT-MULTIREGION-GROUND-CAMPAIGN-V1'
                     and previous['replica_heights'] == {'earth':[11]*4,'proxima':[4]*4,'andromeda':[4]*4},
                     'exact completed joint cycle required')
        mesh.require(commitment(cycle_manifest) == cycle_manifest['source_set_sha256']
                     and commitment(runtime_manifest) == runtime_manifest['source_set_sha256']
                     and cold['format'] == 'RLD-NATIVE-JOINT-CYCLE-COLD-VERIFICATION-V1'
                     and cold['run_report_sha256'] == run_sha
                     and cold['source_set_sha256'] == cycle_manifest['source_set_sha256']
                     and cold['native_implementation'] == previous['implementation']
                         == cycle_manifest['native_implementation'] == runtime_manifest['native_implementation']
                     and cold['all_private_fixture_files_unchanged'] is True
                     and cold['owned_process_cleanup_verified'] is True
                     and len(cold['native_replays']) == len(cold['recipient_checks']) == 12
                     and len(cold['joint_custody_reads']) == 4,
                     'exact stopped joint cold evidence and source required')
        old = {x['path']:x for x in cycle_manifest['files']}
        new = {x['path']:x for x in runtime_manifest['files']}
        protected = RUNTIME | {p for p in old if p.startswith(('tools/regional-ledger/', 'crates/rld-core/'))}
        mesh.require(protected <= old.keys() and protected <= new.keys()
                     and all(old[p] == new[p] for p in protected),
                     'native/core/ordinary runtime differs from the sealed joint cycle')
        self.previous = previous

    @staticmethod
    def rebind(config, source, root, name):
        if name == 'earth':
            mesh.require(config['format'] == FORMAT, 'explicit Earth joint lifecycle required')
            joint = dict(config['joint_epoch'])
            for field in ('key_file','signer_dir','head_file','approval_dir','approval_head'):
                joint[field] = str(root / Path(joint[field]).relative_to(source))
            return dict(config, joint_epoch=joint)
        mesh.require(config['format'] == 'RLD-REGIONAL-BFT-NODE-V1', 'initial remote lifecycle required')
        return config

    @staticmethod
    def voter(config, name, replica):
        if name != 'earth':
            return config
        return None if replica == 0 else config['joint_epoch']

    def custody(self, native, config, state, old, old_head, root, replica):
        return verify_custody(native, config, state, old, old_head, root, replica, self.previous)

    def gate(self, native, config):
        context = native.call('bft-context')
        mesh.require(context['rules'] == 'RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1'
                     and context['context']['epoch'] == self.previous['activated_epoch']
                     and context['keys'] == [v['key'] for v in config['joint_epoch']['validators']],
                     'current native membership differs from the pinned joint intent')
        return missing_leader_gate(context['context']['parent_height'], context['keys'], config['joint_epoch']['key'])

    @staticmethod
    def offline_paths(config, root):
        joint = config['joint_epoch']
        mesh.require(not Path(joint['signer_dir']).exists(), 'keyless carrier has acquired voting custody')
        return [root/'earth-0/journal.json', Path(config['signer_dir'])/'bft.json', Path(config['head_file']),
                Path(joint['approval_dir'])/'signer.json', Path(joint['approval_head']), Path(joint['head_file'])]
