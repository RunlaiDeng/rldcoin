#!/usr/bin/env python3
"""Cold native checks for the exact preconfigured joint three-region cycle.

Reads old fences, candidate approvals and independently retained new caller
heads through read-only native journal checks. No response recovery, state
adoption or first signing.
"""
import argparse
from pathlib import Path

from verify_regional_bft_cycle import require, verify


def verify_run(run):
    require(run['completed'] is True and run['failure'] is None
            and run['owned_process_cleanup_verified'] is True, 'joint cycle did not finish cleanly')
    for field in ['preconfigured_autonomous_joint_epoch', 'one_keyless_carrier_never_first_signed',
                  'late_new_custody_not_created', 'first_export_after_native_epoch_activation']:
        require(run[field] is True, 'joint observation missing: ' + field)
    require(run['joint_selection_height'] == 4 and run['old_durable_fences'] == 3
            and run['new_durable_approvals'] == 3, 'joint quorum observation differs')
    for field in ['controller_generated_epoch_approvals', 'controller_installed_epoch_activation']:
        require(type(run[field]) is int and run[field] == 0, 'controller generated joint authority')
    require(run['full_fault_profile_run'] is False and run['arbitrary_overlapping_membership_qualified'] is False,
            'joint cycle exceeds its profile')


def verify_custody(native, config, state, old, old_head, root, replica, run):
    import interstellar_mesh as mesh
    from regional_bft_joint_epoch import FORMAT
    require(config['format'] == old_head['format'] == FORMAT, 'explicit joint wrapper required')
    context = native.call('bft-context')
    require(context['rules'] == 'RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1'
            and state['validator_epoch'] == run['activated_epoch']
            and len(context['epochs']) == 1, 'exact native joint activation required')
    statement = context['epochs'][0]['statement']
    joint = config['joint_epoch']
    require(statement['validators'] == [v['key'] for v in joint['validators']]
            and statement['closing_height'] == joint['select_height'] == 4, 'pinned joint intent differs')
    for field in ['approval_dir', 'approval_head', 'signer_dir', 'head_file', 'key_file']:
        path = Path(joint[field])
        require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(), 'joint custody escapes fixture')
    binding = dict(currency=state['currency'], region=state['region'], key=joint['key'])
    approval_head = mesh.load(Path(joint['approval_head']), 8*1024*1024)
    approval = native.call('signer-status', '--signer-dir', joint['approval_dir'])
    require(approval_head['format'] == FORMAT and approval_head['binding'] == approval['binding'] == binding
            and approval_head['head'] == approval['lock_head']
            and approval_head['pending'] is None and approval_head['outbox'] is None,
            'candidate caller/native lock unresolved')
    new_head = mesh.load(Path(joint['head_file']), 8*1024*1024)
    require(new_head['format'] == FORMAT and new_head['binding'] == binding
            and all(new_head[k] is None for k in ['pending', 'outbox', 'initialization']),
            'new caller initialization/response unresolved')
    if replica == 0:
        require(old['records'] == 0 and old['state']['epoch_fence'] is None
                and approval['votes'] == 0 and approval['handoff_statements'] == []
                and new_head['head'] is None and not Path(joint['signer_dir']).exists()
                and not Path(config['key_file']).exists() and not Path(joint['key_file']).exists(),
                'keyless carrier acquired voting authority')
    else:
        require(old['state']['epoch_fence'] == run['activated_epoch']
                and approval['votes'] == 1 and approval['handoff_statements'] == [statement],
                'old fence or exact candidate approval differs')
        new = native.call('bft-status', '--signer-dir', joint['signer_dir'])
        require(new['binding'] == new_head['binding'] and new['head'] == new_head['head']
                and new['records'] > 0, 'new voting caller/native head differs')
    require(len({Path(config['head_file']).parent, Path(joint['head_file']).parent,
                 Path(joint['approval_head']).parent}) == 3, 'joint caller directories overlap')
    return dict(replica=replica, native_epoch_matches=True, separately_retained_heads_match=True,
                exact_candidate_approvals=approval['votes'], keyless_nonparticipant=replica == 0,
                old_fence_retained=replica != 0, no_first_signing=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'manifest', 'run-report', 'binary', 'root', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    verify(parser.parse_args(), joint=True)
