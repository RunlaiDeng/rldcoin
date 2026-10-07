"""Stopped-only bounded Native envelope checks; no Runtime or custody recovery."""
from pathlib import Path
import tempfile
from types import SimpleNamespace

import interstellar_mesh as mesh
from regional_bft_cold_batch import check_retained
from regional_bft_retention import FORMAT, unpack_state
from regional_bft_pinned_cold import checked_history, check_retained_pinned


def verify_stopped_state(native, config, current, root):
    return _verify_stopped_state(native, config, current, root)


def verify_stopped_state_pinned(native, config, root, expected_history_head):
    """Explicit external head; current height/tip come from pinned Native replay.

    No unpinned sampling, Runtime creation, response recovery or head adoption.
    Empty retained state still requires an actual pinned Native history check.
    """
    current = checked_history(native, expected_history_head)
    return _verify_stopped_state(native, config, current, root, expected_history_head)


def verify_stopped_state_pinned_observed(native, config, root, expected_history_head):
    """One original full pinned plan supplies its own Native height and tip.

    Base profile only. Every complete envelope still undergoes original Native
    verification. Empty state still requires actual pinned history replay.
    The source file must stay byte-identical through this whole read operation.
    """
    from regional_bft_node import private, MAX_STATE
    mesh.require(config['format']=='RLD-REGIONAL-BFT-NODE-V1',
                 'observed stopped check requires explicit base profile')
    directory=Path(config['state'])
    mesh.require(directory.resolve().is_relative_to(root.resolve()),'BFT retention path escapes fixture')
    path=private(directory/'state.json');before=mesh.evidence.read_file(path,MAX_STATE)
    state=unpack_state(mesh.evidence.decode_json(before))
    mesh.require(set(state)=={'format','binding','messages','height','tip','snapshot_cache','cursor'}
        and state['format']==config['format'] and type(state['binding']) is dict
        and set(state['binding'])=={'currency','region','key'}
        and state['binding']['currency']==native.currency and state['binding']['key']==config['key'],
        'BFT retained runtime domain differs')
    mesh.hex32(state['binding']['region'])
    # Basic bounds reject before any Native query; current height/tip are
    # obtained from actual pinned Native replay, never from retained metadata.
    mesh.integer(state['height'],0,64);mesh.integer(state['cursor'],0,2**63-1)
    mesh.hex32(state['tip'])
    with tempfile.TemporaryDirectory(prefix='rld-stopped-bft-observed-') as scratch:
        request=SimpleNamespace(root=Path(scratch).resolve(),native=native,
                                region=state['binding']['region'],state=state)
        pinned=check_retained_pinned(request,expected_history_head,observed=True)
    mesh.require(mesh.evidence.read_file(path,MAX_STATE)==before,'stopped retained state changed during Native verification')
    result=_verify_stopped_state(native,config,pinned['current'],root,expected_history_head,
                                 authenticated_state=(state,pinned))
    mesh.require(mesh.evidence.read_file(path,MAX_STATE)==before,'stopped retained state changed during Native verification')
    return result


def _verify_stopped_state(native, config, current, root, expected_history_head=None,
                         *, authenticated_state=None):
    from regional_bft_node import private, MAX_STATE
    directory = Path(config['state'])
    mesh.require(directory.resolve().is_relative_to(root.resolve()), 'BFT retention path escapes fixture')
    path = private(directory / 'state.json')
    state = (unpack_state(mesh.load(path, MAX_STATE)) if authenticated_state is None
             else authenticated_state[0])
    mesh.require(set(state) == {'format', 'binding', 'messages', 'height', 'tip', 'snapshot_cache', 'cursor'}
                 and state['format'] == config['format']
                 and (config['format'] == 'RLD-REGIONAL-BFT-NODE-V1'
                      or (config['format'] == 'RLD-REGIONAL-BFT-NODE-JOINT-V1'
                          and native.call('bft-context')['rules'] == 'RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1'))
                 and state['binding'] == {'currency': native.currency, 'region': current['region'], 'key': config['key']},
                 'BFT retained runtime domain differs')
    mesh.integer(state['height'], 0, 64)
    mesh.integer(state['cursor'], 0, 2**63-1)
    mesh.hex32(state['tip'])
    mesh.require(current['height'] >= state['height']
                 and (current['height'] != state['height'] or current['tip'] == state['tip'])
                 and isinstance(state['snapshot_cache'], list) and len(state['snapshot_cache']) <= 64,
                 'BFT retained observation exceeds native state')
    for ident in state['snapshot_cache']:
        mesh.hex32(ident)
    # Temporary inputs live outside the private source; no Runtime is opened.
    # The existing Native batch checks every complete envelope and binds exact
    # request bytes, ordered values, domain and nonmutating response flags.
    pinned = None if authenticated_state is None else authenticated_state[1]
    if authenticated_state is None:
        total = sum(len(state['messages'].payload(ident)) for ident in state['messages'])
    else:
        # Already fully authenticated exact batch bytes contain each payload
        # plus one comma per extra item and two brackets per batch: N + B.
        # Reuse only this operation's sizes; unpack and Native checks stay full.
        total = pinned.get('processed_envelope_batch_bytes', 0) - len(state['messages']) - pinned['batches']
        mesh.require(type(total) is int and total >= len(state['messages']),
                     'authenticated complete envelope byte total differs')
    if authenticated_state is None:
        with tempfile.TemporaryDirectory(prefix='rld-stopped-bft-batch-') as scratch:
            request = SimpleNamespace(root=Path(scratch).resolve(), native=native,
                                      region=current['region'], state=state)
            if expected_history_head is None:
                check_retained(request)
            else:
                pinned = check_retained_pinned(request, expected_history_head)
    return {'retention_format': FORMAT, 'messages_authenticated': len(state['messages']),
            'distinct_complete_snapshots': len(state['messages']._snapshots),
            'retained_state_bytes': path.stat().st_size, 'state_limit_bytes': MAX_STATE,
            'expanded_envelope_bytes_authenticated': total, 'full_native_authentication': True,
            'native_inspection_mode': 'bounded complete-envelope batch' if pinned is None
            else 'explicit pinned complete-envelope plan',
            **({} if pinned is None else {'history_head': expected_history_head,
                                         'native_batches': pinned['batches'],
                                         'implicit_head_adoption': False})}
