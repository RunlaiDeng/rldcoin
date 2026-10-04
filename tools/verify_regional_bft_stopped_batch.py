"""Stopped-only bounded Native envelope checks; no Runtime or custody recovery."""
from pathlib import Path
import tempfile
from types import SimpleNamespace

import interstellar_mesh as mesh
from regional_bft_cold_batch import check_retained
from regional_bft_retention import FORMAT, unpack_state


def verify_stopped_state(native, config, current, root):
    from regional_bft_node import private, MAX_STATE
    directory = Path(config['state'])
    mesh.require(directory.resolve().is_relative_to(root.resolve()), 'BFT retention path escapes fixture')
    path = private(directory / 'state.json')
    state = unpack_state(mesh.load(path, MAX_STATE))
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
    total = sum(len(state['messages'].payload(ident)) for ident in state['messages'])
    with tempfile.TemporaryDirectory(prefix='rld-stopped-bft-batch-') as scratch:
        check_retained(SimpleNamespace(root=Path(scratch), native=native,
                                       region=current['region'], state=state))
    return {'retention_format': FORMAT, 'messages_authenticated': len(state['messages']),
            'distinct_complete_snapshots': len(state['messages']._snapshots),
            'retained_state_bytes': path.stat().st_size, 'state_limit_bytes': MAX_STATE,
            'expanded_envelope_bytes_authenticated': total, 'full_native_authentication': True,
            'native_inspection_mode': 'bounded complete-envelope batch'}
