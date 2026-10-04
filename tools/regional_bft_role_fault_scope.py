"""Scope a later ground drill to exact successful role-payment/cold evidence.

Report metadata grants no ledger or custody rights. The eventual drill must
recheck actual Native history, every separate head and all retained envelopes.
Legacy/disjoint joint profiles and failed/recovered payment runs cannot enter.
"""
from pathlib import Path
import copy

import interstellar_mesh as mesh
from regional_bft_joint_roles import FORMAT, RULES
from regional_bft_joint_fault_profile import commitment, missing_leader_gate


def protected_paths(manifest):
    # Protect Native/Core and every shipped non-controller Python dependency,
    # including role lifecycle, transport/storage and diagnostic observers.
    result = set()
    for row in manifest['files']:
        name = row['path']
        base = Path(name).name
        if name.startswith(('tools/regional-ledger/', 'crates/rld-core/')) or (
                name.startswith('tools/') and name.endswith('.py')
                and not base.startswith(('test_', 'verify_', 'check_'))
                and '_campaign' not in base
                and base not in {'regional_bft_role_fault_scope.py',
                                 'regional_bft_joint_fault_profile.py'}):
            result.add(name)
    mesh.require({'tools/regional_bft_node.py', 'tools/regional_contact_node.py',
                  'tools/regional_bft_joint_roles.py', 'tools/interstellar_mesh.py'}
                 <= result, 'complete role runtime source inventory required')
    return result


class Scope:
    @staticmethod
    def rebind(config, source, root):
        """Rebind private paths only after separately authenticating a stopped copy.

        This does not copy, open or initialize custody, adopt heads, or establish
        independent protection against running another copy of the same keys.
        Membership, nullable slots and all signing parameters stay exact.
        """
        source, root = Path(source), Path(root)
        mesh.require(source.is_absolute() and root.is_absolute()
                     and '..' not in source.parts and '..' not in root.parts
                     and source.is_dir()
                     and not source.is_relative_to(root)
                     and not root.is_relative_to(source),
                     'separate absolute source and drill directories required')
        for base in (source, root):
            mesh.require(not any(p.is_symlink() for p in (base, *base.parents)),
                         'drill custody roots cannot follow symlinks')
        mesh.require(config['format'] == FORMAT
                     and len(config['handoffs']) == 2
                     and [h['select_height'] for h in config['handoffs']] == [4, 8],
                     'exact stopped role lifecycle paths required')

        def private_path(value):
            mesh.require(isinstance(value, str), 'private custody path required')
            path = Path(value)
            mesh.require(path.is_absolute() and path.is_relative_to(source)
                         and path != source and '..' not in path.parts
                         and path.exists()
                         and not any(p.is_symlink() for p in (path, *path.parents)),
                         'existing anchored private custody path required')
            return str(root / path.relative_to(source))

        rebound = copy.deepcopy(config)
        rebound['state'] = private_path(config['state'])
        original_slots = [config['initial_slot'], *[h['slot'] for h in config['handoffs']]]
        slots = [rebound['initial_slot'], *[h['slot'] for h in rebound['handoffs']]]
        for era, (original, slot) in enumerate(zip(original_slots, slots)):
            if original is None:
                continue
            fields = ('key_file', 'signer_dir', 'head_file',
                      *(('ready_dir', 'ready_head') if era else ()))
            mesh.require(isinstance(original, dict)
                         and set(original) == {'key', *fields},
                         'complete original role custody paths required')
            for field in fields:
                slot[field] = private_path(original[field])
        return rebound

    def __init__(self, run, cold, cycle_manifest, runtime_manifest, run_sha):
        mesh.require(run.get('format') == 'RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1'
                     and run.get('completed') is True and not run.get('failure')
                     and run.get('fixture_only') is True and run.get('live_rld') is False
                     and run.get('owned_process_cleanup_verified') is True
                     and run.get('ordinary_native_startup_used') is True
                     and run.get('carriers') == 5 and run.get('configured_handoffs') == 2
                     and run.get('select_heights') == [4, 8]
                     and run.get('final_height') == 14 and run.get('node_process_starts') == 20
                     and run.get('owner_signing_eras') == [0, 1, 2]
                     and type(run.get('controller_authority_calls')) is int
                     and run['controller_authority_calls'] == 0
                     and run.get('conserved') is True
                     and run.get('minted') == run.get('liquid') == '300'
                     and run.get('final_recipient_native_available') == '10',
                     'exact completed ordinary three-era role payment run required')
        payments = run.get('owner_payments')
        mesh.require(isinstance(payments, list) and len(payments) == 3
                     and all(p.get('era') == n and p.get('native_included') is True
                             and p.get('signature_and_submission_did_not_debit') is True
                             for n, p in enumerate(payments)),
                     'three actual included owner payments required')
        mesh.require(commitment(cycle_manifest) == cycle_manifest['source_set_sha256']
                     and commitment(runtime_manifest) == runtime_manifest['source_set_sha256']
                     and run['runtime_source_set_sha256'] == cycle_manifest['source_set_sha256']
                     and run['implementation'] == cycle_manifest['native_implementation']
                         == runtime_manifest['native_implementation'],
                     'exact sealed cycle/native implementation commitment required')
        mesh.require(cold.get('format') == 'RLD-ROLE-PAYMENT-STOPPED-COLD-V1'
                     and cold.get('completed') is True
                     and cold.get('fixture_only') is True and cold.get('live_rld') is False
                     and cold.get('source_unchanged') is True
                     and cold.get('owned_process_cleanup_verified') is True
                     and cold.get('all_private_fixture_files_unchanged') is True
                     and cold.get('run_report_sha256') == run_sha
                     and cold.get('source_set_sha256') == cycle_manifest['source_set_sha256']
                     and cold.get('native_implementation') == run['implementation']
                     and cold.get('binary_sha256') == run['binary_sha256']
                     and cold.get('mesh_inspection_anchors_sha256') == run['mesh_inspection_anchors_sha256']
                     and cold.get('same_host_three_era_owner_payments_verified') is True
                     and cold.get('final_recipient_native_available') == '10'
                     and cold.get('conserved') is True,
                     'exact full stopped role/payment cold verification required')
        replays = cold.get('native_replays', [])
        mesh.require(len(replays) == 5 and {r['carrier'] for r in replays} == set(range(5))
                     and all(r['height'] == 14 and r['active_role_era'] == 2
                             and r['full_genesis_replay'] is True for r in replays),
                     'five complete selected-era Native prefixes required')
        custody = cold.get('custody_reads', [])
        expected = {(n, era) for era, nodes in enumerate(((1, 2, 3), (0, 1, 2, 3), (0, 2, 3, 4)))
                    for n in nodes}
        mesh.require(len(custody) == 11 and {(r['carrier'], r['era']) for r in custody} == expected
                     and all(r['voter_head_matches'] is True
                             and r['readiness_head_matches'] is bool(r['era'])
                             and r['full_native_cold_custody_authentication'] is True for r in custody),
                     'all original voters/readiness and separate caller heads required')
        for field, authenticated in (('retained_envelopes', 'full_native_authentication'),
                                     ('transport_archives', 'full_cold_authentication')):
            rows = cold.get(field, [])
            mesh.require(len(rows) == 5 and {r['carrier'] for r in rows} == set(range(5))
                         and all(r[authenticated] is True for r in rows),
                         'all retained envelope and transport cold checks required')
        owners = cold.get('ordinary_owner_payments_verified', [])
        mesh.require(len(owners) == 3 and {r['era'] for r in owners} == {0, 1, 2}
                     and all(r['full_native_owner_replay'] is True and r['native_included'] is True
                             and r['old_inputs_consumed'] is True
                             and r['reserved_owned_outputs'] == '0' for r in owners),
                     'cold actual owner inclusion/conservation required')
        old = {row['path']: row for row in cycle_manifest['files']}
        new = {row['path']: row for row in runtime_manifest['files']}
        protected = protected_paths(cycle_manifest)
        mesh.require(protected <= new.keys() and all(old[name] == new[name] for name in protected),
                     'Native/Core/ordinary role runtime differs from the sealed cycle')
        self.run = run

    def gate(self, native, config, absent_carrier):
        mesh.require(config['format'] == FORMAT and len(config['handoffs']) == 2
                     and [h['select_height'] for h in config['handoffs']] == [4, 8],
                     'exact role lifecycle configuration required')
        current = native.call('bft-context')
        mapping = config['handoffs'][1]['validators']
        mesh.require(current['rules'] == RULES
                     and current['context']['currency'] == self.run['currency']
                     and current['context']['parent_height'] == 14
                     and current['active_epoch_proof'] is not None
                     and current['active_epoch_proof']['statement']['number'] == 2
                     and len(current['epochs']) == 2
                     and current['keys'] == [v['key'] for v in mapping]
                     and len({v['node_id'] for v in mapping}) == 4,
                     'current complete Native role membership/prefix differs')
        absent = [v['key'] for v in mapping if v['node_id'] == absent_carrier]
        mesh.require(len(absent) == 1, 'absent carrier must be a current voter')
        return missing_leader_gate(14, current['keys'], absent[0])
