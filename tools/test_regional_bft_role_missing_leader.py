"""Finite-drill refusal boundaries; simulated reports grant no authority."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_bft_role_missing_leader_campaign import Campaign,carrier_inventory,entry
from verify_regional_bft_role_lifecycle import DRILL_FORMAT,run_profile,verify_ground_config


class RoleMissingLeaderTests(unittest.TestCase):
    def profile(self):
        return dict(format=DRILL_FORMAT,initial_height=14,final_height=16,absent_carrier=0,
                    node_process_starts=9,post_activation_missing_leader_only=True,
                    offline_carrier_private_files_unchanged=True,sealed_source_state_unchanged=True,
                    fresh_full_fault_profile_completed=False)

    def test_changed_timers_or_stopped_height_cannot_be_adopted_from_valid_reports(self):
        config=dict(round_timeout=20,block_interval=1,stop_height=14)
        verify_ground_config(config,14)
        for field,value in (('round_timeout',200),('round_timeout',20.0),('block_interval',True),
                            ('block_interval',2),('stop_height',16)):
            changed=dict(config);changed[field]=value
            with self.assertRaises(ValueError):verify_ground_config(changed,14)

    def test_explicit_finite_drill_never_relabels_ordinary_payment_or_full_profile(self):
        self.assertEqual(run_profile(self.profile()),(True,True,16))
        self.assertEqual(run_profile(dict(format='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1')),(True,False,14))
        self.assertEqual(run_profile(dict(format='RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1')),(False,False,4))
        with self.assertRaises(ValueError):run_profile(dict(format='RLD-JOINT-BFT-SUSTAINED-GROUND-CAMPAIGN-V1'))

    def test_incomplete_wrong_height_process_count_and_keyless_roles_refuse(self):
        for field,value in (('initial_height',11),('final_height',14),('final_height',19),
                            ('final_height',True),('absent_carrier',1),('absent_carrier',True),
                            ('node_process_starts',5),('node_process_starts',20),
                            ('offline_carrier_private_files_unchanged',False),
                            ('sealed_source_state_unchanged',False),
                            ('post_activation_missing_leader_only',False),
                            ('fresh_full_fault_profile_completed',True)):
            with self.subTest(field=field,value=value):
                changed=self.profile();changed[field]=value
                with self.assertRaises(ValueError):run_profile(changed)

    def test_failed_payment_entry_never_inspects_source_or_calls_native(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);run=base/'run.json';cold=base/'cold.json'
            run.write_text(json.dumps(dict(format='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1',completed=False)))
            cold.write_text(json.dumps(dict(format='RLD-ROLE-PAYMENT-STOPPED-COLD-V1',completed=True)))
            args=SimpleNamespace(run_report=run,cold_report=cold)
            with (patch('regional_bft_role_missing_leader_campaign.files',side_effect=AssertionError('private read')),
                  patch('regional_bft_role_missing_leader_campaign.Native',side_effect=AssertionError('native call'))):
                with self.assertRaisesRegex(ValueError,'successful ordinary'):entry(args)

    def test_controller_forbids_consensus_recovery_initialization_and_carriage(self):
        campaign=object.__new__(Campaign)
        prefix=['binary','--dir','existing','--authority','pinned','--currency','pinned']
        for action in ('init','bft-init','joint-voter-init','joint-voter-recover-init','joint-ready-sign',
                       'bft-sign','bft-quorum','bft-timeout-certificate','bft-certify','finalize',
                       'bft-network-check','bft-epoch-activate','bft-epoch-activate-observed',
                       'wallet-sign','bft-submit'):
            with self.assertRaises(ValueError):campaign.invoke([*prefix,action])
        with self.assertRaises(ValueError):campaign.invoke([*prefix,'status'],helper=True)
        with self.assertRaises(ValueError):campaign.invoke([*prefix,'status'],success=False)

    def test_offline_inventory_includes_every_historical_slot_and_exact_names(self):
        names=('earth-0/journal.json','earth-0-signer/votes.json','mesh-0/identity.json',
               'bft-runtime-0/state.json','caller-head-0/head.json','role-voter-1-0/votes.json',
               'role-voter-2-0/votes.json','role-ready-1-0/ready.json','role-ready-2-0/ready.json',
               'role-voter-caller-1-0/head.json','role-voter-caller-2-0/head.json',
               'role-ready-caller-1-0/head.json','role-ready-caller-2-0/head.json',
               'earth-0-key.json','node-0.log','bft-config-0.json','mesh-config-0.json','role-key-62.json')
        inventory={p:('digest',1,0o600,1) for p in (*names,'earth-00/journal.json',
                    'mesh-1/state.json','role-voter-2-1/votes.json','role-key-63.json')}
        original=copy.deepcopy(inventory)
        self.assertEqual(set(carrier_inventory(inventory,0)),set(names))
        self.assertEqual(inventory,original)


if __name__=='__main__':unittest.main()
