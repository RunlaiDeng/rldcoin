"""Reject inherited fault claims and protect the actual post-handoff runtime."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from regional_bft_joint_fault_profile import Profile, RUNTIME, commitment, missing_leader_gate, bounded_read, LOCK_REFUSAL


class JointFaultScopeTests(unittest.TestCase):
    def test_read_retry_returns_only_the_actual_later_native_response(self):
        retry=[]
        response={'head':'actual-new-head'}
        with patch('regional_bft_joint_fault_profile.time.sleep'):
            call=Mock(side_effect=[ValueError('native rejected: '+LOCK_REFUSAL),response])
            self.assertIs(bounded_read(call,'bft-status','--signer-dir','private',on_retry=lambda:retry.append(True)),response)
        self.assertEqual(call.call_count,2);self.assertEqual(retry,[True])

    def test_read_retry_exhaustion_never_grants_a_response_or_retries_other_failures(self):
        with patch('regional_bft_joint_fault_profile.time.sleep'):
            call=Mock(side_effect=ValueError('native rejected: '+LOCK_REFUSAL))
            with self.assertRaises(ValueError):bounded_read(call,'status')
            self.assertEqual(call.call_count,8)
            for error in ['native rejected: invalid signature', 'native rejected: '+LOCK_REFUSAL+'; altered',
                          'native rejected: lock acquisition failed because the operation would block']:
                call=Mock(side_effect=ValueError(error))
                with self.assertRaises(ValueError):bounded_read(call,'status')
                self.assertEqual(call.call_count,1)

    def test_signing_recovery_and_head_adoption_are_never_retried(self):
        for command in ['bft-sign','bft-epoch-activate','bft-epoch-activate-observed',
                        'signer-recover-handoff','wallet-sign','bft-submit']:
            call=Mock()
            with self.assertRaises(ValueError):bounded_read(call,command)
            call.assert_not_called()

    def evidence(self):
        # Use the real stopped-cycle schema; all cryptographic custody is read
        # again by the actual campaign through native CLI, not granted here.
        run = {'format':'RLD-BFT-JOINT-MULTIREGION-GROUND-CAMPAIGN-V1','completed':True,'failure':None,
            'owned_process_cleanup_verified':True,'preconfigured_autonomous_joint_epoch':True,
            'one_keyless_carrier_never_first_signed':True,'late_new_custody_not_created':True,
            'first_export_after_native_epoch_activation':True,'joint_selection_height':4,
            'old_durable_fences':3,'new_durable_approvals':3,'controller_generated_epoch_approvals':0,
            'controller_installed_epoch_activation':0,'full_fault_profile_run':False,
            'arbitrary_overlapping_membership_qualified':False,'replica_heights':{'earth':[11]*4,'proxima':[4]*4,'andromeda':[4]*4},
            'implementation':'f'*64}
        entries=[dict(path=p,size_bytes=1,sha256='a'*64) for p in sorted(RUNTIME|{'tools/regional-ledger/src/lib.rs','crates/rld-core/src/lib.rs'})]
        manifest=dict(files=entries,native_implementation=run['implementation']);manifest['source_set_sha256']=commitment(manifest)
        run_sha=hashlib.sha256(json.dumps(run,sort_keys=True).encode()).hexdigest()
        cold=dict(format='RLD-NATIVE-JOINT-CYCLE-COLD-VERIFICATION-V1',run_report_sha256=run_sha,
                  source_set_sha256=manifest['source_set_sha256'],native_implementation=run['implementation'],
                  all_private_fixture_files_unchanged=True,owned_process_cleanup_verified=True,
                  native_replays=[{}]*12,recipient_checks=[{}]*12,joint_custody_reads=[{}]*4)
        return run,cold,manifest,copy.deepcopy(manifest),run_sha

    def test_gate_is_the_actual_future_missing_leader_not_legacy_height_nine(self):
        keys=['old-new-0','old-new-1','old-new-2','old-new-3']
        self.assertEqual(missing_leader_gate(11,keys,keys[0]),13)
        self.assertEqual(missing_leader_gate(11,keys,keys[3]),12)
        self.assertEqual(missing_leader_gate(7,keys,keys[0]),9)
        for height,order,absent in [(True,keys,keys[0]),(24,keys,keys[0]),(23,keys,keys[0]),
                                    (11,list(reversed(keys)),keys[0]),(11,keys,'unadmitted')]:
            with self.assertRaises(ValueError):missing_leader_gate(height,order,absent)

    def test_legacy_or_failed_cycle_cannot_supply_joint_fault_scope(self):
        values=self.evidence();Profile(*values)
        for field,value in [('format','RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1'),
                            ('completed',False),('owned_process_cleanup_verified',False),
                            ('controller_installed_epoch_activation',1),
                            ('replica_heights',{'earth':[7]*4,'proxima':[4]*4,'andromeda':[4]*4})]:
            changed=copy.deepcopy(values);changed[0][field]=value
            with self.assertRaises(ValueError):Profile(*changed)

    def test_cold_report_must_bind_exact_source_and_actual_cycle(self):
        values=self.evidence()
        for field,value in [('run_report_sha256','b'*64),('source_set_sha256','b'*64),
                            ('native_implementation','b'*64),('all_private_fixture_files_unchanged',False),
                            ('joint_custody_reads',[{}]*3),('native_replays',[{}]*11)]:
            changed=copy.deepcopy(values);changed[1][field]=value
            with self.assertRaises(ValueError):Profile(*changed)

    def test_controller_changes_do_not_authorize_an_altered_runtime_or_native_core(self):
        values=self.evidence()
        for path in ['tools/regional_bft_node.py','tools/regional_bft_joint_epoch.py',
                     'tools/regional-ledger/src/lib.rs','crates/rld-core/src/lib.rs']:
            changed=copy.deepcopy(values)
            next(x for x in changed[3]['files'] if x['path']==path)['sha256']='b'*64
            changed[3]['source_set_sha256']=commitment(changed[3])
            with self.assertRaises(ValueError):Profile(*changed)
        changed=copy.deepcopy(values);changed[3]['files'].append(dict(path='tools/regional_bft_sustained_campaign.py',size_bytes=1,sha256='b'*64))
        changed[3]['source_set_sha256']=commitment(changed[3]);Profile(*changed)

    def test_rebinding_preserves_key_peer_intent_and_absent_new_journal(self):
        source=Path('/sealed');root=Path('/fresh');joint={'key':'same-key','validators':[{'key':'same-key','node_id':'same-peer'}],
            'select_height':4,**{p:str(source/'private'/p) for p in ['key_file','signer_dir','head_file','approval_dir','approval_head']}}
        config={'format':'RLD-REGIONAL-BFT-NODE-JOINT-V1','joint_epoch':joint}
        rebased=Profile.rebind(config,source,root,'earth')
        self.assertEqual(joint['key'],rebased['joint_epoch']['key']);self.assertEqual(joint['validators'],rebased['joint_epoch']['validators'])
        self.assertEqual(joint['select_height'],rebased['joint_epoch']['select_height'])
        self.assertIsNone(Profile.voter(rebased,'earth',0));self.assertEqual(Profile.voter(rebased,'earth',1),rebased['joint_epoch'])
        changed=copy.deepcopy(config);changed['joint_epoch']['approval_head']='/outside/head'
        with self.assertRaises(ValueError):Profile.rebind(changed,source,root,'earth')


if __name__=='__main__':unittest.main()
