"""Metadata/scheduling gates only; no fixture authority from simulated reports."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from regional_bft_role_fault_scope import Scope, FORMAT, RULES
from regional_bft_joint_fault_profile import commitment


class RoleFaultScopeTests(unittest.TestCase):
    def private_config(self, source):
        def item(name, directory=False):
            path = source/name
            if directory: path.mkdir()
            else: path.write_bytes(b'retained custody observation')
            return str(path)
        slot = dict(key='unchanged-key', key_file=item('key'),
                    signer_dir=item('voter', True), head_file=item('head'),
                    ready_dir=item('ready', True), ready_head=item('ready-head'))
        return dict(format=FORMAT, state=item('runtime', True),
                    validators=[dict(key='old', node_id='pinned')],
                    initial_slot=None, block_interval=1, round_timeout=20,
                    stop_height=14,
                    handoffs=[dict(select_height=4, validators=[], slot=slot),
                              dict(select_height=8, validators=[], slot=None)])

    def test_rebinding_preserves_all_nonpath_values_and_null_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();source=base/'source';source.mkdir();root=base/'drill'
            config=self.private_config(source);original=copy.deepcopy(config)
            result=Scope.rebind(config,source,root)
            self.assertEqual(config,original)
            self.assertIsNone(result['initial_slot']);self.assertIsNone(result['handoffs'][1]['slot'])
            for name in ('format','validators','block_interval','round_timeout','stop_height'):
                self.assertEqual(result[name],original[name])
            for before,after in zip(original['handoffs'],result['handoffs']):
                self.assertEqual(before['validators'],after['validators'])
                self.assertEqual(before['select_height'],after['select_height'])
            self.assertEqual(result['handoffs'][0]['slot']['key'],'unchanged-key')
            for name in ('key_file','signer_dir','head_file','ready_dir','ready_head'):
                self.assertEqual(result['handoffs'][0]['slot'][name],
                                 str(root/Path(original['handoffs'][0]['slot'][name]).relative_to(source)))
            self.assertFalse(root.exists())

    def test_missing_escaped_relative_and_incomplete_paths_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();source=base/'source';source.mkdir();root=base/'drill'
            config=self.private_config(source)
            for value in (str(base/'outside'),str(source/'missing'),'head',str(source/'voter/../head')):
                changed=copy.deepcopy(config);changed['handoffs'][0]['slot']['head_file']=value
                with self.assertRaises(ValueError):Scope.rebind(changed,source,root)
            changed=copy.deepcopy(config);changed['handoffs'][0]['slot'].pop('ready_head')
            with self.assertRaises(ValueError):Scope.rebind(changed,source,root)
            self.assertFalse(root.exists())

    def test_symlinked_custody_refuses_without_following_or_rewriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();source=base/'source';source.mkdir();root=base/'drill'
            config=self.private_config(source);link=source/'head-link';link.symlink_to(source/'head')
            config['handoffs'][0]['slot']['head_file']=str(link)
            with self.assertRaises(ValueError):Scope.rebind(config,source,root)
            self.assertTrue(link.is_symlink());self.assertFalse(root.exists())

    def test_same_nested_relative_and_symlinked_roots_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();source=base/'source';source.mkdir()
            config=self.private_config(source);link=base/'source-link';link.symlink_to(source)
            for src,dst in ((source,source),(source,source/'nested'),(source,base),
                            (Path('relative'),base/'drill'),(link,base/'drill'),
                            (source,base/'other/../source')):
                with self.assertRaises(ValueError):Scope.rebind(config,src,dst)

    def evidence(self):
        files = [dict(path=p, size_bytes=1, sha256='a'*64) for p in (
            'tools/regional_bft_node.py', 'tools/regional_contact_node.py',
            'tools/regional_bft_joint_roles.py', 'tools/interstellar_mesh.py',
            'tools/regional_bft_retention.py', 'tools/regional_bft_observation.py',
            'tools/regional-ledger/src/lib.rs', 'crates/rld-core/src/lib.rs')]
        manifest = dict(files=files, native_implementation='b'*64)
        manifest['source_set_sha256'] = commitment(manifest)
        run = dict(format='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1', completed=True,
            fixture_only=True, live_rld=False, owned_process_cleanup_verified=True,
            ordinary_native_startup_used=True, carriers=5, configured_handoffs=2,
            select_heights=[4,8], final_height=14, node_process_starts=20,
            owner_signing_eras=[0,1,2], controller_authority_calls=0, conserved=True,
            minted='300', liquid='300', final_recipient_native_available='10',
            owner_payments=[dict(era=n,native_included=True,signature_and_submission_did_not_debit=True) for n in range(3)],
            runtime_source_set_sha256=manifest['source_set_sha256'], implementation='b'*64,
            binary_sha256='c'*64, currency='d'*64, mesh_inspection_anchors_sha256='e'*64)
        cold = dict(format='RLD-ROLE-PAYMENT-STOPPED-COLD-V1', completed=True,
            fixture_only=True, live_rld=False, source_unchanged=True,
            owned_process_cleanup_verified=True, all_private_fixture_files_unchanged=True,
            run_report_sha256='f'*64, source_set_sha256=manifest['source_set_sha256'],
            native_implementation='b'*64,binary_sha256='c'*64,mesh_inspection_anchors_sha256='e'*64,
            same_host_three_era_owner_payments_verified=True,final_recipient_native_available='10',conserved=True,
            native_replays=[dict(carrier=n,height=14,active_role_era=2,full_genesis_replay=True) for n in range(5)],
            custody_reads=[dict(carrier=n,era=era,voter_head_matches=True,readiness_head_matches=bool(era),full_native_cold_custody_authentication=True)
                for era,nodes in enumerate(((1,2,3),(0,1,2,3),(0,2,3,4))) for n in nodes],
            retained_envelopes=[dict(carrier=n,full_native_authentication=True) for n in range(5)],
            transport_archives=[dict(carrier=n,full_cold_authentication=True) for n in range(5)],
            ordinary_owner_payments_verified=[dict(era=n,full_native_owner_replay=True,native_included=True,old_inputs_consumed=True,reserved_owned_outputs='0') for n in range(3)])
        return run,cold,manifest,copy.deepcopy(manifest),'f'*64

    def test_exact_profile_accepts_controller_only_additions(self):
        values=self.evidence();Scope(*values)
        values[3]['files'].append(dict(path='tools/new_role_fault_campaign.py',size_bytes=1,sha256='9'*64))
        values[3]['source_set_sha256']=commitment(values[3]);Scope(*values)

    def test_failed_recovered_legacy_and_incomplete_payment_runs_refuse(self):
        for field,value in [('format','RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1'),('completed',False),
                ('failure','retained stage recovery'),('owned_process_cleanup_verified',False),
                ('final_height',12),('owner_signing_eras',[0,1]),('controller_authority_calls',1),
                ('controller_authority_calls',False),('final_recipient_native_available','0')]:
            with self.subTest(field=field,value=value):
                values=self.evidence();values[0][field]=value
                with self.assertRaises(ValueError):Scope(*values)

    def test_pending_payment_and_unsigned_submission_cannot_supply_scope(self):
        for field,value in [('native_included',False),('signature_and_submission_did_not_debit',False),('era',0)]:
            values=self.evidence();values[0]['owner_payments'][2][field]=value
            with self.assertRaises(ValueError):Scope(*values)

    def test_cold_report_requires_exact_run_source_binary_and_setup_binding(self):
        for field in ('run_report_sha256','source_set_sha256','native_implementation','binary_sha256','mesh_inspection_anchors_sha256'):
            values=self.evidence();values[1][field]='9'*64
            with self.assertRaises(ValueError):Scope(*values)
        for field in ('completed','source_unchanged','all_private_fixture_files_unchanged','same_host_three_era_owner_payments_verified','fixture_only'):
            values=self.evidence();values[1][field]=False
            with self.assertRaises(ValueError):Scope(*values)

    def test_all_five_full_native_prefixes_required(self):
        for field,value in [('carrier',1),('height',12),('active_role_era',1),('full_genesis_replay',False)]:
            values=self.evidence();values[1]['native_replays'][0][field]=value
            with self.assertRaises(ValueError):Scope(*values)

    def test_every_separate_historical_custody_head_is_required(self):
        for field,value in [('voter_head_matches',False),('readiness_head_matches',False),('full_native_cold_custody_authentication',False)]:
            values=self.evidence();values[1]['custody_reads'][-1][field]=value
            with self.assertRaises(ValueError):Scope(*values)
        values=self.evidence();values[1]['custody_reads'].pop()
        with self.assertRaises(ValueError):Scope(*values)

    def test_no_digest_only_envelope_transport_or_owner_acceptance(self):
        for field,flag in [('retained_envelopes','full_native_authentication'),('transport_archives','full_cold_authentication'),('ordinary_owner_payments_verified','full_native_owner_replay')]:
            values=self.evidence();values[1][field][0][flag]=False
            with self.assertRaises(ValueError):Scope(*values)
        values=self.evidence();values[1]['ordinary_owner_payments_verified'][2]['reserved_owned_outputs']='20'
        with self.assertRaises(ValueError):Scope(*values)

    def test_native_role_retention_observer_and_transport_changes_refuse(self):
        for path in [r['path'] for r in self.evidence()[2]['files']]:
            values=self.evidence();next(r for r in values[3]['files'] if r['path']==path)['sha256']='9'*64
            values[3]['source_set_sha256']=commitment(values[3])
            with self.assertRaises(ValueError):Scope(*values)

    def context(self):
        mapping=[dict(key=str(n),node_id='carrier-'+str(n)) for n in range(4)]
        config=dict(format=FORMAT,handoffs=[dict(select_height=4,validators=mapping),dict(select_height=8,validators=mapping)])
        context=dict(rules=RULES,context=dict(currency='d'*64,parent_height=14),
            active_epoch_proof=dict(statement=dict(number=2)),epochs=[{},{}],keys=[str(n) for n in range(4)])
        return config,context

    def test_gate_uses_current_native_membership_and_missing_future_leader(self):
        scope=Scope(*self.evidence());config,context=self.context();native=Mock();native.call.return_value=context
        self.assertEqual(scope.gate(native,config,'carrier-0'),17)
        self.assertEqual(scope.gate(native,config,'carrier-2'),15)
        self.assertEqual(native.call.call_args_list[0].args,('bft-context',))

    def test_wrong_native_era_height_currency_keys_or_nonvoter_refuse(self):
        scope=Scope(*self.evidence())
        for mode in ('era','height','currency','keys','nonvoter','legacy'):
            config,context=self.context();absent='carrier-0'
            if mode=='era':context['active_epoch_proof']['statement']['number']=1
            elif mode=='height':context['context']['parent_height']=11
            elif mode=='currency':context['context']['currency']='9'*64
            elif mode=='keys':context['keys'].reverse()
            elif mode=='nonvoter':absent='departed-keyless'
            else:context['rules']='RLD-REGIONAL-BFT-FIXTURE-V1'
            native=Mock();native.call.return_value=context
            with self.assertRaises(ValueError):scope.gate(native,config,absent)
