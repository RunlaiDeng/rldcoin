"""Actual native wallet CLI: current review, signed debit and recipient replay.

All keys are public fixtures; temporary keys/state never enter the public report.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from regional_contact_campaign import Campaign, public, save
import interstellar_transfer as wire

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeWalletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rld-native-wallet-')
        self.root = Path(self.temp.name).resolve()/'fixture'
        self.c = Campaign(BINARY, self.root)
        self.heads = {}
        self.c.mine('earth')
        self.c.mine('earth')
        self.c.mine('earth')
        self.c.mine('earth')
        self.c.certify('earth')

    def tearDown(self):
        self.c.cleanup()
        self.temp.cleanup()

    def request(self, owner=10, amount=30, remote=None):
        return {'owner':public(owner), 'inputs':None,
            'outputs':[] if remote else [{'owner':public(14), 'amount':str(amount)}],
            'remote':remote, 'fee':'1', 'valid_for_blocks':8}

    def prepare(self, name, request):
        seed=next(s for s in range(10,15) if public(s)==request['owner'])
        self.ensure_wallet(name,seed)
        path=self.root/'wallet-request.json'
        save(path, request)
        prepared=self.c.cli(name,'wallet-prepare','--file',path,'--wallet-dir',self.wallet_dir(name,seed),
            '--expected-wallet-head',self.heads[name,seed])
        path=self.root/'wallet-reviewed.json'
        save(path,prepared)
        return prepared,path

    def sign(self, name, prepared, path, seed=10, review=None, success=True):
        owner=next(s for s in range(10,15) if public(s)==prepared['draft']['request']['owner'])
        key=self.root/f'owner-{seed}.json'
        save(key, {'secret_key':(bytes([seed])*32).hex()})
        key.chmod(0o600)
        result=self.c.cli(name,'wallet-sign','--file',path,'--key-file',key,
            '--review',review or prepared['review_commitment'],'--wallet-dir',self.wallet_dir(name,owner),
            '--expected-wallet-head',prepared['wallet_head'],success=success)
        if success:
            self.heads[name,owner]=result['wallet_head']
            self.save_heads()
        return result

    def wallet_dir(self,name,seed):
        return self.root/f'{name}-wallet-{seed}'

    def save_heads(self):
        save(self.root/'caller-retained-wallet-heads.json',{f'{n}-{s}':h for (n,s),h in self.heads.items()})

    def ensure_wallet(self,name,seed):
        if (name,seed) not in self.heads:
            result=self.c.cli(name,'wallet-init','--owner',public(seed),'--wallet-dir',self.wallet_dir(name,seed))
            self.heads[name,seed]=result['wallet_head']
            self.save_heads()

    def view(self, name, seed):
        self.ensure_wallet(name,seed)
        return self.c.cli(name,'wallet-view','--wallet-dir',self.wallet_dir(name,seed),'--expected-wallet-head',self.heads[name,seed])

    def receipt(self, expected, success=True):
        path=self.root/'receipt-expectation.json'
        save(path,expected)
        return self.c.cli('proxima','wallet-receipt','--file',path,success=success)

    def test_review_rejection_real_signed_payment_and_current_balance(self):
        before=(self.root/'earth/journal.json').read_bytes()
        prepared,path=self.prepare('earth',self.request())
        self.assertEqual(prepared['draft']['change'],'69')
        self.sign('earth',prepared,path,review='9'*64,success=False)
        self.sign('earth',prepared,path,seed=11,success=False)
        command=self.sign('earth',prepared,path)
        self.assertNotIn((bytes([10])*32).hex(),json.dumps(command))
        self.assertEqual(before,(self.root/'earth/journal.json').read_bytes())
        self.c.mine('earth',command['commands'])
        self.assertEqual(self.view('earth',14)['available'],'30')
        retry=self.sign('earth',prepared,path)
        self.assertTrue(retry['recovered_exact_retry'])
        self.assertEqual(retry['commands'],command['commands'])
        self.c.mine('earth',retry['commands'],success=False)
        self.c.audit('wallet actual signed local payment')

    def test_remote_export_pending_import_maturity_and_original_output_spent(self):
        remote={'destination':self.c.regions['proxima'],
            'recipient':{'owner':public(11),'amount':'99'},'destination_fee':'1'}
        prepared,path=self.prepare('earth',self.request(remote=remote))
        commands=self.sign('earth',prepared,path)
        self.c.mine('earth',commands['commands'])
        export=prepared['draft']['intent_id']
        self.c.certify('earth')
        expected={'currency':self.c.currency,'source':self.c.regions['earth'],
            'destination':self.c.regions['proxima'],'export':export,'recipient':public(11),'net_amount':'98'}
        self.receipt(expected,success=False)
        frame=self.c.cli('earth','contact-export','--export',export)
        frame_path=self.root/'carried-frame.json'
        frame_path.write_bytes(wire.canonical(frame))
        pending=self.c.cli('proxima','contact-apply','--file',frame_path)
        self.assertFalse(pending['import_accepted'])
        self.assertEqual(self.receipt(expected)['state'],'VERIFIED_EVIDENCE_PENDING_IMPORT')
        self.assertEqual(self.view('proxima',11)['available'],'0')
        self.c.cli('proxima','contact-resume','--message',pending['message_id'],'--miner',public(10))
        self.assertEqual(self.receipt(expected)['state'],'IMPORT_ACCEPTED_IMMATURE')
        self.c.mine('proxima')
        self.c.mine('proxima')
        receipt=self.receipt(expected)
        self.assertTrue(receipt['original_output_spendable_now'])
        self.assertFalse(receipt['local_finality_covers_import'])
        wrong=dict(expected,recipient=public(14))
        self.receipt(wrong,success=False)
        wrong=dict(expected,net_amount='99')
        self.receipt(wrong,success=False)
        prepared,path=self.prepare('proxima',self.request(owner=11))
        command=self.sign('proxima',prepared,path,seed=11)
        self.c.mine('proxima',command['commands'])
        receipt=self.receipt(expected)
        self.assertEqual(receipt['state'],'ORIGINAL_OUTPUT_SPENT')
        self.assertTrue(receipt['import_accepted'])
        self.assertFalse(receipt['original_output_spendable_now'])
        self.assertEqual(self.view('proxima',11)['available'],'67')
        self.assertEqual(self.view('proxima',14)['available'],'30')
        self.assertFalse(receipt['transport_receipt_checked'])
        self.c.audit('wallet verified onward-ready local recipient payment')

    def test_pending_reservations_retry_recovery_and_stale_wallet_backup(self):
        self.ensure_wallet('earth',10)
        journal=self.wallet_dir('earth',10)/'wallet.json'
        backup=journal.read_bytes()
        prepared,path=self.prepare('earth',self.request())
        signed=self.sign('earth',prepared,path)
        retained=journal.read_bytes()
        view=self.view('earth',10)
        self.assertEqual(view['reserved_owned_outputs'],'100')
        self.assertEqual(view['available'],'100')
        self.assertEqual(view['signed'][0]['state'],'SIGNED_PENDING_INCLUSION')
        retry=self.sign('earth',prepared,path)
        self.assertEqual(retry['commands'],signed['commands'])
        self.assertEqual(retained,journal.read_bytes())
        another,_=self.prepare('earth',self.request())
        self.assertTrue(set(another['draft']['intent']['inputs']).isdisjoint(prepared['draft']['intent']['inputs']))
        journal.write_bytes(backup)
        result=self.c.cli('earth','wallet-view','--wallet-dir',self.wallet_dir('earth',10),
            '--expected-wallet-head',self.heads['earth',10],success=False)
        self.assertIn('stale backup',result['reason'])
        self.assertEqual(journal.read_bytes(),backup)
        journal.write_bytes(retained)
        recovered=self.c.cli('earth','wallet-recover','--wallet-dir',self.wallet_dir('earth',10),
            '--expected-wallet-head',self.heads['earth',10],'--intent',signed['intent_id'])
        self.assertEqual(recovered['commands'],signed['commands'])
        self.c.mine('earth',recovered['commands'])
        view=self.view('earth',10)
        self.assertEqual(view['reserved_owned_outputs'],'0')
        self.assertEqual(view['signed'][0]['state'],'INCLUDED_IN_LOCAL_LEDGER')

    def test_local_expiry_allows_new_signing_and_retained_wallet_rejects_node_rollback(self):
        request=self.request()
        request['valid_for_blocks']=1
        prepared,path=self.prepare('earth',request)
        signed=self.sign('earth',prepared,path)
        backup=(self.root/'earth/journal.json').read_bytes()
        self.assertEqual(self.view('earth',10)['signed'][0]['state'],'SIGNED_PENDING_INCLUSION')
        self.c.mine('earth')
        self.c.mine('earth',signed['commands'],success=False)
        self.assertEqual(self.view('earth',10)['signed'][0]['state'],'EXPIRED_BEFORE_INCLUSION')
        request=self.request()
        request['inputs']=prepared['draft']['intent']['inputs']
        prepared,path=self.prepare('earth',request)
        self.sign('earth',prepared,path)
        journal=self.root/'earth/journal.json'
        latest=journal.read_bytes()
        journal.write_bytes(backup)
        result=self.c.cli('earth','wallet-view','--wallet-dir',self.wallet_dir('earth',10),
            '--expected-wallet-head',self.heads['earth',10],success=False)
        self.assertIn('rollback',result['reason'])
        self.assertEqual(journal.read_bytes(),backup)
        journal.write_bytes(latest)
        self.c.audit('restored current native history after deliberate old-backup rejection')

    def test_independent_group_remote_payment_requires_all_exact_retained_approvals(self):
        funding=self.request(amount=60)
        funding['outputs'][0]['owner']=public(11)
        prepared,path=self.prepare('earth',funding)
        funded=self.sign('earth',prepared,path)
        self.c.mine('earth',funded['commands'])
        self.c.certify('earth')
        coins_a=self.view('earth',10)['ledger']['coins']
        coins_b=self.view('earth',11)['ledger']['coins']
        own=next(c['id'] for c in coins_a if c['amount']=='39')
        peer=next(c['id'] for c in coins_b if c['amount']=='60')
        self.c.audit('group inputs funded and locally finalized')
        req=self.request(remote={'destination':self.c.regions['proxima'],
            'recipient':{'owner':public(12),'amount':'97'},'destination_fee':'2'})
        req.update(participants=sorted([public(10),public(11)]), inputs=sorted([own,peer]),
            outputs=[{'owner':public(10),'amount':'1'}])
        pa,path=self.prepare('earth',req)
        pa_path=self.root/'group-reviewed-a.json'
        save(pa_path,pa)
        before=(self.root/'earth/journal.json').read_bytes()
        sa=self.sign('earth',pa,pa_path)
        self.assertFalse(sa['retained_approvals_complete'])
        self.assertEqual(sa['required_owners'],req['participants'])
        self.assertEqual(self.view('earth',10)['reserved_owned_outputs'],'39')
        self.assertEqual(self.view('earth',11)['reserved_owned_outputs'],'0')
        self.c.mine('earth',sa['commands'],success=False)
        contributions=self.root/'group-contributions.json'
        save(contributions,sa['commands'])
        self.c.cli('earth','wallet-combine','--file',contributions,success=False)
        save(contributions,[sa['commands'][0],sa['commands'][0]])
        self.c.cli('earth','wallet-combine','--file',contributions,success=False)
        self.assertEqual(before,(self.root/'earth/journal.json').read_bytes())
        self.c.audit('partial missing and duplicate approvals preserve ledger value')
        req=dict(req,owner=public(11))
        pb,path=self.prepare('earth',req)
        sb=self.sign('earth',pb,path,seed=11)
        self.assertEqual(sa['intent_id'],sb['intent_id'])
        self.assertEqual(self.view('earth',11)['reserved_owned_outputs'],'60')
        recovered=self.c.cli('earth','wallet-recover','--wallet-dir',self.wallet_dir('earth',10),
            '--expected-wallet-head',sa['wallet_head'],'--intent',sa['intent_id'])
        self.assertEqual(recovered['commands'],sa['commands'])
        save(contributions,[sb['commands'][0],recovered['commands'][0]])
        combined=self.c.cli('earth','wallet-combine','--file',contributions)
        self.assertTrue(combined['complete_owner_authorization'])
        self.assertEqual(before,(self.root/'earth/journal.json').read_bytes())
        self.c.audit('all retained approvals combined without ledger mutation')
        self.c.mine('earth',combined['commands'])
        self.c.certify('earth')
        self.c.audit('complete group export debited and finalized')
        for seed in (10,11):
            view=self.view('earth',seed)
            self.assertEqual(view['reserved_owned_outputs'],'0')
            record=next(r for r in view['signed'] if r['intent_id']==sa['intent_id'])
            self.assertEqual(record['state'],'INCLUDED_IN_LOCAL_LEDGER')
            self.assertFalse(record['retained_approvals_complete'])
        frame=self.c.cli('earth','contact-export','--export',sa['intent_id'])
        frame_path=self.root/'group-carried-frame.json'
        frame_path.write_bytes(wire.canonical(frame))
        pending=self.c.cli('proxima','contact-apply','--file',frame_path)
        self.assertFalse(pending['import_accepted'])
        expected={'currency':self.c.currency,'source':self.c.regions['earth'],
            'destination':self.c.regions['proxima'],'export':sa['intent_id'],
            'recipient':public(12),'net_amount':'95'}
        self.assertEqual(self.receipt(expected)['state'],'VERIFIED_EVIDENCE_PENDING_IMPORT')
        self.c.audit('group evidence pending without recipient credit')
        self.c.cli('proxima','contact-resume','--message',pending['message_id'],'--miner',public(10))
        self.assertEqual(self.receipt(expected)['state'],'IMPORT_ACCEPTED_IMMATURE')
        self.c.audit('group unique import accepted before maturity')
        self.c.mine('proxima')
        self.c.mine('proxima')
        self.assertEqual(self.view('proxima',12)['available'],'95')
        self.c.mine('earth',combined['commands'],success=False)
        self.c.audit('independently retained group consent, native remote debit and matured recipient value')
        if os.environ.get('RLD_GROUP_WALLET_REPORT'):
            save(Path(os.environ['RLD_GROUP_WALLET_REPORT']), {
                'format':'RLD-NATIVE-GROUP-WALLET-CAMPAIGN-V1',
                'currency':self.c.currency,'implementation':self.c.bootstrap['currency']['implementation'],
                'regions':self.c.regions,'intent_id':sa['intent_id'],
                'participants':req['participants'],'selected_input_total':'99',
                'input_amounts':pa['draft']['input_amounts'],
                'local_refund':'1','local_fee':'1','gross_remote_payment':'97',
                'destination_fee':'2','mature_recipient_net':'95',
                'only_own_inputs_reserved':True,'partial_mining_refused':True,
                'missing_and_duplicate_approvals_refused':True,
                'exact_partial_recovery_after_cli_restart':True,
                'complete_combination_does_not_change_ledger':True,
                'all_owner_journals_observe_same_included_intent':True,
                'replay_does_not_refund_included_export':True,
                'checks':self.c.checks,'candidate_only':True,'same_host':True,
                'independent_operators_qualified':False,'cross_device_recovery_qualified':False,
                'physical_contact_qualified':False,'wallet_ui_complete':False})


if __name__=='__main__':
    unittest.main()
