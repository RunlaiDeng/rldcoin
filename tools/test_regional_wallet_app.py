"""Real loopback wallet UI APIs and native persistence/security boundaries."""
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from regional_contact_campaign import Campaign, public, save
from regional_contact_node import Native
from regional_wallet_app import App, Server, MAX_REQUEST
import interstellar_mesh as mesh

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class WalletAppFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-wallet-app-')
        self.root=Path(self.temp.name).resolve()/'fixture'
        self.c=Campaign(BINARY,self.root)
        for _ in range(4):self.c.mine('earth')
        self.c.certify('earth')
        self.native=Native(BINARY,self.root/'earth',public(1),self.c.currency)
        self.wallet=self.root/'owner-wallet'
        self.heads=self.root/'retained-caller-head'
        self.key=self.root/'owner-key.json'
        save(self.key,{'secret_key':bytes([10]*32).hex()});self.key.chmod(0o600)
        self.app=App(self.native,self.wallet,self.heads,public(10),key=self.key,miner=public(10))
        self.app.act({'action':'init'})
        self.server=Server(self.app)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
        self.app.close();self.c.cleanup();self.temp.cleanup()

    def request(self,action,values=None,headers=None,raw=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=35)
        h={'Content-Type':'application/json','Origin':self.server.origin,'Authorization':'Bearer '+self.server.token}
        if headers:h.update(headers)
        body=raw or json.dumps({'action':action,**(values or {})})
        connection.request('POST','/api',body,h)
        response=connection.getresponse();data=json.loads(response.read());status=response.status
        connection.close();return status,data

    def prepare(self,remote=None):
        req={'owner':public(10),'inputs':None,'outputs':[] if remote else [{'owner':public(14),'amount':'30'}],
            'remote':remote,'fee':'1','valid_for_blocks':8}
        status,p=self.request('prepare',{'request':req});self.assertEqual(status,200,p)
        return p

    def sign(self,p):
        return self.request('sign',{'review_id':p['review_id'],'review_commitment':p['review_commitment']})


class WalletAppTests(WalletAppFixture):
    def test_auth_origin_host_framing_and_static_assets_never_expose_capability(self):
        before=self.app.path.read_bytes()
        for headers in [{'Authorization':'Bearer '+'0'*64},{'Origin':'http://attacker.invalid'},
            {'Host':'attacker.invalid'},{'Sec-Fetch-Site':'cross-site'}]:
            status,_=self.request('status',headers=headers);self.assertNotEqual(status,200)
        status,_=self.request('status',raw='{"action":"status","action":"init"}')
        self.assertNotEqual(status,200)
        status,_=self.request('status',headers={'Content-Length':str(MAX_REQUEST+1)},raw='{}')
        self.assertNotEqual(status,200)
        status,_=self.request('status',values={'key_file':'/other/key'})
        self.assertNotEqual(status,200)
        self.assertEqual(before,self.app.path.read_bytes())
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('GET','/');r=c.getresponse();body=r.read().decode()
        self.assertEqual(r.status,200);self.assertNotIn(self.server.token,body)
        self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])
        self.assertEqual(r.headers['Cache-Control'],'no-store');c.close()
        old=self.server.token
        self.server.token='f'*64
        status,_=self.request('status',headers={'Authorization':'Bearer '+old})
        self.assertNotEqual(status,200)

    def test_opaque_review_native_signature_reservation_and_actual_submission(self):
        p=self.prepare();before=self.native.call('status')['state']
        status,_=self.request('sign',{'review_id':p['review_id'],'review_commitment':'9'*64})
        self.assertNotEqual(status,200)
        status,s=self.sign(p);self.assertEqual(status,200,s)
        self.assertEqual(before,self.native.call('status')['state'])
        status,v=self.request('status');self.assertEqual(status,200)
        self.assertEqual(v['wallet']['reserved_owned_outputs'],'100')
        self.assertEqual(v['wallet']['available'],'100')
        self.assertEqual(v['wallet']['available_onward_export'],'100')
        self.assertNotIn(bytes([10]*32).hex(),json.dumps(v))
        status,recovered=self.request('recover',{'intent':s['intent_id']});self.assertEqual(status,200)
        self.assertEqual(s['commands'],recovered['commands'])
        status,_=self.request('submit',{'intent':s['intent_id']});self.assertEqual(status,200)
        status,v=self.request('status');self.assertEqual(status,200)
        self.assertEqual(v['wallet']['reserved_owned_outputs'],'0')
        self.assertEqual(v['wallet']['signed'][0]['state'],'INCLUDED_IN_LOCAL_LEDGER')
        self.assertFalse(v['wallet']['signed'][0]['local_export_finalized'])
        status,_=self.request('submit',{'intent':s['intent_id']});self.assertNotEqual(status,200)
        self.c.audit('wallet app local signed payment and duplicate submission refusal')

    def test_stale_review_refuses_signing_then_allows_new_explicit_review(self):
        p=self.prepare();head=self.app.saved['head'];self.c.mine('earth')
        status,_=self.sign(p);self.assertNotEqual(status,200)
        self.assertEqual(head,self.app.saved['head']);self.assertIsNone(self.app.saved['pending'])
        self.assertFalse(self.app.failed)
        status,s=self.sign(self.prepare());self.assertEqual(status,200,s)
        self.assertNotEqual(head,self.app.saved['head'])

    def test_recover_only_native_path_and_unsigned_restart_never_first_sign(self):
        p=self.prepare();prepared={k:v for k,v in p.items() if k!='review_id'}
        result=self.c.cli('earth','wallet-sign','--file',self.save_review(prepared),'--review',prepared['review_commitment'],
            '--wallet-dir',self.wallet,'--expected-wallet-head',self.app.saved['head'],'--recover-only','--key-file',self.key,success=False)
        self.assertIn('cannot first-sign',result['reason'])
        head=self.app.saved['head']
        self.app.save(dict(self.app.saved,pending={'prepared':prepared}));self.app.close()
        restored=App(self.native,self.wallet,self.heads,public(10),key=self.key)
        try:
            self.assertEqual(restored.saved['head'],head);self.assertIsNone(restored.saved['pending'])
            v=restored.status();self.assertEqual(v['wallet']['signed'],[])
            self.assertEqual(v['wallet']['reserved_owned_outputs'],'0')
        finally:restored.close()

    def save_review(self,p):
        path=self.root/'reviewed-native.json';save(path,p);return path

    def test_native_signature_survives_lost_response_and_head_write_failure_without_key(self):
        p=self.prepare();previous=self.app.saved['head'];real_save=self.app.save
        def interrupted(proposed):
            if proposed['head']!=previous:raise OSError('fixture post-sign head persistence failure')
            real_save(proposed)
        with patch.object(self.app,'save',side_effect=interrupted):
            status,_=self.sign(p)
        self.assertNotEqual(status,200);self.assertTrue(self.app.failed)
        self.assertIsNotNone(mesh.load(self.app.path,8*1024*1024)['pending'])
        self.app.close();self.key.unlink()
        restored=App(self.native,self.wallet,self.heads,public(10))
        try:
            self.assertNotEqual(previous,restored.saved['head']);self.assertIsNone(restored.saved['pending'])
            v=restored.status();self.assertEqual(v['wallet']['reserved_owned_outputs'],'100')
            recovered=restored.act({'action':'recover','intent':p['draft']['intent_id']})
            self.assertTrue(recovered['recovered_exact_retry'])
            self.assertEqual(len(v['wallet']['signed']),1)
        finally:restored.close()

    def test_surviving_caller_head_rejects_old_wallet_backup_and_preserves_bytes(self):
        path=self.wallet/'wallet.json';backup=path.read_bytes()
        status,_=self.sign(self.prepare());self.assertEqual(status,200)
        latest_head=self.app.path.read_bytes();self.app.close();path.write_bytes(backup)
        with self.assertRaises(ValueError):App(self.native,self.wallet,self.heads,public(10))
        self.assertEqual(path.read_bytes(),backup);self.assertEqual(self.app.path.read_bytes(),latest_head)

    def test_remote_export_finality_and_recipient_states_are_separate(self):
        remote={'destination':self.c.regions['proxima'],'recipient':{'owner':public(11),'amount':'99'},'destination_fee':'1'}
        p=self.prepare(remote);status,s=self.sign(p);self.assertEqual(status,200)
        status,_=self.request('submit',{'intent':s['intent_id']});self.assertEqual(status,200)
        _,v=self.request('status');self.assertFalse(v['wallet']['signed'][0]['local_export_finalized'])
        self.c.certify('earth');_,v=self.request('status');self.assertTrue(v['wallet']['signed'][0]['local_export_finalized'])
        frame=self.c.cli('earth','contact-export','--export',s['intent_id'])
        frame_path=self.root/'carried-frame.json';save(frame_path,frame)
        pending=self.c.cli('proxima','contact-apply','--file',frame_path)
        dest=App(Native(BINARY,self.root/'proxima',public(1),self.c.currency),self.root/'dest-wallet',self.root/'dest-head',public(11))
        expectation={'currency':self.c.currency,'source':self.c.regions['earth'],'destination':self.c.regions['proxima'],
            'export':s['intent_id'],'recipient':public(11),'net_amount':'98'}
        try:
            r=dest.act({'action':'receipt','expectation':expectation});self.assertEqual(r['state'],'VERIFIED_EVIDENCE_PENDING_IMPORT')
            self.c.cli('proxima','contact-resume','--message',pending['message_id'],'--miner',public(10))
            r=dest.act({'action':'receipt','expectation':expectation});self.assertEqual(r['state'],'IMPORT_ACCEPTED_IMMATURE')
            self.c.mine('proxima');self.c.mine('proxima')
            r=dest.act({'action':'receipt','expectation':expectation});self.assertTrue(r['original_output_spendable_now'])
            self.assertFalse(r['remote_current_state_known']);self.assertFalse(r['transport_receipt_checked'])
        finally:dest.close()
        self.c.audit('wallet app source finality, independent destination import and mature receipt')


if __name__=='__main__':unittest.main()

class GroupProposalTests(WalletAppFixture):
    def test_group_builder_exact_proposal_survives_height_progress_and_native_payment(self):
        request={'owner':public(10),'inputs':None,'outputs':[{'owner':public(11),'amount':'60'}],
            'remote':None,'fee':'1','valid_for_blocks':8}
        status,p=self.request('prepare',{'request':request});self.assertEqual(status,200,p)
        status,funded=self.sign(p);self.assertEqual(status,200,funded)
        status,_=self.request('submit',{'intent':funded['intent_id']});self.assertEqual(status,200)
        self.c.certify('earth')
        owners=sorted([public(10),public(11)])
        before_wallet=self.app.wallet.joinpath('wallet.json').read_bytes()
        status,selection=self.request('proposal-inputs',{'owners':owners});self.assertEqual(status,200,selection)
        coins={o['owner']:o for o in selection['owners']}
        self.assertFalse(selection['peer_wallet_reservations_known'])
        self.assertFalse(coins[public(11)]['private_reservations_known'])
        self.assertTrue(coins[public(10)]['private_reservations_known'])
        chosen=sorted([next(c['id'] for c in coins[public(10)]['coins'] if c['amount']=='39'),
            next(c['id'] for c in coins[public(11)]['coins'] if c['amount']=='60')])
        req={'owner':public(10),'participants':owners,'inputs':chosen,
            'outputs':[{'owner':public(10),'amount':'1'}],'remote':{'destination':self.c.regions['proxima'],
            'recipient':{'owner':public(12),'amount':'97'},'destination_fee':'2'},'fee':'1','valid_for_blocks':8}
        before_ledger=self.root.joinpath('earth/journal.json').read_bytes()
        status,built=self.request('proposal-build',{'request':req,'selection_pin':selection['pin']});self.assertEqual(status,200,built)
        proposal=built['proposal'];self.assertEqual(proposal['request']['valid_through'],selection['pin']['height']+8)
        self.assertEqual(before_wallet,self.app.wallet.joinpath('wallet.json').read_bytes())
        self.assertEqual(before_ledger,self.root.joinpath('earth/journal.json').read_bytes())
        status,first=self.sign(built);self.assertEqual(status,200,first)
        self.assertEqual(self.app.status()['wallet']['reserved_owned_outputs'],'39')
        status,again=self.request('proposal-inputs',{'owners':owners});self.assertEqual(status,200,again)
        self.assertTrue(any(c['reserved_by_this_wallet'] for o in again['owners'] if o['owner']==public(10) for c in o['coins']))
        self.c.mine('earth')
        other_key=self.root/'peer-key.json';save(other_key,{'secret_key':bytes([11]*32).hex()});other_key.chmod(0o600)
        other=App(self.native,self.root/'peer-wallet',self.root/'peer-head',public(11),key=other_key)
        try:
            other.act({'action':'init'})
            reviewed=other.act({'action':'proposal-review','proposal':proposal})
            self.assertNotEqual(reviewed['draft']['pin']['height'],built['draft']['pin']['height'])
            self.assertEqual(reviewed['draft']['intent_id'],first['intent_id'])
            second=other.act({'action':'sign','review_id':reviewed['review_id'],'review_commitment':reviewed['review_commitment']})
            self.assertEqual(other.status()['wallet']['reserved_owned_outputs'],'60')
            status,combined=self.request('combine',{'contributions':first['commands']+second['commands']});self.assertEqual(status,200,combined)
            status,_=self.request('submit-combined',{'combined_id':combined['combined_id']});self.assertEqual(status,200)
            self.assertEqual(self.app.status()['wallet']['reserved_owned_outputs'],'0')
            self.assertEqual(other.status()['wallet']['reserved_owned_outputs'],'0')
            self.c.certify('earth')
            frame=self.c.cli('earth','contact-export','--export',first['intent_id']);path=self.root/'proposal-export.json';save(path,frame)
            pending=self.c.cli('proxima','contact-apply','--file',path)
            self.c.cli('proxima','contact-resume','--message',pending['message_id'],'--miner',public(10))
            self.c.mine('proxima');self.c.mine('proxima')
            recipient=Native(BINARY,self.root/'proxima',public(1),self.c.currency).call('wallet-coins','--owner',public(12))
            self.assertEqual(recipient['owners'][0]['spendable'],'95')
            self.c.audit('interactive proposal, later second-owner approval and matured remote net')
            if os.environ.get('RLD_GROUP_PROPOSAL_REPORT'):
                save(Path(os.environ['RLD_GROUP_PROPOSAL_REPORT']),{'format':'RLD-NATIVE-GROUP-PROPOSAL-CAMPAIGN-V1',
                    'currency':self.c.currency,'implementation':self.c.bootstrap['currency']['implementation'],
                    'intent_id':first['intent_id'],'builder_review_height':built['draft']['pin']['height'],
                    'second_owner_review_height':reviewed['draft']['pin']['height'],'fixed_expiry':proposal['request']['valid_through'],
                    'same_exact_intent_across_heights':True,'construction_reserves_or_signs':False,
                    'input_amounts':built['draft']['input_amounts'],'only_owned_inputs_reserved':True,
                    'mature_recipient_net':'95','checks':self.c.checks,'same_host':True,'candidate_only':True,
                    'independent_operators_qualified':False,'cross_device_custody_qualified':False,'physical_contact_qualified':False})
        finally:other.close()

    def test_group_proposal_refuses_stale_selection_wrong_domain_mutation_and_expiry(self):
        # Fund a second actual owner; no fake peer wallet or signing metadata.
        req={'owner':public(10),'inputs':None,'outputs':[{'owner':public(11),'amount':'60'}],
            'remote':None,'fee':'1','valid_for_blocks':8}
        p=self.app.act({'action':'prepare','request':req});s=self.app.act({'action':'sign','review_id':p['review_id'],'review_commitment':p['review_commitment']});self.app.act({'action':'submit','intent':s['intent_id']})
        owners=sorted([public(10),public(11)]);selection=self.app.act({'action':'proposal-inputs','owners':owners})
        inputs=sorted([next(c['id'] for o in selection['owners'] if o['owner']==public(10) for c in o['coins'] if c['amount']=='39'),next(c['id'] for o in selection['owners'] if o['owner']==public(11) for c in o['coins'] if c['amount']=='60')])
        req={'owner':public(10),'participants':owners,'inputs':inputs,'outputs':[{'owner':public(14),'amount':'98'}],
            'remote':None,'fee':'1','valid_for_blocks':1}
        for bad in [[],[public(10),public(10)],['0'*64,public(11)],owners*9]:
            status,_=self.request('proposal-inputs',{'owners':bad});self.assertNotEqual(status,200)
        before=self.app.path.read_bytes();wallet_before=self.wallet.joinpath('wallet.json').read_bytes()
        status,built=self.request('proposal-build',{'request':req,'selection_pin':selection['pin']});self.assertEqual(status,200,built)
        for field,value in [('currency','0'*64),('region','0'*64),('intent_id','0'*64),('format','unbound')]:
            bad=dict(built['proposal'],**{field:value});status,_=self.request('proposal-review',{'proposal':bad});self.assertNotEqual(status,200)
        bad=json.loads(json.dumps(built['proposal']));bad['request']['outputs'][0]['owner']=public(13)
        status,_=self.request('proposal-review',{'proposal':bad});self.assertNotEqual(status,200)
        unbalanced=dict(req,outputs=[{'owner':public(14),'amount':'97'}])
        status,_=self.request('proposal-build',{'request':unbalanced,'selection_pin':selection['pin']});self.assertNotEqual(status,200)
        self.c.mine('earth')
        status,_=self.request('proposal-build',{'request':req,'selection_pin':selection['pin']});self.assertNotEqual(status,200)
        status,_=self.request('proposal-review',{'proposal':built['proposal']});self.assertNotEqual(status,200)
        self.assertEqual(before,self.app.path.read_bytes());self.assertEqual(wallet_before,self.wallet.joinpath('wallet.json').read_bytes())


if __name__=='__main__':
    unittest.main()
