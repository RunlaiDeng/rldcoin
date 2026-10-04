"""Real encrypted native keys, HTTP consent, complete backup and fresh restore.

Password here is deliberately public ground test data. Generated seeds, encrypted
files, activation/session and wallet state are private temporary inputs, never reports.
"""
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from regional_contact_campaign import Campaign, public, save
from regional_contact_node import Native
from regional_wallet_app import App, Server

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()
PASS=b'public-ground-test-passphrase-only'


class EncryptedWalletCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-wallet-custody-')
        self.root=Path(self.temp.name).resolve()/'fixture'
        self.c=Campaign(BINARY,self.root)
        for _ in range(4):self.c.mine('earth')
        self.c.certify('earth')
        self.native=Native(BINARY,self.root/'earth',public(1),self.c.currency)
        self.issued_before_create=self.native.call('status')['ledger']['minted']
        self.key=self.root/'key.enc.json'
        self.binding=self.native.call('wallet-key-create','--output',self.key,'--passphrase-stdin',private_input=PASS)
        self.owner=self.binding['owner']
        self.wallet=self.root/'wallet'
        self.head=self.native.call('wallet-init','--wallet-dir',self.wallet,'--owner',self.owner)['wallet_head']
        self.apps=[];self.servers=[]

    def tearDown(self):
        for server,thread in self.servers:
            server.shutdown();server.server_close();thread.join(timeout=3)
        for app in self.apps:app.close()
        self.c.cleanup();self.temp.cleanup()

    def reviewed(self,req,wallet,head):
        path=self.root/'request.json';save(path,req)
        prepared=self.native.call('wallet-prepare','--file',path,'--wallet-dir',wallet,'--expected-wallet-head',head)
        save(self.root/'reviewed.json',prepared)
        return prepared,self.root/'reviewed.json'

    def fund(self):
        payer=self.root/'payer';head=self.native.call('wallet-init','--wallet-dir',payer,'--owner',public(10))['wallet_head']
        key=self.root/'fixture-key.json';save(key,{'secret_key':bytes([10]*32).hex()});key.chmod(0o600)
        p,path=self.reviewed({'owner':public(10),'inputs':None,'outputs':[{'owner':self.owner,'amount':'60'}],
            'remote':None,'fee':'1','valid_for_blocks':8},payer,head)
        s=self.native.call('wallet-sign','--file',path,'--key-file',key,'--review',p['review_commitment'],
            '--wallet-dir',payer,'--expected-wallet-head',head)
        self.c.mine('earth',s['commands'])
        for _ in range(3):self.c.mine('earth')

    def http(self,server,action,**values):
        c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=35)
        c.request('POST','/api',json.dumps({'action':action,**values}),
            {'Content-Type':'application/json','Origin':server.origin,'Authorization':'Bearer '+server.token})
        r=c.getresponse();status=r.status;data=json.loads(r.read());c.close();return status,data

    def test_encrypted_http_sign_backup_restore_pending_and_sign_again_with_restored_key(self):
        before=self.issued_before_create
        self.assertNotIn('seed',self.key.read_text());self.assertNotIn('secret_key',self.key.read_text())
        self.assertEqual(before,self.native.call('status')['ledger']['minted'])
        self.fund()
        backups=self.root/'backups';backups.mkdir(mode=0o700)
        app=App(self.native,self.wallet,self.root/'caller-head',self.owner,self.head,
            encrypted_key=self.key,passphrase=PASS,backup_dir=backups,miner=public(10))
        self.apps.append(app);server=Server(app);thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start();self.servers.append((server,thread))
        status,old=self.http(server,'backup');self.assertEqual(status,200,old)
        old_file=Path(old['saved_file']);old_bytes=old_file.read_bytes()
        req={'owner':self.owner,'inputs':None,'outputs':[{'owner':public(14),'amount':'30'}],
            'remote':None,'fee':'1','valid_for_blocks':8}
        status,p=self.http(server,'prepare',request=req);self.assertEqual(status,200,p)
        status,s=self.http(server,'sign',review_id=p['review_id'],review_commitment=p['review_commitment']);self.assertEqual(status,200,s)
        latest=s['wallet_head'];self.assertNotEqual(latest,self.head)
        status,v=self.http(server,'status');self.assertEqual(status,200,v)
        self.assertTrue(v['encrypted_key_enabled']);self.assertTrue(v['backup_enabled'])
        self.assertEqual(v['wallet']['reserved_owned_outputs'],'60');self.assertEqual(v['wallet']['available'],'0')
        for secret in [PASS.decode(),'seed','secret_key',server.token]:self.assertNotIn(secret,json.dumps(v))
        status,_=self.http(server,'backup',output=str(self.root/'attacker.enc'));self.assertNotEqual(status,200)
        self.assertFalse((self.root/'attacker.enc').exists())
        with self.assertRaises(ValueError):
            self.native.call('wallet-restore','--file',old_file,'--wallet-dir',self.root/'stale-restore',
                '--expected-wallet-head',latest,'--passphrase-stdin',private_input=PASS)
        self.assertFalse((self.root/'stale-restore').exists());self.assertEqual(old_bytes,old_file.read_bytes())
        status,b=self.http(server,'backup');self.assertEqual(status,200,b);backup=Path(b['saved_file'])
        self.assertEqual(b['wallet_head'],latest);self.assertTrue(b['complete_native_owner_journal']);self.assertFalse(b['caller_head_included'])
        fresh=self.root/'restore'
        result=self.native.call('wallet-restore','--file',backup,'--wallet-dir',fresh,'--expected-wallet-head',latest,
            '--passphrase-stdin',private_input=PASS)
        self.assertEqual(result['wallet_head'],latest);self.assertFalse(result['caller_head_restored'])
        restored=App(self.native,fresh,self.root/'new-caller-head',self.owner,latest,
            encrypted_key=fresh/'key.enc.json',passphrase=PASS,miner=public(10));self.apps.append(restored)
        self.assertEqual(restored.status()['wallet']['reserved_owned_outputs'],'60')
        self.assertEqual(restored.act({'action':'recover','intent':s['intent_id']})['commands'],s['commands'])
        # A missing key and password do not block exact persisted recovery.
        native_review=self.root/'signed-review.json';save(native_review,{k:x for k,x in p.items() if k!='review_id'})
        retry=self.native.call('wallet-sign','--file',native_review,'--encrypted-key',self.root/'missing-key',
            '--passphrase-stdin','--review',p['review_commitment'],'--wallet-dir',fresh,'--expected-wallet-head',self.head)
        self.assertTrue(retry['recovered_exact_retry']);self.assertEqual(retry['commands'],s['commands'])
        restored.act({'action':'submit','intent':s['intent_id']})
        v=restored.status()['wallet'];self.assertEqual(v['reserved_owned_outputs'],'0');self.assertEqual(v['signed'][0]['state'],'INCLUDED_IN_LOCAL_LEDGER')
        for _ in range(3):self.c.mine('earth')
        req['outputs'][0]['amount']='10'
        p=restored.act({'action':'prepare','request':req})
        again=restored.act({'action':'sign','review_id':p['review_id'],'review_commitment':p['review_commitment']})
        restored.act({'action':'submit','intent':again['intent_id']})
        self.assertEqual(len(restored.status()['wallet']['signed']),2)
        coins=restored.status()['wallet']['ledger']['coins'];self.assertEqual(sum(int(c['amount']) for c in coins),18)
        self.c.audit('generated encrypted owner; backup/restore and two actual native payments conserve')
        report={'format':'RLD-REGIONAL-ENCRYPTED-CUSTODY-GROUND-V1','currency':self.c.currency,
            'random_generated_owner_non_fixture_seed':True,'creation_issues_no_value':True,
            'native_encrypted_signing_and_real_local_inclusion':True,'encrypted_complete_journal_backup':True,
            'pending_reservation_preserved_after_restore':True,'keyless_exact_recovery_after_restore':True,
            'surviving_latest_head_refuses_old_backup':True,'fresh_directory_restored_key_signs_second_payment':True,
            'explicit_restore_does_not_replace_caller_head':True,'private_password_and_key_absent_from_http_status':True,
            'http_cannot_choose_backup_path':True,'final_owner_unspent':'18','conservation':self.c.checks,
            'same_host_same_controller':True,'external_joint_rollback_qualified':False,'cross_device_qualified':False,
            'independent_custody_or_security_review':False,'stellar_cryptography_qualified':False,'live_rld':False}
        if os.environ.get('RLD_CUSTODY_REPORT'):save(Path(os.environ['RLD_CUSTODY_REPORT']),report)

    def test_wrong_password_domains_format_permissions_and_no_overwrite(self):
        raw=self.key.read_bytes()
        with self.assertRaises(ValueError):self.native.call('wallet-key-check','--encrypted-key',self.key,'--owner',self.owner,
            '--passphrase-stdin',private_input=b'wrong-ground-password')
        with self.assertRaises(ValueError):App(self.native,self.wallet,self.root/'wrong-caller',self.owner,self.head,
            encrypted_key=self.key,passphrase=b'wrong-ground-password')
        with self.assertRaises(ValueError):self.native.call('wallet-key-create','--output',self.key,'--passphrase-stdin',private_input=PASS)
        self.assertEqual(self.key.read_bytes(),raw)
        with self.assertRaises(ValueError):self.native.call('wallet-key-create','--output',self.root/'weak.enc','--passphrase-stdin',private_input=b'short')
        self.assertFalse((self.root/'weak.enc').exists())
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):self.native.call('wallet-key-check','--encrypted-key',self.key,'--owner',self.owner,'--passphrase-stdin',private_input=PASS)
        self.key.chmod(0o600)
        # No implicit plaintext-key or other-ledger fallback for an encrypted key.
        remote=Native(BINARY,self.root/'proxima',public(1),self.c.currency)
        with self.assertRaises(ValueError):remote.call('wallet-key-check','--encrypted-key',self.key,'--owner',self.owner,'--passphrase-stdin',private_input=PASS)
        self.assertEqual(self.key.read_bytes(),raw)


if __name__=='__main__':unittest.main()
