"""Actual Rust wallet entry, browser guards, payments and private cold recovery.

Fixed signing seeds and the passphrase below are public no-value fixture inputs.
Generated ciphertext, session tokens, private caller state and logs stay local.
Python remains the independent application/reference controller, never a server
child or a production fallback.
"""
import fcntl
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import termios
import time
import unittest
from urllib.parse import urlsplit

from regional_contact_campaign import Campaign, public, save
from regional_contact_node import Native
from regional_wallet_app import App as PythonApp
import interstellar_mesh as mesh
import interstellar_transfer as wire

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).resolve().parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()
PASS=b'public-ground-test-passphrase-only'


class NativeServer:
    def __init__(self,native,wallet,heads,owner,key=None,miner=None,expected=None,encrypted=None,backup=None,passphrase=None):
        self.native=native;self.wallet=Path(wallet);self.heads=Path(heads);self.owner=owner;self.master=None
        self.log=self.heads.parent/(self.heads.name+'-server.stderr')
        self.errors=open(self.log,'wb');os.chmod(self.log,0o600)
        command=[str(native.binary),'--dir',str(native.ledger),'--authority',native.authority,'--currency',native.currency,
            '--transport-python',str(self.heads.parent/'python-runtime-must-not-exist'),'wallet-app',
            '--wallet-dir',str(wallet),'--head-dir',str(heads),'--owner',owner]
        for name,value in [('key-file',key),('miner',miner),('expected-wallet-head',expected),('encrypted-key',encrypted),('backup-dir',backup)]:
            if value is not None:command.extend(['--'+name,str(value)])
        if passphrase is None:
            self.process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=self.errors)
            descriptor=self.process.stdout.fileno()
        else:
            self.master,slave=os.openpty()
            def terminal():
                os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
            self.process=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=self.errors,preexec_fn=terminal)
            os.close(slave);descriptor=self.master
            deadline=time.monotonic()+35
            try:
                prompt=b''
                while b'Wallet passphrase:' not in prompt:
                    if self.process.poll() is not None:raise ValueError('native terminal startup refused')
                    remaining=max(0,deadline-time.monotonic())
                    if not remaining or not select.select([self.master],[],[],remaining)[0]:raise TimeoutError('native terminal prompt')
                    prompt+=os.read(self.master,4096)
                    if len(prompt)>8192:raise ValueError('native terminal prompt bound')
                # rpassword writes its prompt to /dev/tty, not redirected stderr.
                # Wait until the native terminal has actually disabled echo.
                while termios.tcgetattr(self.master)[3]&termios.ECHO:
                    if time.monotonic()>=deadline:raise TimeoutError('native terminal echo')
                    time.sleep(.01)
                os.write(self.master,passphrase+b'\n')
            except BaseException:
                self.stop(startup_failure=True);raise
        try:
            deadline=time.monotonic()+35;raw=b''
            startup=None
            while startup is None:
                if self.process.poll() is not None:raise ValueError('native wallet startup refused: '+self.log.read_text()[:2048])
                wait=max(0,deadline-time.monotonic())
                if not wait or not select.select([descriptor],[],[],wait)[0]:raise TimeoutError('native startup response')
                raw+=os.read(descriptor,4096)
                if len(raw)>8192:raise ValueError('native startup response bound')
                for line in raw.splitlines(keepends=True):
                    if line.startswith(b'{') and line.endswith(b'\n'):startup=json.loads(line)
            url=urlsplit(startup['local_wallet_url'])
            if url.hostname!='127.0.0.1' or url.scheme!='http':raise ValueError('native server is not loopback')
            self.origin=f'http://127.0.0.1:{url.port}';self.port=url.port;self.token=url.fragment
            if not startup['fixture_only'] or startup['live_rld'] or len(self.token)!=64:raise ValueError('native startup domain')
        except BaseException:
            self.stop(startup_failure=True);raise

    def request(self,action,values=None,headers=None,raw=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=35)
        fields={'Content-Type':'application/json','Origin':self.origin,'Authorization':'Bearer '+self.token}
        if headers:fields.update(headers)
        body=raw if raw is not None else json.dumps({'action':action,**(values or {})})
        try:
            conn.request('POST','/api',body,fields);response=conn.getresponse()
            if not 0<=int(response.getheader('Content-Length','-1'))<=8*1024*1024:raise ValueError('native response bound')
            value=json.loads(response.read());return response.status,value
        finally:conn.close()

    def act(self,action,**values):
        status,value=self.request(action,values)
        if status!=200:raise ValueError(value.get('error','native HTTP refusal'))
        return value

    def stop(self,startup_failure=False):
        if hasattr(self,'process'):
            if self.process.poll() is None:self.process.terminate()
            try:result=self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait();raise AssertionError('native wallet normal stop exceeded five seconds')
            if self.process.stdout:self.process.stdout.close()
            if result!=0 and not startup_failure:raise AssertionError(f'native wallet exit {result}')
        if self.master is not None:os.close(self.master);self.master=None
        self.errors.close()


class NativeWalletHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-wallet-http-')
        self.root=Path(self.temp.name).resolve()/'fixture';self.c=Campaign(BINARY,self.root)
        for _ in range(4):self.c.mine('earth')
        self.c.certify('earth');self.native=Native(BINARY,self.root/'earth',public(1),self.c.currency)
        self.key=self.root/'public-fixture-key.json';save(self.key,{'secret_key':bytes([10]*32).hex()});self.key.chmod(0o600)
        self.wallet=self.root/'wallet';self.heads=self.root/'heads';self.servers=[]
        self.server=self.start(self.wallet,self.heads,public(10),key=self.key,miner=public(10))
        self.server.act('init')

    def start(self,wallet,heads,owner,**kwargs):
        server=NativeServer(self.native,wallet,heads,owner,**kwargs);self.servers.append(server);return server

    def tearDown(self):
        for server in reversed(self.servers):
            if not server.errors.closed:server.stop()
        self.c.cleanup();self.temp.cleanup()

    def request(self,amount='30',**extra):
        return {'owner':public(10),'inputs':None,'outputs':[{'owner':public(14),'amount':amount}],
            'remote':None,'fee':'1','valid_for_blocks':8,**extra}

    def sign(self,server,prepared):
        return server.act('sign',review_id=prepared['review_id'],review_commitment=prepared['review_commitment'])

    def file(self,name,value):
        path=self.root/name;save(path,value);return path

    def test_actual_entry_has_no_python_child_and_reference_preparation_matches(self):
        command=subprocess.check_output(['ps','-o','comm=','-p',str(self.server.process.pid)],text=True).strip()
        self.assertIn('rld-regional-ledger-candidate',command)
        inventory=subprocess.check_output(['ps','-axo','ppid,pid,comm'],text=True)
        self.assertFalse(any(row.split() and row.split()[0]==str(self.server.process.pid) for row in inventory.splitlines()))
        state=mesh.load(self.heads/'wallet-client.json',8*1024*1024)
        reference=PythonApp(self.native,self.wallet,self.root/'reference-heads',public(10),expected=state['head'],key=self.key,miner=public(10))
        try:
            req=self.request();a=self.server.act('prepare',request=req);b=reference.act({'action':'prepare','request':req})
            self.assertEqual(wire.canonical({k:v for k,v in a.items() if k!='review_id'}),wire.canonical({k:v for k,v in b.items() if k!='review_id'}))
            a=self.server.act('status');b=reference.status();a.pop('checked_at_unix');b.pop('checked_at_unix')
            self.assertEqual(wire.canonical(a),wire.canonical(b))
        finally:reference.close()
        self.assertEqual(state,mesh.load(self.heads/'wallet-client.json',8*1024*1024))

    def test_http_host_origin_capability_framing_and_nested_duplicate_refusals(self):
        before=(self.heads/'wallet-client.json').read_bytes();wallet=(self.wallet/'wallet.json').read_bytes()
        for headers in [{'Host':'attacker.invalid'},{'Origin':'http://attacker.invalid'},{'Authorization':'Bearer '+'0'*64},
                {'Sec-Fetch-Site':'cross-site'},{'Content-Type':'text/plain'}]:
            status,_=self.server.request('status',headers=headers,raw='{}');self.assertNotEqual(status,200)
        for headers in [{'Transfer-Encoding':'chunked'},{'Content-Length':str(2*1024*1024+1)}]:
            try:
                status,_=self.server.request('status',headers=headers,raw='{}');self.assertNotEqual(status,200)
            except (ConnectionResetError,http.client.RemoteDisconnected):
                # Closing a refused frame with unread body may reset TCP. It
                # grants no response, mutation or permission to retry the frame.
                pass
            self.server.act('status')
        for raw in ['{"action":"status","action":"init"}','{"action":"prepare","request":{"fee":"1","fee":"2"}}',
                '{"action":"status","key_file":"/private/key"}','{"action":"backup","output":"/private/backup"}']:
            status,_=self.server.request('status',raw=raw);self.assertNotEqual(status,200)
        conn=http.client.HTTPConnection('127.0.0.1',self.server.port);conn.request('GET','/');r=conn.getresponse();data=r.read()
        self.assertEqual(r.status,200);self.assertNotIn(self.server.token.encode(),data);self.assertEqual(r.headers['Cache-Control'],'no-store')
        self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy']);conn.close()
        for name in ('app.js','app.css'):
            conn=http.client.HTTPConnection('127.0.0.1',self.server.port);conn.request('GET','/'+name);r=conn.getresponse()
            self.assertEqual(r.read(),(Path(__file__).parent/'regional-wallet'/name).read_bytes());self.assertEqual(r.status,200);conn.close()
        raw=f'POST /api HTTP/1.1\r\nHost: 127.0.0.1:{self.server.port}\r\nHost: 127.0.0.1:{self.server.port}\r\nContent-Length: 2\r\n\r\n{{}}'.encode()
        with socket.create_connection(('127.0.0.1',self.server.port),timeout=5) as sock:
            sock.sendall(raw);self.assertIn(b'409',sock.recv(4096).split(b'\r\n')[0])
        self.assertEqual(before,(self.heads/'wallet-client.json').read_bytes());self.assertEqual(wallet,(self.wallet/'wallet.json').read_bytes())

    def test_payment_stale_review_reservations_and_actual_inclusion(self):
        p=self.server.act('prepare',request=self.request());head=mesh.load(self.heads/'wallet-client.json',8*1024*1024)['head']
        self.c.mine('earth')
        with self.assertRaises(ValueError):self.sign(self.server,p)
        self.assertEqual(head,mesh.load(self.heads/'wallet-client.json',8*1024*1024)['head'])
        p=self.server.act('prepare',request=self.request());signed=self.sign(self.server,p)
        v=self.server.act('status')['wallet'];self.assertEqual(v['reserved_owned_outputs'],'100')
        recovered=self.server.act('recover',intent=signed['intent_id']);self.assertEqual(recovered['commands'],signed['commands'])
        self.server.act('submit',intent=signed['intent_id']);v=self.server.act('status')['wallet']
        self.assertEqual(v['reserved_owned_outputs'],'0');self.assertEqual(v['signed'][0]['state'],'INCLUDED_IN_LOCAL_LEDGER')
        with self.assertRaises(ValueError):self.server.act('submit',intent=signed['intent_id'])
        self.c.audit('native HTTP payment and duplicate inclusion refusal')

    def test_bounded_review_cache_cancel_and_wrong_commitment_never_sign(self):
        before=(self.heads/'wallet-client.json').read_bytes();wallet=(self.wallet/'wallet.json').read_bytes()
        reviews=[self.server.act('prepare',request=self.request()) for _ in range(4)]
        with self.assertRaises(ValueError):self.server.act('prepare',request=self.request())
        with self.assertRaises(ValueError):self.server.act('sign',review_id=reviews[0]['review_id'],review_commitment='0'*64)
        canceled=self.server.act('cancel-review',review_id=reviews[0]['review_id'])
        self.assertFalse(canceled['signed_inputs_released'])
        with self.assertRaises(ValueError):self.sign(self.server,reviews[0])
        self.server.act('prepare',request=self.request())
        self.assertEqual(before,(self.heads/'wallet-client.json').read_bytes());self.assertEqual(wallet,(self.wallet/'wallet.json').read_bytes())

    def test_keyless_unsigned_and_signed_pending_restart_uses_exact_original_custody(self):
        p=self.server.act('prepare',request=self.request());prepared={k:v for k,v in p.items() if k!='review_id'}
        self.server.stop();previous=mesh.load(self.heads/'wallet-client.json',8*1024*1024)
        proposed=dict(previous,pending={'prepared':prepared})
        self.native.call('wallet-client-store','--file',self.file('pending-transition.json',{'previous':previous,'proposed':proposed}),
            '--wallet-dir',self.wallet,'--head-dir',self.heads,'--owner',public(10))
        readonly=self.start(self.wallet,self.heads,public(10));v=readonly.act('status')
        self.assertEqual(v['wallet']['signed'],[]);self.assertFalse(v['signing_enabled'])
        self.assertIsNone(mesh.load(self.heads/'wallet-client.json',8*1024*1024)['pending'])
        p=readonly.act('prepare',request=self.request());prepared={k:v for k,v in p.items() if k!='review_id'};readonly.stop()
        previous=mesh.load(self.heads/'wallet-client.json',8*1024*1024);proposed=dict(previous,pending={'prepared':prepared})
        self.native.call('wallet-client-store','--file',self.file('signed-transition.json',{'previous':previous,'proposed':proposed}),
            '--wallet-dir',self.wallet,'--head-dir',self.heads,'--owner',public(10))
        signed=self.native.call('wallet-sign','--file',self.file('approved.json',prepared),'--review',prepared['review_commitment'],
            '--wallet-dir',self.wallet,'--expected-wallet-head',previous['head'],'--key-file',self.key)
        self.key.unlink();wallet_before=(self.wallet/'wallet.json').read_bytes();ledger_before=(self.root/'earth/journal.json').read_bytes()
        restored=self.start(self.wallet,self.heads,public(10));v=restored.act('status')
        self.assertFalse(v['signing_enabled']);self.assertEqual(v['wallet']['reserved_owned_outputs'],'100');self.assertEqual(len(v['wallet']['signed']),1)
        self.assertEqual(restored.act('recover',intent=signed['intent_id'])['commands'],signed['commands'])
        self.assertEqual(wallet_before,(self.wallet/'wallet.json').read_bytes());self.assertEqual(ledger_before,(self.root/'earth/journal.json').read_bytes())

    def test_group_fixed_expiry_second_owner_and_mature_remote_payment(self):
        p=self.server.act('prepare',request=self.request(outputs=[{'owner':public(11),'amount':'60'}]));s=self.sign(self.server,p)
        self.server.act('submit',intent=s['intent_id']);self.c.certify('earth')
        owners=sorted([public(10),public(11)]);selection=self.server.act('proposal-inputs',owners=owners)
        inputs=sorted(next(c['id'] for o in selection['owners'] if o['owner']==public(seed) for c in o['coins'] if c['amount']==amount) for seed,amount in [(10,'39'),(11,'60')])
        req={'participants':owners,'inputs':inputs,'outputs':[{'owner':public(10),'amount':'1'}],
            'remote':{'destination':self.c.regions['proxima'],'recipient':{'owner':public(12),'amount':'97'},'destination_fee':'2'},'fee':'1','valid_for_blocks':8}
        built=self.server.act('proposal-build',request=req,selection_pin=selection['pin']);first=self.sign(self.server,built)
        self.c.mine('earth');key=self.file('public-peer-key.json',{'secret_key':bytes([11]*32).hex()});key.chmod(0o600)
        other=self.start(self.root/'peer-wallet',self.root/'peer-heads',public(11),key=key);other.act('init')
        review=other.act('proposal-review',proposal=built['proposal']);self.assertEqual(review['draft']['intent_id'],first['intent_id'])
        self.assertEqual(review['draft']['intent']['valid_through'],built['draft']['intent']['valid_through']);second=self.sign(other,review)
        combined=self.server.act('combine',contributions=first['commands']+second['commands']);self.server.act('submit-combined',combined_id=combined['combined_id'])
        self.c.certify('earth');frame=self.c.cli('earth','contact-export','--export',first['intent_id']);path=self.file('carried-export.json',frame)
        pending=self.c.cli('proxima','contact-apply','--file',path);self.c.cli('proxima','contact-resume','--message',pending['message_id'],'--miner',public(10))
        self.c.mine('proxima');self.c.mine('proxima')
        destination=Native(BINARY,self.root/'proxima',public(1),self.c.currency)
        recipient=NativeServer(destination,self.root/'recipient-wallet',self.root/'recipient-heads',public(12));self.servers.append(recipient)
        expectation={'currency':self.c.currency,'source':self.c.regions['earth'],'destination':self.c.regions['proxima'],'export':first['intent_id'],'recipient':public(12),'net_amount':'95'}
        receipt=recipient.act('receipt',expectation=expectation);self.assertTrue(receipt['original_output_spendable_now'])
        self.assertEqual(self.server.act('status')['wallet']['reserved_owned_outputs'],'0');self.assertEqual(other.act('status')['wallet']['reserved_owned_outputs'],'0')
        self.c.audit('native HTTP group export and independent recipient maturity')

    def test_slow_headers_hold_no_ledger_lock_and_have_one_input_deadline(self):
        with socket.create_connection(('127.0.0.1',self.server.port),timeout=5) as sock:
            started=time.monotonic();sock.sendall(b'GET / HTTP/1.1\r\n')
            observed=self.native.call('status');self.assertIn('ledger',observed)
            time.sleep(.5);sock.sendall(b'H');raw=sock.recv(4096)
            self.assertIn(b'409',raw.split(b'\r\n')[0]);self.assertLess(time.monotonic()-started,4.5)
        self.server.act('status')

    def test_historical_transport_float_encoding_never_grants_liveness_or_money(self):
        transport=self.root/'earth/transport';transport.mkdir(mode=0o700,exist_ok=True)
        value={'currency':self.c.currency,'region':self.c.regions['earth'],'observed_at_unix':123,
            'transport':{'samples':[1.0,-0.0,1e-5,1e-4,1e15,1e16,5e-324,1.23456789]}}
        path=transport/'regional-contact-status.json';save(path,value);path.chmod(0o600)
        status=self.server.act('status')['transport'];self.assertEqual(status['observation'],value['transport'])
        self.assertTrue(status['report_is_historical']);self.assertFalse(status['process_liveness_verified']);self.assertFalse(status['transport_receipt_is_payment_authority'])

    def test_encrypted_terminal_sign_backup_restore_and_second_payment(self):
        key=self.root/'native-generated-key.enc.json';binding=self.native.call('wallet-key-create','--output',key,'--passphrase-stdin',private_input=PASS)
        owner=binding['owner'];p=self.server.act('prepare',request=self.request(outputs=[{'owner':owner,'amount':'60'}]));funded=self.sign(self.server,p)
        self.server.act('submit',intent=funded['intent_id'])
        for _ in range(3):self.c.mine('earth')
        wallet=self.root/'encrypted-wallet';head=self.native.call('wallet-init','--wallet-dir',wallet,'--owner',owner)['wallet_head']
        backups=self.root/'native-backups'
        encrypted=self.start(wallet,self.root/'encrypted-heads',owner,expected=head,encrypted=key,backup=backups,miner=public(10),passphrase=PASS)
        req=self.request();req['owner']=owner;p=encrypted.act('prepare',request=req);signed=self.sign(encrypted,p)
        latest=signed['wallet_head'];backup=encrypted.act('backup');self.assertEqual(backup['wallet_head'],latest)
        self.assertFalse(backup['caller_head_included']);self.assertTrue(backup['complete_native_owner_journal'])
        status=encrypted.act('status');self.assertTrue(status['encrypted_key_enabled'])
        self.assertNotIn(PASS.decode(),json.dumps(status));self.assertNotIn(encrypted.token,json.dumps(status))
        encrypted.stop();fresh=self.root/'restored-encrypted'
        self.native.call('wallet-restore','--file',backup['saved_file'],'--wallet-dir',fresh,'--expected-wallet-head',latest,'--passphrase-stdin',private_input=PASS)
        restored=self.start(fresh,self.root/'restored-heads',owner,expected=latest,encrypted=fresh/'key.enc.json',miner=public(10),passphrase=PASS)
        self.assertEqual(restored.act('recover',intent=signed['intent_id'])['commands'],signed['commands'])
        restored.act('submit',intent=signed['intent_id'])
        for _ in range(3):self.c.mine('earth')
        req['outputs'][0]['amount']='10';p=restored.act('prepare',request=req);second=self.sign(restored,p);restored.act('submit',intent=second['intent_id'])
        self.assertEqual(len(restored.act('status')['wallet']['signed']),2)
        self.c.audit('native HTTP encrypted backup restore and second payment')


if __name__=='__main__':unittest.main()
