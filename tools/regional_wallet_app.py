#!/usr/bin/env python3
"""Loopback-only fixture wallet UI; native Rust owns signing, value and recovery."""
import argparse
import fcntl
import getpass
import hmac
import io
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Native

FORMAT = 'RLD-REGIONAL-WALLET-APP-V1'
PROPOSAL_FORMAT = 'RLD-REGIONAL-GROUP-PROPOSAL-V1'
MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
SESSION_SECONDS = 3600
REVIEW_SECONDS = 300
ASSETS = Path(__file__).resolve().parent / 'regional-wallet'


def private_path(path, exists=False):
    path = Path(path)
    mesh.require(path.is_absolute() and not any(p.is_symlink() for p in [path, *path.parents]), 'private path must be absolute without symlinks')
    if exists:
        info = path.lstat()
        mesh.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private file permissions or type invalid')
    return path


class App:
    def __init__(self, native, wallet, heads, owner, expected=None, key=None, miner=None,
                 encrypted_key=None, passphrase=None, backup_dir=None):
        self.native = native
        self.wallet = private_path(wallet)
        self.root = mesh.safe_dir(heads)
        mesh.require(self.wallet != self.root and self.wallet not in self.root.parents and self.root not in self.wallet.parents, 'caller head must be separate from wallet directory')
        self.owner = mesh.hex32(owner)
        self.key = private_path(key, exists=True) if key else None
        mesh.require(not (key and encrypted_key), 'choose exactly one native key format')
        self.encrypted_key = private_path(encrypted_key, exists=True) if encrypted_key else None
        self.passphrase = bytearray(passphrase) if passphrase is not None else None
        self.backup_dir = mesh.safe_dir(backup_dir) if backup_dir else None
        mesh.require(self.encrypted_key is not None or passphrase is None, 'passphrase needs encrypted key')
        self.miner = mesh.hex32(miner) if miner else None
        self.lock = None
        self.failed = False
        self.previews = {}
        self.combinations = {}
        self.recovery_notice = None
        try:
            self.lock = os.open(self.root / '.app.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info=os.fstat(self.lock)
            mesh.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode & 0o077, 'private app lock type or permissions')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.context = native.call('wallet-context')
            if self.encrypted_key:
                mesh.require(self.passphrase is not None, 'encrypted wallet requires terminal unlock')
                binding=native.call('wallet-key-check','--encrypted-key',self.encrypted_key,'--owner',self.owner,
                    '--passphrase-stdin',private_input=self.passphrase)
                mesh.require(binding=={'currency':self.context['currency'],'region':self.context['region'],'owner':self.owner},
                    'encrypted key domain differs')
            mesh.require(self.context['currency'] == native.currency and self.context['fixture_only'] and not self.context['live_rld'], 'wallet app requires exact no-value fixture root')
            self.binding = {'currency':native.currency, 'region':self.context['region'], 'owner':self.owner, 'wallet_dir':str(self.wallet)}
            self.path = self.root / 'wallet-client.json'
            if self.path.exists() or self.path.is_symlink():
                private_path(self.path, exists=True)
                self.saved = mesh.load(self.path, MAX_RESPONSE)
                mesh.require(set(self.saved) == {'format','binding','head','pending'} and self.saved['format'] == FORMAT and self.saved['binding'] == self.binding, 'caller-head binding differs')
                if expected is not None:
                    mesh.require(self.saved['head'] in (None, mesh.hex32(expected)), 'explicit caller head differs from retained state')
                if self.saved['head'] is None and expected is not None:
                    self.native.call('wallet-view', '--wallet-dir', self.wallet, '--expected-wallet-head', expected)
                    self.save(dict(self.saved, head=expected))
            else:
                if expected is not None:
                    mesh.hex32(expected)
                    native.call('wallet-view', '--wallet-dir', self.wallet, '--expected-wallet-head', expected)
                else:
                    mesh.require(not self.wallet.exists(), 'existing wallet needs separately retained latest head')
                self.saved = {'format':FORMAT, 'binding':self.binding, 'head':expected, 'pending':None}
                self.save(self.saved)
            if self.saved['pending'] is not None:
                self.reconcile()
            if self.saved['head'] is not None:
                self.native.call('wallet-view', '--wallet-dir', self.wallet, '--expected-wallet-head', self.saved['head'])
            else:
                mesh.require(not self.wallet.exists(), 'interrupted wallet initialization needs explicit verified caller head')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.passphrase is not None:
            self.passphrase[:] = b'\0' * len(self.passphrase)
            self.passphrase = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def save(self, proposed):
        mesh.require(not self.failed and len(wire.canonical(proposed)) <= MAX_RESPONSE, 'caller-head persistence unavailable or full')
        try:
            mesh.atomic(self.path, proposed)
        except BaseException:
            self.failed = True
            raise
        self.saved = proposed

    def with_json(self, action, value, *args, private_input=None):
        with tempfile.NamedTemporaryFile(dir=self.root, prefix='.request-', suffix='.json') as handle:
            handle.write(wire.canonical(value))
            handle.flush()
            os.fsync(handle.fileno())
            return self.native.call(action, '--commands' if action=='mine' else '--file', handle.name, *args,
                private_input=private_input)

    def wallet_args(self):
        mesh.require(self.saved['head'] is not None, '请先初始化本机钱包')
        return ['--wallet-dir', self.wallet, '--expected-wallet-head', self.saved['head']]

    def retain_review(self, prepared):
        mesh.require(len(self.previews)<4, 'review capacity reached')
        ident=secrets.token_hex(32)
        self.previews[ident]=(time.monotonic(),prepared)
        return {'review_id':ident,**prepared}

    def reconcile(self):
        """Recover existing native consent only; never first-sign at restart."""
        pending = self.saved['pending']
        mesh.require(isinstance(pending,dict) and set(pending)=={'prepared'} and pending['prepared']['wallet_head']==self.saved['head'], 'pending request differs from caller head')
        prepared = pending['prepared']
        try:
            result = self.with_json('wallet-sign', prepared, '--review', prepared['review_commitment'],
                '--recover-only', *self.wallet_args())
            mesh.require(result['recovered_exact_retry'], 'restart must recover existing signature')
        except (OSError, ValueError):
            # An exact unchanged native head proves no new wallet record exists.
            # If it cannot be proved, retain pending bytes and fail closed.
            self.native.call('wallet-view', *self.wallet_args())
            self.save(dict(self.saved, pending=None))
            self.recovery_notice = '上次确认未生成签名；请重新预览并确认。'
            return
        self.save(dict(self.saved, head=result['wallet_head'], pending=None))
        self.recovery_notice = '已恢复上次保存的签名和输入预留，没有再次签名。'

    def status(self):
        mesh.require(not self.failed, '保存失败；保留目录并重启核验')
        view = self.native.call('wallet-view', *self.wallet_args()) if self.saved['head'] else None
        contacts = self.native.call('contact-status')
        transport = None
        status_path = self.native.ledger / 'transport' / 'regional-contact-status.json'
        if status_path.exists() or status_path.is_symlink():
            raw = mesh.load(private_path(status_path, exists=True), MAX_RESPONSE)
            mesh.require(raw['currency'] == self.binding['currency'] and raw['region'] == self.binding['region'], 'transport report identity differs')
            # This is historical process reporting, never authenticated payment
            # authority, present reachability or proof that the process is alive.
            transport = {'reported_at_unix':raw['observed_at_unix'], 'report_is_historical':True,
                'process_liveness_verified':False,'transport_receipt_is_payment_authority':False,
                'observation':raw['transport']}
        return {'format':FORMAT,'context':self.context,'owner':self.owner,'wallet':view,'contacts':contacts,
            'transport':transport,'checked_at_unix':int(time.time()),'signing_enabled':self.key is not None or self.encrypted_key is not None and self.passphrase is not None,
            'encrypted_key_enabled':self.encrypted_key is not None,'backup_enabled':self.encrypted_key is not None and self.passphrase is not None and self.backup_dir is not None,
            'local_block_producer_enabled':self.miner is not None,'recovery_notice':self.recovery_notice,
            'external_rollback_anchor_qualified':False,'remote_current_state_known':False,'live_rld':False}

    def act(self, value):
        mesh.require(isinstance(value,dict) and isinstance(value.get('action'),str), 'invalid action')
        action = value['action']
        fields = {'status':set(),'init':set(),'backup':set(),'prepare':{'request'},'sign':{'review_id','review_commitment'},
            'cancel-review':{'review_id'},'recover':{'intent'},'submit':{'intent'},
            'combine':{'contributions'},'submit-combined':{'combined_id'},'receipt':{'expectation'},
            'proposal-inputs':{'owners'},'proposal-build':{'request','selection_pin'},'proposal-review':{'proposal'}}
        mesh.require(action in fields and set(value)==fields[action]|{'action'}, 'unexpected action or fields')
        mesh.require(not self.failed, '保存失败；保留目录并重启核验')
        if action == 'status':
            return self.status()
        if action == 'init':
            mesh.require(self.saved['head'] is None and not self.wallet.exists(), 'wallet already initialized or interrupted')
            result = self.native.call('wallet-init','--wallet-dir',self.wallet,'--owner',self.owner)
            self.save(dict(self.saved,head=result['wallet_head']))
            return self.status()
        if action == 'receipt':
            expectation = value['expectation']
            mesh.require(expectation.get('currency')==self.context['currency'] and expectation.get('destination')==self.context['region'], 'receipt expectation differs from local currency/destination')
            return self.with_json('wallet-receipt',expectation)
        view=self.native.call('wallet-view', *self.wallet_args())
        if action == 'backup':
            mesh.require(self.encrypted_key is not None and self.passphrase is not None and self.backup_dir is not None
                and self.saved['pending'] is None, 'backup needs encrypted key, configured directory and reconciled consent')
            # Never accept an HTTP path. Do not stream key/backup contents to the browser.
            output=self.backup_dir / ('wallet-backup-'+secrets.token_hex(16)+'.enc.json')
            result=self.native.call('wallet-backup',*self.wallet_args(),'--encrypted-key',self.encrypted_key,
                '--output',output,'--passphrase-stdin',private_input=self.passphrase)
            mesh.require(result['wallet_head']==self.saved['head'], 'backup head differs from caller')
            return {**result,'saved_file':str(output),'retain_latest_head_separately':True}
        now = time.monotonic()
        self.previews = {i:p for i,p in self.previews.items() if now-p[0]<REVIEW_SECONDS}
        self.combinations = {i:p for i,p in self.combinations.items() if now-p[0]<REVIEW_SECONDS}
        if action == 'proposal-inputs':
            owners=value['owners']
            mesh.require(isinstance(owners,list) and 2<=len(owners)<=16 and all(isinstance(o,str) for o in owners), '请选择 2 至 16 个不同的参与者')
            for owner in owners:mesh.hex32(owner)
            mesh.require(owners==sorted(set(owners)) and self.owner in owners, '参与者须唯一、排序并包括本钱包')
            result=self.native.call('wallet-coins','--owner',*owners)
            mesh.require(result['pin']==view['ledger']['pin'], 'wallet state changed; load proposal inputs again')
            reserved={i for record in view['signed'] if record['state']=='SIGNED_PENDING_INCLUSION'
                for i in record['inputs'] if any(c['id']==i for c in view['ledger']['coins'])}
            for owner_view in result['owners']:
                for coin in owner_view['coins']:
                    coin['reserved_by_this_wallet']=coin['id'] in reserved
                owner_view['private_reservations_known']=owner_view['owner']==self.owner
            result['wallet_head']=view['wallet_head']
            return result
        if action == 'proposal-build':
            req=value['request']
            mesh.require(isinstance(req,dict) and 'valid_through' not in req, 'builder requires a new explicit proposal')
            mesh.require(value['selection_pin']==view['ledger']['pin'], 'wallet state changed; load proposal inputs again')
            blocks=req.get('valid_for_blocks')
            mesh.integer(blocks,1,32)
            req=dict(req,owner=self.owner,valid_through=view['ledger']['pin']['height']+blocks)
            mesh.require(isinstance(req.get('participants'),list) and len(req['participants'])>=2, 'proposal needs multiple actual owners')
            prepared=self.with_json('wallet-prepare',req,*self.wallet_args())
            mesh.require(prepared['draft']['pin']==value['selection_pin'], 'wallet state changed; load proposal inputs again')
            proposal={'format':PROPOSAL_FORMAT,'currency':self.context['currency'],'region':self.context['region'],
                'intent_id':prepared['draft']['intent_id'],'request':prepared['draft']['request']}
            return {**self.retain_review(prepared),'proposal':proposal}
        if action == 'proposal-review':
            proposal=value['proposal']
            mesh.require(isinstance(proposal,dict) and set(proposal)=={'format','currency','region','intent_id','request'}
                and proposal['format']==PROPOSAL_FORMAT and proposal['currency']==self.context['currency']
                and proposal['region']==self.context['region'], '提案的格式、货币根或地区不匹配')
            mesh.hex32(proposal['intent_id'])
            req=proposal['request']
            mesh.require(isinstance(req,dict) and isinstance(req.get('participants'),list) and len(req['participants'])>=2
                and req.get('valid_through') is not None, '提案必须固定全部参与者、输入、输出和有效高度')
            prepared=self.with_json('wallet-prepare',dict(req,owner=self.owner),*self.wallet_args())
            mesh.require(prepared['draft']['intent_id']==proposal['intent_id'], '提案付款编号与实际内容不一致')
            return self.retain_review(prepared)
        if action == 'prepare':
            mesh.require(len(self.previews)<4 and isinstance(value['request'],dict), 'review capacity reached')
            request = dict(value['request'])
            mesh.require(request.get('owner',self.owner)==self.owner, 'request belongs to another wallet owner')
            request['owner']=self.owner
            prepared = self.with_json('wallet-prepare',request,*self.wallet_args())
            return self.retain_review(prepared)
        if action == 'cancel-review':
            self.previews.pop(value['review_id'],None)
            return {'review_canceled':True,'signed_inputs_released':False}
        if action == 'sign':
            mesh.require((self.key is not None or self.encrypted_key is not None and self.passphrase is not None)
                and self.saved['pending'] is None, 'read-only wallet or pending recovery')
            mesh.hex32(value['review_id'])
            mesh.require(value['review_id'] in self.previews, '审阅已过期；请重新预览')
            _,prepared = self.previews[value['review_id']]
            mesh.require(value['review_commitment']==prepared['review_commitment'], 'review commitment changed')
            # Record approved operation before asking native Rust to sign.
            self.save(dict(self.saved,pending={'prepared':prepared}))
            try:
                key_args=['--encrypted-key',self.encrypted_key,'--passphrase-stdin'] if self.encrypted_key else ['--key-file',self.key]
                result = self.with_json('wallet-sign',prepared,'--review',prepared['review_commitment'],
                    *key_args,*self.wallet_args(),private_input=self.passphrase)
                self.save(dict(self.saved,head=result['wallet_head'],pending=None))
            except Exception:
                self.previews.clear()
                # A verified unchanged native head permits a fresh review; an
                # ambiguous/persistence failure remains retained and stopped.
                if not self.failed:
                    try:
                        self.reconcile()
                    except Exception:
                        self.failed = True
                raise
            self.previews.clear()
            return result
        if action in ('recover','submit'):
            mesh.hex32(value['intent'])
            result = self.native.call('wallet-recover','--intent',value['intent'],*self.wallet_args())
            if action == 'recover':
                return result
            mesh.require(self.miner is not None, '未配置本地区出块；可下载签名交给本地出块者')
            return self.with_json('mine',result['commands'],'--miner',self.miner)
        if action == 'combine':
            mesh.require(len(self.combinations)<4 and isinstance(value['contributions'],list) and 1<=len(value['contributions'])<=16, 'owner contribution capacity')
            combined = self.with_json('wallet-combine',value['contributions'])
            ident = secrets.token_hex(32)
            self.combinations[ident]=(now,combined)
            return {'combined_id':ident,**combined}
        if action == 'submit-combined':
            mesh.require(self.miner is not None and value['combined_id'] in self.combinations, '组合审阅已失效或没有本地出块者')
            _,combined = self.combinations[value['combined_id']]
            return self.with_json('mine',combined['commands'],'--miner',self.miner)
        raise ValueError('unknown action')


class Server(HTTPServer):
    def __init__(self, app, port=0):
        mesh.integer(port,0,65535)
        self.app = app
        self.token = secrets.token_hex(32)
        self.started = time.monotonic()
        super().__init__(('127.0.0.1',port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(2)
        return conn,address

    def handle_error(self, request, client_address):
        pass  # No request URLs, headers or session capabilities in logs.


class DeadlineInput(io.RawIOBase):
    def __init__(self, connection):
        self.connection=connection
        self.deadline=time.monotonic()+3
    def readable(self):
        return True
    def readinto(self, buffer):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:
            raise TimeoutError('local request input deadline')
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile=io.BufferedReader(DeadlineInput(self.connection),buffer_size=8192)

    def log_message(self, *args):
        pass

    def reply(self, status, raw, content_type='application/json'):
        mesh.require(len(raw)<=MAX_RESPONSE, 'response outside bound')
        self.connection.settimeout(3)
        self.send_response(status)
        for k,v in {'Content-Type':content_type,'Content-Length':str(len(raw)),'Connection':'close',
            'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}.items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection=True

    def check_host(self):
        mesh.require(self.headers.get_all('Host')==[self.server.origin.removeprefix('http://')] and sum(len(k)+len(v) for k,v in self.headers.items())<=8192, 'invalid local host/header bound')

    def do_GET(self):
        try:
            self.check_host()
            assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/app.css':('app.css','text/css; charset=utf-8')}
            mesh.require(self.path in assets,'unknown local asset')
            name,kind=assets[self.path]
            self.reply(200,wire.read_file(ASSETS/name,512*1024),kind)
        except (OSError,ValueError):
            self.reply(403,b'{"error":"Local request refused"}')

    def do_POST(self):
        try:
            self.check_host()
            mesh.require(self.path=='/api' and self.headers.get_all('Origin')==[self.server.origin]
                and self.headers.get('Sec-Fetch-Site','same-origin') in ('same-origin','none')
                and len(self.headers.get_all('Authorization',[]))==1
                and hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer '+self.server.token)
                and time.monotonic()-self.server.started<SESSION_SECONDS, '本机会话无效或已过期')
            mesh.require(self.headers.get_all('Content-Type')==['application/json'] and not self.headers.get_all('Transfer-Encoding')
                and len(self.headers.get_all('Content-Length',[]))==1, 'invalid request framing')
            count=int(self.headers['Content-Length'])
            mesh.integer(count,1,MAX_REQUEST)
            raw=self.rfile.read(count)
            mesh.require(len(raw)==count,'incomplete request')
            value=wire.decode_json(raw)
            result=self.server.app.act(value)
            self.reply(200,wire.canonical(result))
        except (OSError,ValueError,KeyError,TypeError,socket.timeout) as error:
            self.reply(409,wire.canonical({'error':str(error)[:2048],'fresh':False}))
        except Exception:
            self.reply(409,wire.canonical({'error':'本机操作未完成；保留数据并重新核验','fresh':False}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','ledger','wallet-dir','head-dir'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('authority','currency','owner'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--expected-wallet-head')
    p.add_argument('--key-file',type=Path)
    p.add_argument('--encrypted-key',type=Path)
    p.add_argument('--backup-dir',type=Path)
    p.add_argument('--miner')
    p.add_argument('--port',type=int,default=0)
    args=p.parse_args()
    native=Native(args.binary,args.ledger,args.authority,args.currency)
    passphrase=None
    if args.encrypted_key:
        mesh.require(os.isatty(0), 'encrypted app unlock requires a local terminal; no HTTP/argv/env passphrase')
        passphrase=bytearray(getpass.getpass('Wallet passphrase: ').encode('utf-8'))
    try:
        app=App(native,args.wallet_dir,args.head_dir,args.owner,args.expected_wallet_head,args.key_file,args.miner,
            encrypted_key=args.encrypted_key,passphrase=passphrase,backup_dir=args.backup_dir)
    finally:
        if passphrase is not None: passphrase[:] = b'\0' * len(passphrase)
    try:
        with Server(app,args.port) as server:
            # Explicit local startup output is private. The fragment is never
            # sent in HTTP or logged, and frontend immediately removes it.
            print(json.dumps({'local_wallet_url':server.origin+'/#'+server.token,'fixture_only':True,'live_rld':False}),flush=True)
            server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        app.close()


if __name__=='__main__':
    main()
