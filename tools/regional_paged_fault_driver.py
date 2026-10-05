"""One bounded full paged fault controller over exact fresh prepared custody.

Only ordinary nodes vote, relay certificates and install/import evidence. The
controller first-signs the three retained owner reviews once, operates processes
and opaque directed outage relays, and obtains fresh Native observations. No
copy, genesis initialization, recovery, vote, checkpoint installation or refund.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

import interstellar_mesh as mesh
from interstellar_mesh_inspection import MeshInspection, config_commitment
from regional_bft_pinned_cold import checked_history
from regional_bft_sustained_campaign import FaultRelay, has_complete_commit_group
from regional_contact_campaign import public
from regional_fixture_native_json import decode_native_json
from regional_fixture_transport_contract import verify_original_limits
from regional_paged_fault_launch import PHASES, SLOTS
from regional_paged_fault_prepared import Bound
from regional_paged_fault_scope import REGIONS, RULES, digest, document, inventory, require, safe
from verify_regional_bft_stopped_batch import verify_stopped_state_pinned

CAPS = dict(earth=27, proxima=24, andromeda=24)
READS = frozenset(('status', 'proof', 'bft-context', 'wallet-receipt', 'wallet-view',
    'history-head', 'history-check', 'bft-status', 'bft-retained-messages', 'bft-network-check-plan'))
WRITES = frozenset(('wallet-sign', 'bft-submit'))


class LiteralFaultRelay(FaultRelay):
    """Keep the legacy ciphertext bounds, with an explicitly bound literal port."""
    def __init__(self, port, target):
        require(type(port) is int and 1 <= port <= 65535 and type(target) is tuple
            and target[0] == '127.0.0.1' and type(target[1]) is int and 1 <= target[1] <= 65535,
            'explicit loopback directed relay endpoints required')
        self.target = target
        self.listener = socket.socket()
        try:
            self.listener.bind(('127.0.0.1', port))
            self.listener.listen(4)
            self.listener.settimeout(.2)
        except BaseException:
            self.listener.close()
            raise
        self.port = port
        self.enabled = False
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.capacity = threading.BoundedSemaphore(2)
        self.workers = []
        self.attempts = self.refused = self.forwarded = self.bytes = 0
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def close(self):
        self.closed.set()
        self.listener.close()
        deadline = time.monotonic() + 5
        for thread in (self.thread, *self.workers):
            thread.join(timeout=max(0, deadline-time.monotonic()))
        require(not self.thread.is_alive() and not any(t.is_alive() for t in self.workers),
            'owned literal outage relay did not stop within original cleanup bound')


def statement_id(value):
    ordered = {k:value[k] for k in ('currency','region','height','block','state','previous','epoch')}
    return hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'
        + json.dumps(ordered,separators=(',',':')).encode()).hexdigest()


def compatible(states, proofs):
    """Observe already fully Native-replayed exact certified prefixes, no authority."""
    require(len(states)==len(proofs)==4, 'all four Native replicas required')
    rows=[]
    for state, proof in zip(states, proofs):
        own={statement_id(s['statement']):s['statement'] for s in proof['snapshots']
            if s['statement']['region']==state['region'] and s['statement']['currency']==state['currency']}
        require(state['finality'] in own, 'current Native finality lacks exact certified checkpoint')
        tip=own[state['finality']]
        require((tip['height'],tip['block'],tip['state'])==(state['height'],state['tip'],state['state']),
            'Native current checkpoint differs')
        rows.append(own)
    for i in range(4):
        for j in range(i+1,4):
            low, high=sorted((i,j),key=lambda n:states[n]['height']);a,z=states[low],states[high]
            require(a['currency']==z['currency'] and a['region']==z['region'], 'replica trust differs')
            tip=rows[high][z['finality']];seen=set()
            while tip['height']>a['height']:
                previous=tip['previous']
                require(previous is not None and previous not in seen and previous in rows[high],
                    'complete certified predecessor observation missing')
                seen.add(previous);parent=rows[high][previous]
                require(parent['height']+1==tip['height'],'certified predecessor height differs');tip=parent
            require(statement_id(tip)==a['finality'] and (tip['block'],tip['state'])==(a['tip'],a['state']),
                'Native certified replicas incompatible')
            if a['height']==z['height']:require(a['ledger']==z['ledger'],'equal checkpoint ledgers differ')
    return min(s['height'] for s in states)


def observation_height(value, pid, currency, certificate, listener, cap):
    require(value['process_id']==pid and value['currency']==currency and value['relay_enabled'] is True,
        'observation belongs to another process/domain')
    transport=value.get('transport')
    if type(transport) is dict and transport.get('progress_observation_available',True) is True:
        tcp=transport['tcp']
        require(tcp['encrypted'] is True and tcp['tls_version']=='TLSv1.3'
            and tcp['fallback_to_plaintext'] is False and tcp['plaintext_selected_explicitly'] is False
            and tcp['tls_cert_sha256']==certificate and tcp['listener']==listener, 'actual TLS observation differs')
        verify_original_limits(tcp['limits'])
    require(not value['rejected'], 'ordinary Native rejected a complete envelope')
    native_busy=False
    for error in value['errors']:
        if error in SERVICE_NATIVE_BUSY_DIAGNOSTICS:
            native_busy=True
            continue
        require(not error.startswith('native rejected:') and any(t in error for t in
            ('Connection refused','[Errno 61]','[Errno 35]','already locked','lock contention',
             'TCP peer refused custody; retain queued evidence','timed out','Connection reset by peer',
             'Broken pipe','UNEXPECTED_EOF_WHILE_READING','TCP stream closed')), 'actual Native/Service error: '+error)
    # Runtime errors omit the command/exit code. Exact lock text is therefore
    # unknown for the entire observation, even if a height remains present.
    # It cannot prove progress or authorize replay/signing; later fresh Native
    # observations and the complete stopped custody checks remain mandatory.
    consensus=value.get('consensus') or {}
    if consensus.get('progress_observation_available',True) is not True or 'height' not in consensus:return None
    height=consensus['height']
    require(type(height) is int and 0<=height<=cap, 'observed original native height cap exceeded')
    if native_busy:return None
    return height


def retain_original_objects(before, after, mutable_manifest):
    """Every original immutable byte remains; one exact manifest may advance.

    This is retention observation only. Native still replays the entire journal
    and its separately retained head, purpose, owner/value and signer history.
    No digest/metadata comparison grants ledger or custody authorization.
    """
    require(type(mutable_manifest) is str and mutable_manifest in before,
        'explicit original stream manifest required')
    require(all(path in after and (path==mutable_manifest or after[path]==row)
        for path,row in before.items()), 'original immutable journal object lost or altered')


class NativeReadBusy(ValueError):
    """Only a reported native OS lock is unknown; other refusals remain failures."""


NATIVE_BUSY_DIAGNOSTICS = frozenset((
    'regional candidate rejected: lock acquisition failed because the operation would block',
    'regional candidate rejected: BFT signer is already locked',
    'regional candidate rejected: complete stream already locked',
))


SERVICE_NATIVE_BUSY_DIAGNOSTICS = frozenset('native rejected: '+v for v in NATIVE_BUSY_DIAGNOSTICS)


def native_read_busy(command, code, diagnostic):
    return command in READS and type(code) is int and code==1 and diagnostic.strip() in NATIVE_BUSY_DIAGNOSTICS


class NativeReceiptNotObserved(ValueError):
    """Only exact Native no-evidence-yet observation; never verified receipt."""


def receipt_not_observed(command, code, diagnostic):
    return (command=='wallet-receipt' and type(code) is int and code==1
        and diagnostic.strip()=='regional candidate rejected: wallet has no independently verified evidence for this export')


class Driver:
    def __init__(self, project, bound, deadline, account):
        require(type(bound) is Bound and bound.native_history_checks==12
            and (bound.stage_seconds,bound.round_seconds,bound.new_height_limit,bound.maturity,bound.quorum)==(600,60,24,2,3)
            and bound.missing_leader_gate==9 and bound.network_authority is False
            and bound.signing_authority is False, 'complete prepared gate and original limits required')
        self.project=safe(project);require(self.project==Path('/Users/galaxy/GitHub/rldcoin')
            and Path.cwd()==self.project,'explicit migrated cwd required')
        require(type(deadline) in (int,float) and math.isfinite(deadline)
            and 0<deadline-time.monotonic()<=600, 'one original600-second total deadline required')
        self.bound,self.root,self.output,self.deadline=bound,safe(bound.root),safe(bound.output),deadline
        require(not self.output.exists() and not (self.root/'fault-scope-started.json').exists()
            and not (self.root/'runtime').exists(), 'once-only fresh runtime/config output required')
        self.account=account
        self.configs={(c.phase,c.region,c.index):c for c in bound.configs}
        require(len(bound.configs)==len(self.configs)==48
            and set(self.configs)=={(p,*s) for p in PHASES for s in SLOTS}, 'complete48phase configs required')
        self.observed=document(self.root/'native-prepared-observation.json')
        self.currency=bound.currency;self.authority=document(self.root/'signed-fresh-bootstrap.json')['currency']['authority']
        self.regions={label:self.observed['heads'][REGIONS.index(label)*4]['region'] for label in REGIONS}
        self.processes,self.logs,self.relays,self.owners,self.cold={},{},[],{},[]
        self.calls,self.starts,self.events,self.terminal=[],0,[],[]
        self.stopped_heads={};self.unknowns=0;self.phase=None;self.signed_count=0;self.prepared_inventory=inventory(self.root)
        self.mesh_anchors={slot:dict(public_key=document(self.root/'mesh'/f'{slot[0]}-{slot[1]}'/'identity.private.json')['public_key'],node_id=self.observed['transport_pins'][i]['node_id'],network=self.currency,config_sha256=config_commitment(json.loads(self.configs[PHASES[-1],*slot].mesh))) for i,slot in enumerate(SLOTS)}
        self.tls_observations=set()
        self.original_states=None;self.original_objects={slot:inventory(self.root/slot[0]/f'native-{slot[1]}') for slot in SLOTS}
        self.original_voter_objects={slot:inventory(self.root/slot[0]/f'voter-{slot[1]}') for slot in SLOTS}
        self.write_counts={command:0 for command in WRITES}

    def remaining(self):
        require(time.monotonic()<self.deadline,'original one600-second fault budget exhausted')
        return self.deadline-time.monotonic()

    def record(self, kind, **data):
        event=dict(kind=kind,phase=self.phase,**data);self.events.append(event)
        print('paged-fault-step '+json.dumps(event,sort_keys=True),flush=True)

    def file(self, name, value):
        self.remaining();path=self.output/(name+'.json');require(not path.exists(),'retain original controller input/response')
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);mesh.atomic(path,value);return path

    def call(self, label, n, command, *args):
        require(command in READS|WRITES,'controller consensus/init/recovery command forbidden')
        require((label,n) in SLOTS,'explicit Native slot required')
        binary=Path(self.configs[PHASES[0],label,n].argv[0])
        started=time.monotonic()
        with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
            result=subprocess.run([str(binary),'--dir',str(self.root/label/f'native-{n}'),
                '--authority',self.authority,'--currency',self.currency,command,*map(str,args)],
                cwd=self.project,input=None,stdout=output,stderr=errors,timeout=min(30,self.remaining()),check=False)
            require(output.tell()<=8*1024**2 and errors.tell()<=65536,'controller Native output capacity')
            errors.seek(0);diagnostic=errors.read(65536).decode(errors='replace')
            call=dict(command=command,region=label,index=n,exit_code=result.returncode,
                wall_seconds=round(time.monotonic()-started,6))
            self.calls.append(call)
            if native_read_busy(command,result.returncode,diagnostic):
                call['observation_kind']='NATIVE_READ_BUSY'
                raise NativeReadBusy('Native observation OS lock unavailable')
            if receipt_not_observed(command,result.returncode,diagnostic):
                call['observation_kind']='NATIVE_RECEIPT_NOT_OBSERVED'
                raise NativeReceiptNotObserved('Native receipt evidence not observed at this replica')
            call['observation_kind']='NATIVE_EXIT_ZERO' if result.returncode==0 else 'FATAL_NATIVE_REFUSAL'
            require(result.returncode==0,'controller Native refusal: '+diagnostic[:2048])
            output.seek(0);answer=decode_native_json(output.read(8*1024**2+1))
        if command in WRITES:self.write_counts[command]+=1
        return answer

    def native(self,label,n):
        driver=self
        class Read:
            currency=driver.currency
            def call(self,*args):return driver.call(label,n,*args)
        return Read()

    def pin_head(self,label,n,prefix):
        require((label,n) not in self.processes,'fixed-head inspection requires stopped own process')
        head=self.call(label,n,'history-head');self.file(prefix+'/head-'+label+'-'+str(n),head)
        checked=checked_history(self.native(label,n),head['history_head'])
        require(checked['region']==self.regions[label] and checked['height']<=CAPS[label], 'stopped Native domain/cap differs')
        self.stopped_heads[label,n]=head['history_head'];return head

    def sign_original(self,label):
        require(label not in self.owners and not self.processes,'owner approval once before node startup required')
        owner=self.root/'fault-owners'/label;caller_path=owner/'caller/head.json';caller=document(caller_path)
        review=document(owner/'unsigned-review.json');request=document(owner/'request.json');wallet=owner/'wallet'
        require(caller['pending'] is None and caller['head']==review['wallet_head']
            and review['draft']['request']==request and document(wallet/'wallet.json')['records']==[], 'original unsigned approval differs')
        before=self.call(label,1,'status')
        require(all(before[k]==review['draft']['pin'][k] for k in ('currency','region','height','tip','state','finality')),
            'original signing-height Native checkpoint changed')
        mesh.atomic(caller_path,dict(caller,pending=dict(intent_id=review['draft']['intent_id'],review=review['review_commitment'])))
        signed=self.call(label,1,'wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',caller['head'],
            '--file',owner/'unsigned-review.json','--review',review['review_commitment'],'--key-file',owner/'public-fixture-key.json')
        self.signed_count+=1
        require(signed['previous_wallet_head']==caller['head'] and signed['recovered_exact_retry'] is False
            and signed['retained_approvals_complete'] is True and signed['intent_id']==review['draft']['intent_id'],
            'once original owner approval response differs')
        self.file('owners/'+label+'/signed-response',signed)
        mesh.atomic(caller_path,dict(caller,head=signed['wallet_head'],pending=None))
        commands=self.file('owners/'+label+'/signed-commands',signed['commands'])
        queued=self.call(label,1,'bft-submit','--file',commands)
        require(queued['queued'] is True and queued['block_included'] is False and queued['ledger_changed'] is False,
            'queue grants no debit or inclusion')
        after=self.call(label,1,'status');require(after==before,'queued original owner request changed Native ledger')
        self.owners[label]=dict(signed=signed,request=request,wallet=wallet,caller=caller_path,inventory=inventory(owner),
            input=review['draft']['request']['inputs'][0])
        self.record('original-owner-first-sign-once-queued',region=label,queue_did_not_debit=True)
        return signed

    def materialize(self):
        self.remaining();require(inventory(self.root)==self.prepared_inventory,'prepared custody changed before launch')
        self.output.mkdir(mode=0o700)
        mesh.atomic(self.root/'fault-scope-started.json',dict(format='RLD-PAGED-FAULT-ONCE-STARTED-V1',
            output=str(self.output),currency=self.currency,original_preparation_inventory=self.bound.preparation_inventory,
            one_attempt=True,failed_scope_never_resume=True))
        for conf in self.bound.configs:
            for kind,raw in (('mesh',conf.mesh),('bft',conf.bft)):
                p=self.output/conf.phase/f'{kind}-{conf.region}-{conf.index}.json'
                p.parent.mkdir(mode=0o700,exist_ok=True);mesh.atomic(p,json.loads(raw));require(p.read_bytes()==raw,'exact config bytes differ')
        self.file('trusted-prelaunch-mesh-anchors', {label+'-'+str(n):anchor for (label,n),anchor in self.mesh_anchors.items()})
        self.original_states={label:[self.call(label,n,'status') for n in range(4)] for label in REGIONS}

    def start(self,phase,slots):
        for label,n in slots:
            self.remaining();require((label,n) not in self.processes,'copied/concurrent own custody refused')
            conf=self.configs[phase,label,n]
            require(conf.started,'initial missing validator must remain stopped')
            log_path=self.output/phase/f'service-{label}-{n}.log'
            log=os.fdopen(os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb')
            self.logs[label,n]=log
            try:process=subprocess.Popen(conf.argv,cwd=self.project,stdout=log,stderr=log,start_new_session=True)
            except BaseException:log.close();del self.logs[label,n];raise
            self.processes[label,n]=process;self.starts+=1;self.record('ordinary-node-start',region=label,index=n,keyless=phase=='keyless-drain')

    def stop_all(self):
        if not self.processes:return
        deadline=time.monotonic()+5
        for process in self.processes.values():
            if process.poll() is None:os.kill(process.pid,signal.SIGTERM)
        unclean=False
        for slot,process in list(self.processes.items()):
            try:process.wait(timeout=max(.001,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5);unclean=True
            self.terminal.append(dict(region=slot[0],index=slot[1],exit_code=process.returncode))
            unclean|=process.returncode!=0
            self.logs[slot].close();del self.logs[slot];del self.processes[slot]
        require(not unclean,'owned ordinary node shutdown was unclean')

    def observations(self):
        heights={}
        for (label,n),process in self.processes.items():
            require(process.poll() is None,'owned ordinary node exited prematurely')
            path=self.root/'mesh'/f'{label}-{n}'/'regional-contact-status.json'
            if not path.exists():heights[label,n]=None;continue
            value=document(path);conf=self.configs[self.phase,label,n]
            pin=self.observed['transport_pins'][SLOTS.index((label,n))]
            listener=conf.argv[conf.argv.index('--mesh-listen')+1].split(':')
            heights[label,n]=observation_height(value,process.pid,self.currency,pin['tls_cert_sha256'],
                dict(host=listener[0],port=int(listener[1])),CAPS[label])
            if heights[label,n] is None:self.unknowns+=1
            if type(value.get('transport')) is dict and value['transport'].get('progress_observation_available',True) is True:self.tls_observations.add((label,n))
            if self.phase=='keyless-drain' and heights[label,n] is not None:
                require(value['consensus']['autonomous_signing_enabled'] is False,'keyless observer began signing')
        return heights

    def wait(self, label, check):
        while self.remaining()>0:
            heights=self.observations()
            try:value=check(heights)
            except (NativeReadBusy,NativeReceiptNotObserved):value=False
            if value:self.record('phase-discriminator',observation=label);return value
            time.sleep(min(.2,self.remaining()))

    def check_wallets(self):
        for label,owner in self.owners.items():
            require(inventory(self.root/'fault-owners'/label)==owner['inventory'],'original owner custody changed')
            caller=document(owner['caller']);signed=owner['signed']
            require(caller['pending'] is None and caller['head']==signed['wallet_head'],'original owner caller head differs')
            view=self.call(label,0,'wallet-view','--wallet-dir',owner['wallet'],'--expected-wallet-head',caller['head'])
            require(len(view['signed'])==1 and view['signed'][0]['intent_id']==signed['intent_id']
                and view['signed'][0]['state']=='INCLUDED_IN_LOCAL_LEDGER' and not view['signed'][0]['quarantined'],
                'original owner request not natively included')

    def isolation_ready(self, heights):
        active=[('earth',n) for n in (1,2,3)]
        if not all(type(heights.get(s)) is int and heights[s]>=9 for s in active):return False
        if not all(type(heights.get((label,n))) is int and heights[label,n]>=6 for label in REGIONS[1:] for n in range(4)):return False
        states={label:self.call(label,1,'status') for label in REGIONS}
        export=self.owners['earth']['signed']['intent_id']
        if export not in states['earth']['ledger']['exports']:return False
        require(export not in states['proxima']['ledger']['imports'],'disconnected contact fabricated an import')
        for label,recipient in (('proxima',15),('andromeda',16)):
            coins=states[label]['ledger']['coins']
            if sum(int(c['payment']['amount']) for c in coins.values() if c['payment']['owner']==public(recipient))!=1:return False
        proof=self.call('earth',1,'proof')
        require(any(s['statement']['region']==self.regions['earth'] and s['statement']['height']==9
            and s['bft']['prepared']['round']>0 for s in proof['snapshots']), 'missing leader lacks certified view change')
        require(all(r.report()['refused_connections']>0 for r in self.relays),'both directed contacts lack actual refused attempts')
        return True

    def live_receipt(self, heights):
        # A Native recipient read authenticates its complete source/import/value
        # evidence. Missing unrelated telemetry must not gate that read or its
        # fair replica rotation. Observations() still refuses real errors/caps.
        now=time.monotonic()
        if now<getattr(self,'next_receipt',0):return False
        self.next_receipt=now+2
        n=getattr(self,'receipt_slot',0);self.receipt_slot=(n+1)%4
        value=self.call('proxima',n,'wallet-receipt','--file',self.expectation_path)
        require(value['expected']==self.expectation,'exact original receipt binding differs')
        self.receipt_observations=getattr(self,'receipt_observations',0)+1
        self.file('observations/original-receipt-'+str(self.receipt_observations),
            dict(region='proxima',index=n,call_index=len(self.calls)-1,receipt=value))
        return value if (value['evidence_verified'] and value['import_accepted'] and value['maturity_reached']
            and value['original_output_spendable_now'] and value['original_output_remaining']=='9'
            and value['local_finality_covers_import'] and not value['quarantined']) else False

    def drain_ready(self,heights):
        if not all(type(heights.get((label,n))) is int for label in REGIONS for n in range(4)):return False
        for label in REGIONS:
            if len({heights[label,n] for n in range(4)})!=1:return False
            context=self.call(label,0,'bft-context')['context']
            if context['parent_height']!=heights[label,0]:return False
            messages=[]
            for n in range(4):
                config=json.loads(self.configs[PHASES[-1],label,n].bft);caller=document(config['head_file'])
                if caller['pending'] is not None or caller['outbox'] is not None:return False
                signer=self.call(label,n,'bft-status','--signer-dir',config['signer_dir'])
                require(signer['head']==caller['head'] and signer['binding']==caller['binding'],'keyless caller/signer head differs')
                messages.extend(self.call(label,n,'bft-retained-messages','--signer-dir',config['signer_dir']))
            if has_complete_commit_group(messages,context):return False
        return True

    def stopped(self):
        require(not self.processes,'full cold checks require stopped own nodes')
        states={};proofs={}
        for label in REGIONS:
            states[label]=[];proofs[label]=[]
            for n in range(4):
                head=self.pin_head(label,n,'stopped')
                state=self.call(label,n,'status');proof=self.call(label,n,'proof')
                require(all(state[k]==head[k] for k in ('currency','region','height','tip','state','finality')),
                    'stopped actual checkpoint changed')
                conf=json.loads(self.configs[PHASES[-1],label,n].bft);before=inventory(Path(conf['state']))
                cold=verify_stopped_state_pinned(self.native(label,n),conf,self.root,head['history_head'])
                require(inventory(Path(conf['state']))==before,'stopped complete envelope check changed retained bytes')
                caller=document(conf['head_file']);signer=self.call(label,n,'bft-status','--signer-dir',conf['signer_dir'])
                require(caller['head']==signer['head'] and caller['binding']==signer['binding']
                    and caller['pending'] is None and caller['outbox'] is None, 'final separate native voter/caller heads differ')
                context=self.call(label,n,'bft-context')
                require(context['rules']==RULES and context['keys']==[v['key'] for v in conf['validators']]
                    and context['context']['parent_height']==state['height'],'final original membership differs')
                after=inventory(self.root/label/f'native-{n}')
                retain_original_objects(self.original_objects[label,n],after,'ledger-events/stream.json')
                retain_original_objects(self.original_voter_objects[label,n],inventory(Path(conf['signer_dir'])),
                    'bft-records/stream.json')
                pin=self.observed['transport_pins'][SLOTS.index((label,n))]
                config=json.loads(self.configs[PHASES[-1],label,n].mesh)
                with MeshInspection(config,**self.mesh_anchors[label,n]) as image:transport=dict(image.summary)
                self.cold.append(dict(region=label,index=n,height=state['height'],history_head=head['history_head'],
                    envelopes=cold,transport=transport,separate_caller_head_verified=True))
                if label=='proxima':
                    receipt=self.call(label,n,'wallet-receipt','--file',self.expectation_path)
                    require(receipt['expected']==self.expectation and receipt['evidence_verified'] and receipt['import_accepted']
                        and receipt['maturity_reached'] and receipt['original_output_spendable_now']
                        and receipt['original_output_remaining']=='9' and receipt['local_finality_covers_import']
                        and not receipt['quarantined'] and receipt['mature_height']==receipt['import_height']+2<=state['height'],
                        'all four actual stopped recipient imports lack original maturity')
                require(all(state['ledger'][field].get(k)==v for field in ('exports','imports')
                    for k,v in self.original_states[label][n]['ledger'][field].items()), 'original debit/import tombstone changed')
                states[label].append(state);proofs[label].append(proof)
            compatible(states[label],proofs[label])
            require(len({(s['height'],s['tip'],s['state'],s['finality']) for s in states[label]})==1, 'full stopped region has not converged')
        self.check_wallets()
        selected=[max(states[label],key=lambda s:s['height']) for label in REGIONS]
        bootstrap=document(self.root/'signed-fresh-bootstrap.json')['currency']
        accounting=self.account(selected,self.currency,self.regions['earth'],bootstrap['cap'],bootstrap['block_reward'])
        require(accounting['conserved'] is True and accounting['pending_exports']=='0'
            and accounting['observed_exports']==accounting['observed_permanent_imports']==3, 'full stopped original value conservation differs')
        for label in REGIONS:
            if label!='earth':
                recipient=public(15 if label=='proxima' else 16)
                require(all(sum(int(v['payment']['amount']) for v in s['ledger']['coins'].values()
                    if v['payment']['owner']==recipient and v['mature']<=s['height'])==1 for s in states[label]),
                    'all four remote original local payments not mature')
        return states,accounting

    def run(self):
        self.materialize();self.phase=PHASES[0]
        # The actual prepared graph supplies these exact two directed relay ports.
        e=json.loads(self.configs[self.phase,'earth',1].mesh)['contacts']
        p=json.loads(self.configs[self.phase,'proxima',1].mesh)['contacts']
        e_peer=self.observed['transport_pins'][5]['node_id'];p_peer=self.observed['transport_pins'][1]['node_id']
        endpoints=[next(c for c in e if c['peer']==e_peer)['port'],next(c for c in p if c['peer']==p_peer)['port']]
        targets=[int(self.configs[self.phase,'proxima',1].argv[self.configs[self.phase,'proxima',1].argv.index('--mesh-listen')+1].split(':')[1]),
            int(self.configs[self.phase,'earth',1].argv[self.configs[self.phase,'earth',1].argv.index('--mesh-listen')+1].split(':')[1])]
        for port,target in zip(endpoints,targets):self.relays.append(LiteralFaultRelay(port,('127.0.0.1',target)))
        for label in REGIONS:self.sign_original(label)
        require(self.signed_count==self.write_counts['wallet-sign']==self.write_counts['bft-submit']==3,'three once original owner requests required')
        self.expectation=dict(currency=self.currency,source=self.regions['earth'],destination=self.regions['proxima'],
            export=self.owners['earth']['signed']['intent_id'],recipient=public(21),net_amount='9')
        self.expectation_path=self.file('original-receipt-expectation',self.expectation)
        offline={str(p):digest(p) for directory in (self.root/'earth/native-0',self.root/'earth/voter-0',self.root/'earth/caller-0')
            for p in directory.rglob('*') if p.is_file()}
        initial=[s for s in SLOTS if s!=('earth',0)]
        self.start(self.phase,initial)
        self.wait('missing-leader9 plus isolated two original local payments; no new import',self.isolation_ready)
        require(all(digest(Path(p))==v for p,v in offline.items()),'offline original ledger/voter/caller changed')
        self.phase=PHASES[1];self.start(self.phase,[('earth',0)])
        self.wait('offline original validator catches up while both contacts stay cut',
            lambda h:type(h.get(('earth',0))) is int and h['earth',0]>=9)
        self.phase=PHASES[2]
        for relay in self.relays:relay.enable()
        self.record('both-directed-original-contacts-restored')
        self.wait('original export native import/maturity before unchanged caps',self.live_receipt)
        self.stop_all();self.phase=PHASES[3]
        self.start(self.phase,SLOTS)
        self.wait('keyless all-replica certified drain and exact caller heads',self.drain_ready)
        self.stop_all()
        states,accounting=self.stopped()
        require(self.remaining()>0 and not self.processes and self.signed_count==3 and self.tls_observations==set(SLOTS),'full fault terminal/budget differs')
        return dict(completed=True,fixture_only=True,live_rld=False,full_fault_qualified=True,
            stage_seconds=600,round_seconds=60,new_height_limit=24,absolute_height_caps=CAPS,maturity=2,quorum=3,
            original_owner_first_signs=3,owner_requests_replaced=0,custody_copied=False,
            controller_consensus_or_checkpoints=0,ordinary_service_starts=self.starts,service_terminals=self.terminal,
            all12fixed_head_native_and_complete_envelopes=self.cold,native_accounting=accounting,
            final_heights={label:[s['height'] for s in states[label]] for label in REGIONS},
            directed_fault_relays=[relay.report() for relay in self.relays],unknown_process_observations=self.unknowns,
            independent_freshness_custody_physical_long_history_qualified=False,whole_goal_completed=False)

    def cleanup(self):
        primary=None
        try:self.stop_all()
        except BaseException as error:primary=error
        for relay in self.relays:
            try:relay.close()
            except BaseException as error:
                if primary is None:primary=error
        if primary:raise primary
