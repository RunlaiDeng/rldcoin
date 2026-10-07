#!/usr/bin/env python3
"""Bounded autonomous ground consensus companion; native Rust owns all votes.

Only explicitly configured, admitted validator keys sign. Authenticated mesh
carriage supplies bytes, not authority. Caller-head consent survives response
loss independently of the signer/runtime directories. No stellar RTT claim.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages, pack_state, unpack_state
from regional_bft_query_index import lookup as signed_lookup
from regional_bft_observation import Observation
from regional_bft_cold_batch import check_retained as check_cold_retained
from regional_bft_live_batch import inspect as inspect_live_batch
from regional_bft_joint_epoch import JointEpoch, JointLoopStatus, FORMAT as JOINT_FORMAT, signed_body
from regional_bft_joint_roles import RoleJoint, FORMAT as ROLE_FORMAT, readonly_head
from regional_native_startup import Inspection
from regional_bft_timeout_hint import ordered_timeout

FORMAT = 'RLD-REGIONAL-BFT-NODE-V1'
NETWORK = 'RLD-REGIONAL-BFT-NETWORK-V2'
MAX_MESSAGES = 512
MAX_STATE = 32*1024*1024
MAX_BROADCAST_HINT_BYTES = 4*1024*1024
MAX_BROADCAST_QUIET_SECONDS = 4.0
MAX_BROADCAST_QUIET_CALLS = 16


def current_empty_proposal_hint(proposal, context, keys):
    """Scheduling only for a Native-checked empty candidate and bounded parent.

    Only parent Import commands (original maximum 16) have a typed encoding.
    Other commands, epochs and other shapes use ordinary carriage. Later
    rounds require a complete bounded timeout certificate and its signatures.
    This extra exact signature check supplies no Native acceptance.
    """
    if (type(proposal) is not dict or set(proposal)!={'round','snapshot','timeout','leader'}
            or type(proposal['round']) is not int or not 0<=proposal['round']<32):return False
    round_number=proposal['round'];timeout=None;selected_high=None
    if round_number==0:
        if proposal['timeout'] is not None:return False
    else:
        try:
            timeout,selected_high=ordered_timeout(proposal['timeout'],context,keys,round_number)
        except (KeyError,TypeError,ValueError,mesh.InvalidSignature):return False
    snapshot=proposal['snapshot'];leader=proposal['leader']
    if (type(snapshot) is not dict or set(snapshot)!={'base','statement','approvals','blocks','epochs'}
            or snapshot['base'] is None or snapshot['base']!=context['previous']
            or snapshot['approvals']!=[] or snapshot['epochs']!=[]
            or type(snapshot['blocks']) is not list or len(snapshot['blocks'])!=2
            or type(leader) is not dict or set(leader)!={'key','signature'}
            or leader['key']!=keys[(context['parent_height']+round_number)%4]):return False
    header_fields=('currency','region','parent','anchor','height','miner','commands','state','nonce')
    statement_fields=('currency','region','height','block','state','previous','epoch')
    headers=[];blocks=[]
    for index,block in enumerate(snapshot['blocks']):
        if (type(block) is not dict or set(block)!={'header','commands'}
                or type(block['commands']) is not list or len(block['commands'])>16
                or index==1 and block['commands']!=[]
                or type(block['header']) is not dict or set(block['header'])!=set(header_fields)):return False
        commands=[]
        for command in block['commands']:
            if (type(command) is not dict or set(command)!={'Import'}
                    or type(command['Import']) is not dict or set(command['Import'])!={'snapshot','export'}):return False
            imp=command['Import'];mesh.hex32(imp['snapshot']);mesh.hex32(imp['export'])
            commands.append({'Import':{'snapshot':imp['snapshot'],'export':imp['export']}})
        h={k:block['header'][k] for k in header_fields};headers.append(h);blocks.append(dict(header=h,commands=commands))
    encode=lambda value:wire.json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    block_hash=lambda h:hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encode(h)).hexdigest()
    parent,child=headers;statement=snapshot['statement']
    if (blocks[0]['commands'] and parent['commands']!=hashlib.sha256(
            b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encode(blocks[0]['commands'])).hexdigest()):return False
    if (type(statement) is not dict or set(statement)!=set(statement_fields)
            or parent['height']!=context['parent_height'] or parent['state']!=context['parent_state']
            or block_hash(parent)!=context['parent_block']
            or child['parent']!=context['parent_block'] or child['anchor']!=context['previous']
            or child['height']!=context['parent_height']+1
            or any(h['currency']!=context['currency'] or h['region']!=context['region'] for h in headers)
            or statement!=dict(currency=context['currency'],region=context['region'],height=child['height'],
                block=block_hash(child),state=child['state'],previous=context['previous'],epoch=context['epoch'])):return False
    ordered=dict(base=snapshot['base'],statement={k:statement[k] for k in statement_fields},
                 approvals=[],blocks=blocks,epochs=[])
    if selected_high is not None and selected_high!=hashlib.sha256(
            b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'+encode(ordered['statement'])).hexdigest():return False
    data=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\0'+encode([round_number,ordered,timeout,leader['key']])
    mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(leader['key'])).verify(
        bytes.fromhex(leader['signature']),data)
    return True


def current_finalized_hint(snapshot, context, keys):
    """Extra carriage filter for an exact Native-checked current checkpoint.

    The original retained-envelope authentication is still required. These
    complete quorum signatures narrow scheduling only, never validate blocks,
    state, evidence, epochs, custody or a receiver's Native acceptance.
    """
    fields=('currency','region','height','block','state','previous','epoch')
    context_fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
    if (type(snapshot) is not dict or set(snapshot)!={'base','bft','statement','approvals','blocks','epochs'}
            or snapshot['approvals']!=[] or snapshot['epochs']!=[]
            or type(snapshot['blocks']) is not list or len(snapshot['blocks'])>256):return False
    statement=snapshot['statement'];certificate=snapshot['bft']
    if (type(statement) is not dict or set(statement)!=set(fields)
            or type(statement['height']) is not int or statement['height']<1
            or statement['height']!=context['parent_height']
            or (statement['currency'],statement['region'],statement['epoch'],statement['block'],statement['state'])
               !=(context['currency'],context['region'],context['epoch'],context['parent_block'],context['parent_state'])
            or snapshot['base']!=statement['previous']
            or type(certificate) is not dict or set(certificate)!={'prepared','committed'}):return False
    encode=lambda value:wire.json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    value=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'+
                        encode({k:statement[k] for k in fields})).hexdigest()
    if value!=context['previous']:return False
    previous=None;round_number=None
    for name,phase in (('prepared','Prepare'),('committed','Commit')):
        quorum=certificate[name]
        if (type(quorum) is not dict or set(quorum)!={'context','round','value','phase','votes'}
                or type(quorum['round']) is not int or not 0<=quorum['round']<32
                or quorum['value']!=value or quorum['phase']!=phase
                or type(quorum['votes']) is not list or not 3<=len(quorum['votes'])<=4):return False
        parent=quorum['context']
        if (type(parent) is not dict or set(parent)!=set(context_fields)
                or type(parent['parent_height']) is not int or parent['parent_height']+1!=statement['height']
                or (parent['currency'],parent['region'],parent['epoch'],parent['previous'])
                   !=(statement['currency'],statement['region'],statement['epoch'],statement['previous'])):return False
        mesh.hex32(parent['parent_block']);mesh.hex32(parent['parent_state'])
        if name=='prepared':previous=parent;round_number=quorum['round']
        elif parent!=previous or quorum['round']!=round_number:return False
        last=None
        for vote in quorum['votes']:
            if (type(vote) is not dict or set(vote)!={'context','round','value','phase','approval'}
                    or vote['context']!=parent or type(vote['round']) is not int
                    or vote['round']!=quorum['round'] or vote['value']!=value or vote['phase']!=phase
                    or type(vote['approval']) is not dict or set(vote['approval'])!={'key','signature'}):return False
            approval=vote['approval'];key=approval['key']
            if key not in keys or last is not None and key<=last:return False
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+encode(
                [{k:parent[k] for k in context_fields},quorum['round'],value,phase,key])
            mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                bytes.fromhex(approval['signature']),data)
            last=key
    return True


def commit_carriage_frames(messages, context, keys, currency, region):
    """Exact current votes and bounded empty proposals from Native-checked Messages.

    The signature check only narrows scheduling. Native still checks every
    complete envelope, dependency, lock and quorum before any authority.
    """
    mesh.require(isinstance(messages,Messages) and len(messages)<=MAX_MESSAGES,
                 'Commit carriage requires bounded retained messages')
    fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
    if (type(context) is not dict or set(context)!=set(fields)
            or context['currency']!=currency or context['region']!=region):return ()
    mesh.require(type(keys) is tuple and len(keys)==4 and len(set(keys))==4,
                 'Commit carriage requires configured base validators')
    for key in keys:mesh.hex32(key)
    frames=[];expanded_bytes=0;finalized_ids=[]
    for ident,body,_,_ in messages.bodies():
        signed=body.get('Signed',{});vote=signed.get('Vote',{});proposal=signed.get('Proposal');finalized=body.get('Finalized')
        try:
            if finalized is not None:
                finalized_ids.append(ident)
                continue
            if proposal is not None:
                if not current_empty_proposal_hint(proposal,context,keys):continue
            else:
                if vote.get('phase') not in ('Prepare','Commit') or vote.get('context')!=context:continue
                approval=vote['approval'];key=approval['key']
                if key not in keys:continue
                data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+wire.json.dumps(
                    [{k:context[k] for k in fields},vote['round'],vote['value'],vote['phase'],key],
                    separators=(',',':'),ensure_ascii=False).encode()
                mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                    bytes.fromhex(approval['signature']),data)
            expanded_bytes+=messages.record(ident)['size_bytes']
            if expanded_bytes>MAX_BROADCAST_HINT_BYTES:return ()
            payload=messages.payload(ident);envelope=wire.decode_json(payload)
            if (envelope['format']!=NETWORK or envelope['currency']!=currency
                    or envelope['region']!=region):continue
            raw=wire.make_frame('regional-bft',region,region,messages.content(ident),payload)
            frames.append(wire.inspect_frame(raw)[0]['message_id'])
        except (KeyError,TypeError,ValueError,mesh.InvalidSignature):
            # A hint failure is ordinary scheduling fallback, never admission.
            continue
    if frames:return tuple(sorted(set(frames)))
    # A complete current Signed envelope carries its predecessor evidence and
    # advances live consensus. A latest finalized checkpoint is fallback for
    # quiescent/lagging peers; it must not displace active current frames or
    # spend their original expansion budget. Native admission is unchanged.
    expanded_bytes=0
    for ident in finalized_ids:
        try:
            finalized=messages.record(ident)['body']['Finalized']
            if not current_finalized_hint(finalized,context,keys):continue
            expanded_bytes+=messages.record(ident)['size_bytes']
            if expanded_bytes>MAX_BROADCAST_HINT_BYTES:return ()
            payload=messages.payload(ident);envelope=wire.decode_json(payload)
            if (envelope['format']!=NETWORK or envelope['currency']!=currency
                    or envelope['region']!=region):continue
            raw=wire.make_frame('regional-bft',region,region,messages.content(ident),payload)
            frames.append(wire.inspect_frame(raw)[0]['message_id'])
        except (KeyError,TypeError,ValueError,mesh.InvalidSignature):
            continue
    return tuple(sorted(set(frames)))


def carriage_batch(messages, pending, height, cursor):
    """Reserve carriage for this native-observed height and retained history.

    Classification schedules already retained complete bytes only. It never
    validates an envelope or supplies a ledger, quorum or signing decision.
    """
    current = set()
    for ident, body, _, _ in messages.bodies():
        message = signed_body(body)
        proposal = message.get('Proposal')
        finalized = body.get('Finalized')
        context = message.get('Vote', message.get('Timeout', {})).get('context', {})
        if ((proposal is not None and proposal['snapshot']['statement']['height'] == height + 1)
                or (finalized is not None and finalized['statement']['height'] == height)
                or context.get('parent_height') == height):
            current.add(ident)
    active = [pair for pair in pending if pair[1] in current]
    history = [pair for pair in pending if pair[1] not in current]

    def take(rows, count):
        if not rows:
            return []
        # Durable cursor advances by four per published batch. Rotate each
        # class by one so a stable odd/even class cannot pin its first slots.
        offset = (cursor // 4) % len(rows)
        return (rows[offset:] + rows[:offset])[:count]

    if active and history:
        selected = take(active, 2) + take(history, 2)
        # A short class donates its spare slot without starving either class.
        if len(selected) < 4:
            selected += [pair for pair in take(active + history, 4)
                         if pair not in selected][:4 - len(selected)]
        return selected
    return take(active or history, 4)


def private(path, directory=False, missing=False):
    path = Path(path)
    mesh.require(path.is_absolute() and not any(p.is_symlink() for p in [path, *path.parents]), 'BFT private path must be absolute without symlinks')
    if missing and not path.exists():
        private(path.parent,True)
        return path
    info = path.lstat()
    mesh.require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                 and info.st_uid == os.getuid() and not info.st_mode & 0o077
                 and (directory or info.st_nlink == 1), 'BFT private ownership/type/permissions invalid')
    return path


class Runtime:
    def __init__(self, native, transport, path):
        self._signed_query_ready = False
        self._broadcast_quiet = None
        self._carriage_context = None
        self._carriage_priority_key = None
        self.observation = Observation()
        self.native, self.transport = Inspection(native), transport
        self.failed = False
        self.lock = self.head_lock = None
        self.extra_locks = []
        self.joint = None
        self.last_error = None
        config = mesh.load(private(path), 65536)
        fields={'format','state','signer_dir','head_file','key_file','key','miner','validators','block_interval','round_timeout','stop_height'}
        role_fields={'format','state','miner','validators','block_interval','round_timeout','stop_height','initial_slot','handoffs'}
        roles = config['format']==ROLE_FORMAT
        mesh.require((set(config)==fields and config['format']==FORMAT)
                     or (set(config)==fields|{'joint_epoch'} and config['format']==JOINT_FORMAT)
                     or (set(config)==role_fields and roles),
                     'BFT configuration fields/version invalid')
        self.format=config['format']
        self.miner = mesh.hex32(config['miner'])
        self.root = mesh.safe_dir(config['state'])
        private(self.root, True)
        if roles:
            self.key = self.signer = self.head_path = self.key_file = None
            self.head = readonly_head()
        else:
            self.key = mesh.hex32(config['key'])
            self.signer = private(config['signer_dir'], True)
            self.head_path = private(config['head_file'])
            private(self.head_path.parent,True)
            self.key_file = private(config['key_file'],missing=True)
            mesh.require(all(self.head_path.parent != p and p not in self.head_path.parents for p in (self.root, self.signer, native.ledger)),
                         'BFT caller head must survive signer/runtime/ledger directory backups')
        mesh.require(type(config['block_interval']) in (float,int) and 0.5 <= config['block_interval'] <= 3600
                     and type(config['round_timeout']) in (float,int) and 2 <= config['round_timeout'] <= 3600,
                     'BFT local ground timing outside bound')
        mesh.integer(config['stop_height'], 0, 64)
        self.block_interval, self.round_timeout, self.stop_height = config['block_interval'], config['round_timeout'], config['stop_height']
        try:
            locks=[(self.root,'lock')]
            if not roles:locks.append((self.head_path.parent,'head_lock'))
            for directory, attr in locks:
                fd = os.open(directory/'.bft-runtime.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
                setattr(self,attr,fd)
                info = os.fstat(fd)
                mesh.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077 and info.st_nlink == 1, 'BFT runtime lock invalid')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            current = self.native.call('bft-context')
            self.region = current['context']['region']
            validators = config['validators']
            if roles:
                with mesh.Node(transport) as node:
                    mesh.require(node.network==native.currency, 'configured role carrier network differs')
                    self.node_id=node.id
                self.binding={'currency':native.currency,'region':self.region,'node_id':self.node_id}
                self.joint=RoleJoint(self,config,current)
            else:
                mesh.require(isinstance(validators,list) and len(validators)==4
                         and (config['format']==JOINT_FORMAT or [v['key'] for v in validators] == current['keys'])
                         and all(set(v)=={'key','node_id'} for v in validators), 'BFT configured validator membership differs from signed admission')
                self.peers = {mesh.hex32(v['key']): mesh.hex32(v['node_id']) for v in validators}
                mesh.require(len(set(self.peers.values())) == 4 and self.key in self.peers, 'BFT validator carrier identities duplicate or key absent')
                with mesh.Node(transport) as node:
                    mesh.require(node.id == self.peers[self.key] and node.network == native.currency, 'configured BFT carrier differs from local mesh identity')
                    self.node_id = node.id
                self.binding = {'currency':native.currency,'region':self.region,'key':self.key}
                self.signing_binding=self.binding
                self.head=self.load_head(self.head_path,self.signing_binding)
                if self.format==JOINT_FORMAT:
                    self.joint=JointEpoch(self,config['joint_epoch'],validators,current)
            self.state_path = self.root/'state.json'
            if self.state_path.exists() or self.state_path.is_symlink():
                self.state = unpack_state(mesh.load(private(self.state_path),MAX_STATE))
                mesh.require(set(self.state)=={'format','binding','messages','height','tip','snapshot_cache','cursor'}
                             and self.state['format']==self.format and self.state['binding']==self.binding, 'BFT runtime state binding differs')
                mesh.integer(self.state['height'],0,64)
                mesh.integer(self.state['cursor'],0,2**63-1)
                mesh.require(isinstance(self.state['messages'],Messages) and len(self.state['messages'])<=MAX_MESSAGES
                             and isinstance(self.state['snapshot_cache'],list) and len(self.state['snapshot_cache'])<=64, 'BFT runtime retained capacity invalid')
                check_cold_retained(self)
            else:
                self.state = {'format':self.format,'binding':self.binding,'messages':Messages(),'height':0,'tip':self.region,'snapshot_cache':[],'cursor':0}
                self.save(self.state)
            self._retained_native_authenticated = True
            if self.joint is not None:
                self.joint.startup()
            else:
                if self.head['pending'] is not None:self.reconcile()
                self.signer_status()
                self.flush_outbox()
            self.observe()
            retained_dirs=(self.joint.retained_directories() if roles else
                           [self.signer] if self.joint is None else [self.joint.old['signer'],self.joint.new['signer']])
            from regional_bft_retained_response import RetainedResponses
            retained_responses = RetainedResponses(self, signed_body)
            for directory in retained_dirs:
                if not directory.exists():continue
                for message in self.native.call('bft-retained-messages','--signer-dir',directory):
                    if retained_responses.reuse(message):continue
                    self.retain_local_body({'Signed':message})
            proof=self.native.call('proof')
            local=[s for s in proof['snapshots'] if s['statement']['region']==self.region and s['statement']['height']==self.state['height']]
            if local:
                self.retain_local_body({'Finalized':local[0]})
            self._signed_query_index = None
            self._signed_query_ready = True
            self.slot = None
            self.entered_at = time.monotonic()
        except BaseException:
            self.close()
            raise
        finally:
            # Live ticks retain their original lock-refusal/unknown semantics.
            self.native = native

    def close(self):
        mesh.forget_carriage_position(getattr(self,'_carriage_priority_key',None))
        self._carriage_priority_key = None
        self._carriage_context = None
        self._broadcast_quiet = None
        self._signed_query_ready = False
        self._signed_query_index = None
        for descriptor in self.extra_locks:os.close(descriptor)
        self.extra_locks=[]
        for attr in ('lock','head_lock'):
            descriptor=getattr(self,attr,None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self,attr,None)

    def save(self, state):
        packed=pack_state(state)
        mesh.require(not self.failed and len(wire.canonical(packed))<=MAX_STATE, 'BFT runtime persistence unavailable/capacity')
        try:
            mesh.atomic(self.state_path,packed)
        except BaseException:
            self.failed=True
            raise
        if (hasattr(self, '_signed_query_index')
                and state['messages'] is not self.state['messages']):
            self._signed_query_index = None
        self.state=state

    def save_head(self, value):
        mesh.require(not self.failed and len(wire.canonical(value))<=8*1024*1024, 'BFT caller-head persistence unavailable/capacity')
        try:
            mesh.atomic(self.head_path,value)
        except BaseException:
            self.failed=True
            raise
        self.head=value

    def with_json(self, action, value, *args):
        started = time.monotonic()
        succeeded = False
        try:
            with tempfile.NamedTemporaryFile(dir=self.root,prefix='.native-',suffix='.json') as handle:
                handle.write(wire.canonical(value))
                handle.flush()
                os.fsync(handle.fileno())
                result = self.native.call(action,'--commands' if action=='bft-candidate' else '--file',handle.name,*args)
                succeeded = True
                return result
        finally:
            observation = getattr(self, 'observation', None)
            if observation is not None:
                observation.operation(action, started, succeeded)

    def load_head(self,path,binding,allow_initialization=False):
        value=mesh.load(private(path),8*1024*1024)
        fields={'format','binding','head','pending','outbox'}|({'initialization'} if allow_initialization else set())
        mesh.require(set(value)==fields and value['format']==self.format and value['binding']==binding,
                     'BFT external caller-head binding differs')
        if value['head'] is None:
            mesh.require(allow_initialization and value['pending'] is None and value['outbox'] is None,
                         'only fresh explicit new slot may lack a native head')
        else:mesh.hex32(value['head'])
        return value

    def signer_status(self):
        if self.format==ROLE_FORMAT and self.head['head'] is None:
            if self.signer is not None:
                mesh.require(not self.signer.exists() or self.head['initialization'] is not None,
                             'unanchored role voter cannot be adopted')
            return {'binding':self.signing_binding,'head':None,'state':None,'records':None,'uninitialized_role_signer':True}
        if self.joint is not None and self.joint.active=='new' and self.head['head'] is None:
            mesh.require(not self.signer.exists() or self.head['initialization'] is not None,
                         'new native journal cannot be adopted without retained initialization')
            return {'binding':self.signing_binding,'head':None,'state':None,'records':None,'uninitialized_late_new_signer':True}
        value=self.native.call('bft-status','--signer-dir',self.signer)
        mesh.require(value['binding']==self.signing_binding and value['head']==self.head['head'], 'BFT signer differs from separately retained caller head')
        return value

    def reconcile(self):
        request=self.head['pending']
        try:
            result=self.with_json('bft-sign',request,'--signer-dir',self.signer,'--expected-head',self.head['head'],'--recover-only')
        except (OSError,ValueError,subprocess.TimeoutExpired):
            # Read-only equality proves that this pending request did not advance
            # the retained native history. Never adopt a different native head.
            self.signer_status()
            self.save_head(dict(self.head,pending=None))
            return
        self.save_head(dict(self.head,head=result['head'],pending=None,outbox=result['message']))

    def flush_outbox(self):
        if self.head['outbox'] is not None:
            self.retain_local_body({'Signed':self.head['outbox']})
            # Clear only after full Native authentication and durable retention.
            self.save_head(dict(self.head,outbox=None))

    def retain_local_body(self, body):
        """Construct and fully authenticate local bytes before durable retention.

        The base profile uses one operation-local Native replay. Other profiles
        keep their original decorated envelope and independent verification.
        Incoming envelopes always retain their complete receive checks.
        """
        if getattr(self,'format',None)==FORMAT and self.joint is None:
            from regional_bft_local_envelope import pack
            envelope,verified=pack(self,body)
            self._retain_checked(envelope,verified,sync=False,local=True)
        else:
            self.retain(self.envelope(body),sync=False,local=True)

    def sign(self, request):
        observation = getattr(self, 'observation', None)
        started = time.monotonic()
        kind, payload = next(iter(request.items()))
        selected = payload.get('proposal', payload)
        context = selected.get('context')
        if kind in ('Prepare', 'Commit'):
            context = selected['snapshot']['statement']
        if observation is not None:
            observation.event('sign-start', action=kind, round=selected.get('round'),
                              context_id=mesh.digest(context) if context is not None else None)
        succeeded = False
        try:
            self._sign(request)
            succeeded = True
        finally:
            if observation is not None:
                observation.event('sign-end', started, action=kind, succeeded=succeeded)

    def _sign_stage(self, name, operation, *args):
        observation = getattr(self, 'observation', None)
        if observation is None:
            return operation(*args)
        started = time.monotonic()
        succeeded = False
        try:
            result = operation(*args)
            succeeded = True
            return result
        finally:
            # Fixed names and scalars only; never retain the request, head,
            # response or proof. Timing does not authorize custody or retry.
            observation.operation('sign-' + name, started, succeeded)
            observation.event('sign-stage', started, stage=name, succeeded=succeeded)

    def _sign(self, request):
        private(self.key_file)
        mesh.require(self.head['pending'] is None and self.head['outbox'] is None, 'BFT signer has unreconciled request/response')
        self._sign_stage('status', self.signer_status)
        self._sign_stage('pending', self.save_head, dict(self.head,pending=request))
        result=self._sign_stage('native', self.with_json, 'bft-sign',request,'--signer-dir',self.signer,'--expected-head',self.head['head'],'--key-file',self.key_file)
        self._sign_stage('response', self.save_head, dict(self.head,head=result['head'],pending=None,outbox=result['message']))
        self._sign_stage('outbox', self.flush_outbox)
        # Give a newly persisted local phase time to propagate. Native one-vote
        # rules bound these resets; arbitrary peer traffic cannot renew a timer.
        self.entered_at=time.monotonic()

    def envelope(self, body):
        if self.joint is not None:body=self.joint.decorate(body)
        envelope={'format':NETWORK,'currency':self.native.currency,'region':self.region,
                  'evidence':self.native.call('proof'),'body':body}
        envelope=self.with_json('bft-network-pack',envelope)
        mesh.require(len(wire.canonical(envelope))<=wire.MAX_PAYLOAD,'BFT network payload capacity; retain signed native response')
        return envelope

    def loop_observation(self):
        # Operation-local native observation, never a serialized status cache.
        # Native holds both locks, fully replays and refuses publication residue.
        # A later sign still performs its independent fresh status/head checks.
        mesh.require(self.head['pending'] is None and self.head['outbox'] is None,
                     'BFT loop observation requires reconciled caller state')
        value=self.native.call('bft-loop-status','--signer-dir',self.signer,
                               '--expected-head',self.head['head'])
        mesh.require(set(value)=={'format','native','signer','signing_authority','independent_freshness_qualified'}
                     and value['format']=='RLD-BFT-LOOP-OBSERVATION-V1'
                     and value['signing_authority'] is False and value['independent_freshness_qualified'] is False,
                     'BFT loop observation domain differs')
        status=value['signer']
        mesh.require(status['binding']==self.signing_binding and status['head']==self.head['head'],
                     'BFT signer differs from separately retained caller head')
        return self._observe_context(value['native']['context']),status

    def observe(self):
        return self._observe_context(self.native.call('bft-context')['context'])

    def _observe_context(self, value):
        mesh.require(value['parent_height']>=self.state['height']
                     and (value['parent_height']!=self.state['height'] or value['parent_block']==self.state['tip']),
                     'BFT native ledger rolled back beneath retained runtime observation')
        if value['parent_height']!=self.state['height']:
            self.save(dict(self.state,height=value['parent_height'],tip=value['parent_block']))
        if getattr(self,'format',None)==FORMAT:
            context=wire.canonical(value)
            if context!=getattr(self,'_carriage_context',None):
                mesh.forget_carriage_position(getattr(self,'_carriage_priority_key',None))
                self._carriage_priority_key=None
            self._carriage_context=context
        return value

    def retain(self, envelope, sync=True, local=False):
        # A retained signed body does not authenticate a later envelope's proof.
        # Check every complete envelope before deduplication and let newly
        # certified dependencies reach native sync without replacing old bytes.
        verified=self.with_json('bft-network-check',envelope)
        self._retain_checked(envelope,verified,sync,local)

    def _retain_checked(self,envelope,verified,sync=True,local=False):
        # Private operation-local result only; never a persisted validation cache.
        ident=mesh.digest(envelope['body'])
        mesh.require(ident in self.state['messages'] or len(self.state['messages'])<MAX_MESSAGES,
                     'BFT message capacity; retain existing evidence')
        # Use only the complete evidence returned by native wire reconstruction
        # and authentication. Python neither expands prefixes nor grants rights.
        snapshots=list(verified['evidence']['snapshots'])
        if 'Finalized' in envelope['body']:
            final=envelope['body']['Finalized']
            if not any(s['statement']==final['statement'] for s in snapshots):
                snapshots.append(final)
        fingerprints=[mesh.digest(s['statement']) for s in snapshots]
        if sync and any(f not in self.state['snapshot_cache'] for f in fingerprints):
            self.with_json('bft-sync',{'snapshots':snapshots})
            self.observe()
            self.save(dict(self.state,snapshot_cache=sorted(set(self.state['snapshot_cache']+fingerprints))))
        if sync and self.joint is not None:
            proofs=verified.get('epochs',[])
            activation=envelope['body'].get('EpochActivation')
            # This observation includes only exact proofs selected by ordered
            # local journal events, reconstructed by full native replay under
            # pinned trust after authentication and dependency synchronization.
            # Compare full canonical proof bytes, never a statement/body digest
            # or a retained Python cache. An exact already installed proof needs
            # no second proof/pack/activation operation; all other proofs still
            # take the ordinary native activation path.
            def installed_proofs():
                observation=self.native.call('bft-installed-epochs')
                mesh.require(observation['format']=='RLD-BFT-INSTALLED-EPOCH-OBSERVATION-V1'
                    and observation['currency']==self.native.currency
                    and observation['region']==self.region
                    and isinstance(observation['proofs'],list) and len(observation['proofs'])<=16,
                    'native installed epoch observation binding')
                return observation['proofs']
            installed=installed_proofs() if proofs or activation is not None else []
            def present(proof):
                raw=wire.canonical(proof)
                return any(raw==wire.canonical(retained) for retained in installed)
            def activate_observed(index=None):
                args=() if index is None else ('--carried-index',str(index))
                observation=self.with_json('bft-epoch-activate-observed',envelope,*args)
                mesh.require(type(observation) is dict
                    and set(observation)=={'format','currency','region','epoch','activated_epoch',
                        'request_sha256','carried_index','proofs','fixture_only',
                        'independent_freshness_qualified','signing_authority'}
                    and observation.get('format')=='RLD-BFT-ACTIVATION-OBSERVATION-V1'
                    and observation.get('currency')==self.native.currency
                    and observation.get('region')==self.region
                    and observation.get('request_sha256')==hashlib.sha256(wire.canonical(envelope)).hexdigest()
                    and (observation.get('carried_index') is None if index is None else
                         type(observation.get('carried_index')) is int and observation['carried_index']==index)
                    and observation.get('fixture_only') is True
                    and observation.get('independent_freshness_qualified') is False
                    and observation.get('signing_authority') is False
                    and isinstance(observation.get('proofs'),list) and len(observation['proofs'])<=16
                    and len(wire.canonical(observation))<=8*1024*1024
                    and all(isinstance(observation.get(k),str) and len(observation[k])==64
                            and all(c in '0123456789abcdef' for c in observation[k])
                            for k in ('epoch','activated_epoch')),
                    'native activation observation binding')
                return observation['proofs']
            if activation is not None and not present(activation):
                installed=activate_observed()
            for index,proof in enumerate(proofs):
                if not present(proof):
                    installed=activate_observed(index)
        if ident in self.state['messages']:
            if local and not self.state['messages'].record(ident)['local']:
                messages=self.state['messages'].with_local(ident)
                self.save(dict(self.state,messages=messages))
            # Full Native authentication, certified dependency sync and every
            # carried activation above still precede body deduplication. An
            # already retained body cannot create new voting custody here.
            # The normal tick re-reads Native membership and reconciles all
            # caller heads before signing; transport workers never vote.
            return
        if sync and self.joint is not None:
            self.joint.advance()
            self.observe()
        messages=self.state['messages'].append(ident,envelope,verified['value'],local)
        self.save(dict(self.state,messages=messages))

    def receive(self, raw):
        started = time.monotonic()
        succeeded = False
        fields = {}
        try:
            frame,payload=wire.inspect_frame(raw)
            mesh.require(frame['kind']=='regional-bft' and frame['source_chain_id']==self.region, 'BFT received foreign region/carriage kind')
            envelope = wire.decode_json(payload)
            self.retain(envelope)
            succeeded = True
            message = signed_body(envelope['body'])
            kind = next(iter(message), 'Other')
            value = message.get(kind, {})
            context = value.get('context')
            if kind == 'Proposal':
                context = value['snapshot']['statement']
            fields = dict(kind_received=kind, round=value.get('round'), phase=value.get('phase'),
                          context_id=mesh.digest(context) if context is not None else None,
                          envelope_id=mesh.digest(envelope), body_id=mesh.digest(envelope['body']))
        finally:
            observation = getattr(self, 'observation', None)
            if observation is not None:
                observation.event('receive-end', started, succeeded=succeeded, **fields)

    def receive_many(self, raws):
        mesh.require(type(raws) is list and 0<len(raws)<=4,'BFT live receive count exceeds bound')
        envelopes=[]
        for raw in raws:
            frame,payload=wire.inspect_frame(raw)
            mesh.require(frame['kind']=='regional-bft' and frame['source_chain_id']==self.region,
                         'BFT received foreign region/carriage kind')
            envelopes.append(wire.decode_json(payload))
        # Complete all Native authentication before any dependency sync or retain.
        started=time.monotonic()
        try:
            checked=inspect_live_batch(self,envelopes)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            for _ in raws:self.observation.event('receive-end',started,succeeded=False)
            raise
        for envelope,verified in zip(envelopes,checked):
            succeeded=False;started=time.monotonic()
            try:
                self._retain_checked(envelope,verified)
                succeeded=True
            finally:
                message=signed_body(envelope['body']);kind=next(iter(message),'Other')
                value=message.get(kind,{})
                context=value['snapshot']['statement'] if kind=='Proposal' else value.get('context')
                self.observation.event('receive-end',started,succeeded=succeeded,
                    kind_received=kind,round=value.get('round'),phase=value.get('phase'),
                    context_id=mesh.digest(context) if context is not None else None,
                    envelope_id=mesh.digest(envelope),body_id=mesh.digest(envelope['body']))

    def broadcast(self):
        # Retained complete envelopes were Native authenticated on cold open or
        # receipt. This hint schedules carriage only, never Native validation,
        # dependency synchronization, caller-head checks or signing.
        messages=sorted(i for i,_,_,local in self.state['messages'].bodies() if local)
        peers=self.joint.relay_peers if self.format==ROLE_FORMAT else set(self.peers.values())
        recipients=sorted(peers-{self.node_id})
        rows=[(self.state['messages'].content(ident),ident) for ident in messages]
        inventory=None
        if (getattr(self,'_retained_native_authenticated',False)
                and len(rows)<=MAX_MESSAGES and len(self.state['messages'])<=MAX_MESSAGES
                and len(recipients)<=mesh.MAX_CONTACTS):
            raw=wire.canonical({'format':self.format,'binding':self.binding,
                'native':[self.native.authority,self.native.currency,str(self.native.ledger)],
                'region':self.region,'node_id':self.node_id,'transport':self.transport,
                'carriage_context':getattr(self,'_carriage_context',None).hex() if getattr(self,'_carriage_context',None) is not None else None,
                'domains':[NETWORK,mesh.VERSION],
                'limits':[MAX_MESSAGES,MAX_STATE,wire.MAX_PAYLOAD,mesh.MAX_MESSAGES,
                          mesh.MAX_BATCH,mesh.MAX_PACKET_BATCH,mesh.MAX_CONTACTS,
                          MAX_BROADCAST_HINT_BYTES,MAX_BROADCAST_QUIET_SECONDS,
                          MAX_BROADCAST_QUIET_CALLS],
                'local_complete_envelope_ids':rows,
                # Remote Native-checked envelopes also supply current-frame
                # scheduling hints. A new complete retained frame must invalidate
                # this quiet inventory even when all local recipient pairs match.
                # Exact IDs only; no proof, context or signing authority cached.
                'retained_complete_envelope_ids':[(self.state['messages'].content(i),i)
                                                 for i in sorted(self.state['messages'])],
                'recipients':recipients})
            if len(raw)<=MAX_BROADCAST_HINT_BYTES:inventory=raw
        quiet=getattr(self,'_broadcast_quiet',None)
        # Quiet inventory equality cannot preserve a discarded scheduling hint.
        # A missing bounded position takes the existing complete Mesh path;
        # this availability check grants no authentication or custody.
        priority_key=getattr(self,'_carriage_priority_key',None)
        if (inventory is not None and quiet is not None and inventory==quiet[0]
                and (priority_key is None or mesh.carriage_position(priority_key) is not None)
                and time.monotonic()-quiet[1]<MAX_BROADCAST_QUIET_SECONDS
                and quiet[2]<MAX_BROADCAST_QUIET_CALLS):
            self._broadcast_quiet=(inventory,quiet[1],quiet[2]+1)
            return
        # A miss, capacity fallback, changed scope, periodic probe or failure
        # takes the original complete Mesh path. No hint survives a failed read,
        # enqueue, close or companion publication. Restart always starts cold.
        self._broadcast_quiet=None
        pairs=[(content,ident,peer) for content,ident in rows for peer in recipients]
        carriage_node=getattr(self,'carriage_node',None)
        with (carriage_node() if carriage_node is not None else mesh.Node(self.transport)) as node:
            # Only the admitted base profile and an actual Native observation
            # can install this scheduling hint. Epoch/role profiles fall back.
            if (self.format==FORMAT and getattr(self,'_retained_native_authenticated',False)
                    and getattr(self,'_carriage_context',None) is not None):
                context=wire.decode_json(self._carriage_context)
                frames=commit_carriage_frames(self.state['messages'],context,
                                             tuple(self.peers),self.native.currency,self.region)
                scope=mesh.digest(dict(binding=self.binding,context=context,keys=sorted(self.peers),
                    native=[self.native.authority,self.native.currency,str(self.native.ledger)]))
                self._carriage_priority_key=node.set_carriage_priority(scope,frames)
            retained=set()
            for summary in node.summaries().values():
                if summary['source']==node.id and summary['kind']=='regional-bft':
                    retained.add((summary['export_id'],summary['destination']))
            pending=[pair for pair in pairs if (pair[0],pair[2]) not in retained]
            if pending:
                batch_pairs=carriage_batch(self.state['messages'],pending,
                                          self.state['height'],self.state['cursor'])
                batch=[]
                for content,ident,peer in batch_pairs:
                    payload=self.state['messages'].payload(ident)
                    batch.append((wire.make_frame('regional-bft',self.region,self.region,content,payload),peer))
                identifiers=node.enqueue_batch(batch)
                trace=getattr(self,'contact_trace',None)
                if trace is not None:
                    for ident,(content,_,peer) in zip(identifiers,batch_pairs):
                        trace.event('source_enqueued',peer,packet_id=ident,envelope_id=content,
                            frame_id=node.state['messages'][ident]['routing']['body']['frame_id'])
                retained.update((content,peer) for content,_,peer in batch_pairs)
            complete=all((content,peer) in retained for content,_,peer in pairs)
        if pending:self.save(dict(self.state,cursor=(self.state['cursor']+4)%(2**63)))
        # Complete Native envelope metadata is immutable in Messages. Equality
        # of this bounded inventory can postpone only an empty Mesh reread,
        # after the original durable path confirmed every recipient pair.
        if inventory is not None and complete:
            self._broadcast_quiet=(inventory,time.monotonic(),0)

    def signed(self, context, round_number, kind, phase=None, value=None):
        # Only a completed Runtime cold open enables this lookup. Immutable
        # retained bytes and the complete native context/binding scope it;
        # native quorum/sign/certificate checks remain unchanged below.
        if getattr(self, '_signed_query_ready', False):
            scope = {'format': self.format, 'binding': self.state['binding'],
                     'signing_binding': getattr(self, 'signing_binding', None),
                     'currency': self.native.currency, 'authority': self.native.authority,
                     'ledger': str(self.native.ledger)}
            witness, rows = signed_lookup(self._signed_query_index, self.state['messages'],
                                          context, scope, round_number, kind, phase, value, signed_body)
            self._signed_query_index = witness
            if rows is not None:
                return rows
        result=[]
        for _,body,message_value,_ in self.state['messages'].bodies():
            message=signed_body(body)
            if kind not in message:
                continue
            payload=message[kind]
            c=payload.get('context') if kind!='Proposal' else None
            if kind=='Proposal':
                s=payload['snapshot']['statement']
                matches=(s['currency']==context['currency'] and s['region']==context['region']
                         and s['epoch']==context['epoch'] and s['previous']==context['previous']
                         and s['height']==context['parent_height']+1)
            else:
                matches=c==context
            if (matches and payload['round']==round_number and (phase is None or payload.get('phase')==phase)
                    and (value is None or message_value==value)):
                result.append((payload,message_value))
        return result

    def quorum(self, context, round_number, phase, value):
        voters={v['approval']['key']:v for v,_ in self.signed(context,round_number,'Vote',phase,value)}
        observation = getattr(self, 'observation', None)
        if observation is not None:
            observation.event('quorum-search', context_id=mesh.digest(context), round=round_number,
                              phase=phase, value=value, distinct_votes=len(voters))
        if len(voters)<3:
            return None
        return self.with_json('bft-quorum',[voters[k] for k in sorted(voters)[:3]])

    def timeout_certificate(self, context, round_number):
        voters={v['approval']['key']:v for v,_ in self.signed(context,round_number,'Timeout')}
        if len(voters)<3:
            return None
        mesh.require(len(voters)<=4,'BFT timeout active voter bound')
        # Native already accepts three or four ordered votes and authenticates
        # every high QC. Do not discard the fourth voter's retained lock.
        return self.with_json('bft-timeout-certificate',[voters[k] for k in sorted(voters)])

    def _try_prepare(self, proposal):
        request={'Prepare':proposal}
        try:
            self.sign(request)
            return True
        except ValueError as error:
            if str(error)!='native rejected: regional candidate rejected: proposal violates durable prepared lock without a newer valid prepare QC':
                raise
            # The exact native refusal cannot reset a timer or bypass a lock.
            # Reconcile only this retained unsigned attempt under the separately
            # pinned head. A recovered response/head change refuses this path.
            retained=self.head['head']
            mesh.require(self.head['pending']==request and self.head['outbox'] is None,
                         'rejected Prepare lost its exact pending caller review')
            self.reconcile()
            mesh.require(self.head['head']==retained and self.head['pending'] is None
                         and self.head['outbox'] is None,
                         'rejected Prepare advanced native custody; retain response')
            return False

    def candidate(self, context, high=None):
        if high is not None:
            for _,body,message_value,_ in self.state['messages'].bodies():
                p=signed_body(body).get('Proposal')
                if p and message_value==high and p['snapshot']['statement']['height']==context['parent_height']+1:
                    return p['snapshot']
            raise ValueError('highest prepared value retained without its proposal; wait for carriage')
        commands=[]
        incoming=[]
        if self.joint is not None:
            plan=self.joint.plan_command(context)
            if plan is not None:incoming.append(plan)
        for _,body,_,_ in self.state['messages'].bodies():
            incoming.extend(body.get('Submission',body.get('EpochSubmission',{}).get('commands',[])))
        incoming.extend(self.native.call('bft-pending-imports'))
        seen=set()
        for command in incoming:
            ident=mesh.digest(command)
            if ident in seen or len(commands)>=4:
                continue
            seen.add(ident)
            try:
                self.with_json('bft-candidate',commands+[command],'--miner',self.miner)
            except ValueError as error:
                # A contended native trial never established command invalidity.
                # Abort this selection; the next ordinary tick retries from the
                # native head, with no empty/partial fallback or signing here.
                from regional_contact_node import NativeRefusal
                if (isinstance(error, NativeRefusal)
                        and error.command == 'bft-candidate'
                        and type(error.exit_code) is int and error.exit_code == 1
                        and error.diagnostic.strip() in (
                            'regional candidate rejected: lock acquisition failed because the operation would block',
                            'regional candidate rejected: complete stream already locked',
                        )):
                    raise
                continue  # retain stale/invalid submission; never rewrite or cancel it.
            commands.append(command)
        return self.with_json('bft-candidate',commands,'--miner',self.miner)

    def tick(self):
        started = time.monotonic()
        succeeded = False
        try:
            result = self._tick()
            succeeded = True
            return result
        finally:
            observation = getattr(self, 'observation', None)
            if observation is not None:
                observation.operation('consensus-tick', started, succeeded)
                observation.event('tick-end', started, succeeded=succeeded)

    def _tick(self):
        mesh.require(not self.failed, 'BFT runtime requires restart after persistence failure')
        if self.head['pending'] is not None:
            self.reconcile()
        self.flush_outbox()
        queue=self.native.ledger/'bft-submissions'
        if queue.exists():
            private(queue,True)
            files=sorted(queue.iterdir())
            mesh.require(len(files)<=32, 'BFT submission spool capacity')
            for path in files[:32]:
                # Native serde field order is not the mesh's sorted JSON wire
                # order. Bound/read the native file, then let Rust authenticate
                # its complete typed contents before canonical wire packing.
                envelope=wire.decode_json(wire.read_file(private(path),wire.MAX_PAYLOAD))
                if mesh.digest(envelope['body']) not in self.state['messages']:
                    self.retain(envelope,local=True)
        operation = object()
        loop_status = None
        if self.format == JOINT_FORMAT and isinstance(self.joint, JointEpoch):
            decision = self.joint.tick_for_native_loop(operation)
            if isinstance(decision, JointLoopStatus):
                loop_status = decision
                decision = False
        else:
            joint_tick = (getattr(self.joint, 'tick_for_native_loop', self.joint.tick)
                          if self.joint is not None else None)
            decision = joint_tick() if joint_tick is not None else False
        if decision:
            self.broadcast()
            context=self.observe()
            status=self.signer_status()
            return self.report(context,None,status,stopped=True)
        if self.joint is None and self.head['head'] is not None:
            context,status=self.loop_observation()
        else:
            context=self.observe()
            status = loop_status.read(self, operation) if loop_status is not None else None
            if status is None:
                status=self.signer_status()
        active=status['state'] if status['state'] is not None and status['state']['context']==context else {'round':0,'prepared':None,'committed':None,'proposed':False}
        round_number=active['round']
        slot=(mesh.digest(context),round_number)
        if self.slot!=slot:
            self.slot,self.entered_at=slot,time.monotonic()
        stopped=context['parent_height']>=self.stop_height or self.key_file is None or not self.key_file.exists() or self.head['head'] is None
        observation = getattr(self, 'observation', None)
        if observation is not None:
            observation.event('tick-phase', context_id=mesh.digest(context), height=context['parent_height'],
                              round=round_number, stopped=stopped, prepared=active['prepared'],
                              committed=active['committed'], phase_age_seconds=round(time.monotonic()-self.entered_at, 6))
        phase_advanced = False
        future = None
        # A local timeout does not invalidate a complete certificate for this
        # parent. Install delayed certified rounds even after moving ahead, and
        # even in read-only/keyless mode; only Rust authorizes the state change.
        for certified_round in range(32):
            for proposal,value in self.signed(context,certified_round,'Proposal'):
                # Incomplete Commit cannot finalize. Avoid aggregating Prepare
                # here only to aggregate it again for the signing phase below.
                # Complete pairs still require both original Native checks.
                committed=self.quorum(context,certified_round,'Commit',value)
                if committed is None:
                    continue
                prepared=self.quorum(context,certified_round,'Prepare',value)
                if prepared is not None:
                    certificate=self.with_json('bft-certify',{'proposal':proposal,'prepared':prepared,'committed':committed})
                    self.with_json('finalize',certificate)
                    self.retain_local_body({'Finalized':certificate})
                    self.observe()
                    self.broadcast()
                    return self.report(context,round_number,status,stopped=self.state['height']>=self.stop_height)
        if not stopped:
            current_proposals=self.signed(context,round_number,'Proposal')
            for proposal,value in current_proposals:
                prepared=self.quorum(context,round_number,'Prepare',value)
                if active['prepared'] is None:
                    if not self._try_prepare(proposal):
                        continue
                    phase_advanced = True
                    if prepared is not None:
                        fresh = self.signer_status()['state']
                        if (fresh is not None and fresh['context'] == context
                                and fresh['round'] == round_number
                                and fresh['prepared'] == value and fresh['committed'] is None):
                            self.sign({'Commit':{'proposal':proposal,'prepared':prepared}})
                    break
                if active['prepared']==value and active['committed'] is None and prepared is not None:
                    self.sign({'Commit':{'proposal':proposal,'prepared':prepared}})
                    phase_advanced = True
                    break
            else:
                future=[]
                for later in range(round_number+1,32):
                    future.extend(self.signed(context,later,'Proposal'))
                eligible=[]
                if not future:
                    for later in range(round_number+1,32):
                        if sorted(self.peers)[(context['parent_height']+later)%4]!=self.key:
                            continue
                        voters={v['approval']['key'] for v,_ in self.signed(context,later-1,'Timeout')}
                        if len(voters)>=3:eligible.append(later)
                proposed_round=max(eligible,default=round_number)
                leader=sorted(self.peers)[(context['parent_height']+proposed_round)%4]
                tc=None if proposed_round==0 else self.timeout_certificate(context,proposed_round-1)
                # Retained rows choose only a candidate round. Native aggregation,
                # leadership, highest-QC/value, signer/head and complete execution
                # still authorize the request. Existing future proposals take
                # Prepare first; current complete Prepare/Commit took priority above.
                if (not current_proposals and not future and leader==self.key and (proposed_round>round_number or not active['proposed'])
                        and (proposed_round==0 or tc is not None)
                        and time.monotonic()-self.entered_at>=self.block_interval):
                    highs=[v['high'] for v in tc['votes'] if v['high'] is not None] if tc else []
                    high=max(highs,key=lambda q:q['round'])['value'] if highs else None
                    self.sign({'Propose':{'round':proposed_round,'snapshot':self.candidate(context,high),'timeout':tc}})
                    phase_advanced = True
            # Release the current round phase before advancing to a future round.
            if not phase_advanced:
                # Learn certified future rounds rather than timing out forever one
                # round behind. Native Prepare validates the immediate timeout QC.
                if future is None:
                    future=[]
                    for later in range(round_number+1,32):
                        future.extend(self.signed(context,later,'Proposal'))
                if future:
                    for proposal,_ in sorted(future,key=lambda p:p[0]['round'],reverse=True):
                        if self._try_prepare(proposal):
                            phase_advanced = True
                            break
                if not phase_advanced and time.monotonic()-self.entered_at>=min(3600,self.round_timeout*(round_number+1)):
                    self.sign({'Timeout':{'context':context,'round':round_number}})
                    phase_advanced = True
        if phase_advanced:
            status = self.signer_status()
            fresh = status['state']
            if fresh is not None and fresh['context'] == context:
                round_number = fresh['round']
                self.slot = (mesh.digest(context), round_number)
            else:
                round_number = None
                self.slot = None
        self.broadcast()
        return self.report(context,round_number,status,stopped)

    def report(self, context, round_number, status, stopped):
        return {'format':self.format,'currency':self.native.currency,'region':self.region,'validator':self.key,
                'height':self.state['height'],'round':None if status['state'] is None else round_number,'native_records':status['records'],
                'retained_messages':len(self.state['messages']),'autonomous_signing_enabled':self.key_file is not None and self.key_file.exists() and self.head['head'] is not None,
                'joint_epoch_lifecycle_enabled':self.joint is not None,'joint_active_slot':self.joint.active if self.joint is not None else None,
                'explicit_stop_height_reached':self.state['height']>=self.stop_height,'caller_head_pending':self.head['pending'] is not None,
                'caller_head_rollback_qualification':False,'independent_bft_qualified':False,
                'physical_interstellar_route_qualified':False,'local_ground_timing_only':True}
