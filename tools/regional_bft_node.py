#!/usr/bin/env python3
"""Bounded autonomous ground consensus companion; native Rust owns all votes.

Only explicitly configured, admitted validator keys sign. Authenticated mesh
carriage supplies bytes, not authority. Caller-head consent survives response
loss independently of the signer/runtime directories. No stellar RTT claim.
"""
import fcntl
from bisect import bisect_right
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
from regional_bft_pinned_cold import check_retained_pinned
from regional_bft_live_batch import inspect as inspect_live_batch
from regional_bft_live_batch import supported as supports_origin_receive, receive_origin
from regional_bft_joint_epoch import JointEpoch, JointLoopStatus, FORMAT as JOINT_FORMAT, signed_body
from regional_bft_joint_roles import RoleJoint, FORMAT as ROLE_FORMAT, readonly_head
from regional_native_startup import Inspection
from regional_bft_timeout_hint import ordered_timeout, ordered_timeout_vote

FORMAT = 'RLD-REGIONAL-BFT-NODE-V1'
ORIGIN_RUNTIME_FORMAT = 'RLD-REGIONAL-BFT-ORIGIN-NODE-V8'
NETWORK = 'RLD-REGIONAL-BFT-NETWORK-V2'
ORIGIN_NETWORK = 'RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3'
MAX_MESSAGES = 512
MAX_STATE = 32*1024*1024
MAX_BROADCAST_HINT_BYTES = 4*1024*1024
MAX_BROADCAST_QUIET_SECONDS = 4.0
MAX_BROADCAST_QUIET_CALLS = 16
MAX_CARRIAGE_FRONTIER_BYTES = 8192


def current_empty_proposal_hint(proposal, context, keys, *, allow_import=False):
    """Extra signature filter for a Native-checked bounded candidate and parent.

    Import commands (original maximum 16 per block) have a typed encoding.
    Children retain the empty-only default unless current Origin enables Import.
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
    encode=lambda value:wire.json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    headers=[];blocks=[]
    for index,block in enumerate(snapshot['blocks']):
        if (type(block) is not dict or set(block)!={'header','commands'}
                or type(block['commands']) is not list or len(block['commands'])>16
                or index==1 and block['commands']!=[] and not allow_import
                or type(block['header']) is not dict or set(block['header'])!=set(header_fields)):return False
        commands=[]
        for command in block['commands']:
            if (type(command) is not dict or set(command)!={'Import'}
                    or type(command['Import']) is not dict or set(command['Import'])!={'snapshot','export'}):return False
            imp=command['Import'];mesh.hex32(imp['snapshot']);mesh.hex32(imp['export'])
            commands.append({'Import':{'snapshot':imp['snapshot'],'export':imp['export']}})
        h={k:block['header'][k] for k in header_fields};headers.append(h);blocks.append(dict(header=h,commands=commands))
        if allow_import and commands and h['commands']!=hashlib.sha256(
                b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encode(commands)).hexdigest():return False
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


def commit_carriage_frames(messages, context, keys, currency, region, round_number=None, *, import_proposals=False):
    """Exact current votes and bounded empty proposals from Native-checked Messages.

    The signature check only narrows scheduling. Native still checks every
    complete envelope, dependency, lock and quorum before any authority.
    """
    mesh.require(isinstance(messages,Messages) and len(messages)<=MAX_MESSAGES,
                 'Commit carriage requires bounded retained messages')
    mesh.require(type(import_proposals) is bool,'invalid Origin carriage selection')
    fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
    if (type(context) is not dict or set(context)!=set(fields)
            or context['currency']!=currency or context['region']!=region):return ()
    if round_number is not None and (type(round_number) is not int or not 0<=round_number<32):return ()
    mesh.require(type(keys) is tuple and len(keys)==4 and len(set(keys))==4,
                 'Commit carriage requires configured base validators')
    for key in keys:mesh.hex32(key)
    frames=[];expanded_bytes=0;finalized_ids=[]
    rows=messages.bodies()
    if import_proposals:
        def order(row):
            signed=signed_body(row[1]);vote=signed.get('Vote',{})
            selected=signed.get('Proposal',signed.get('Vote',signed.get('Timeout',{})))
            phase=(0 if 'Proposal' in signed else 1 if vote.get('phase')=='Commit'
                   else 2 if vote.get('phase')=='Prepare' else 3 if 'Timeout' in signed else 4)
            number=selected.get('round')
            return phase, -number if type(number) is int else 0
        rows=sorted(rows,key=order)
    for ident,body,_,_ in rows:
        signed=body.get('Signed',{});vote=signed.get('Vote',{});proposal=signed.get('Proposal');finalized=body.get('Finalized');timeout=signed.get('Timeout')
        try:
            if finalized is not None:
                finalized_ids.append(ident)
                continue
            if timeout is not None:
                if round_number is not None and not max(0,round_number-1)<=timeout['round']<=round_number:continue
                ordered_timeout_vote(timeout,context,keys,timeout['round'])
            elif proposal is not None:
                if round_number is not None and proposal['round']!=round_number:continue
                imported=import_proposals and messages.record(ident)['header']['format']==ORIGIN_NETWORK
                if not current_empty_proposal_hint(proposal,context,keys,allow_import=imported):continue
            else:
                if vote.get('phase') not in ('Prepare','Commit') or vote.get('context')!=context:continue
                # Another signer can still complete the preceding phase after
                # this relay timed out. Native alone accepts delayed certificates.
                if round_number is not None and not max(0,round_number-1)<=vote.get('round',-1)<=round_number:continue
                approval=vote['approval'];key=approval['key']
                if key not in keys:continue
                data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+wire.json.dumps(
                    [{k:context[k] for k in fields},vote['round'],vote['value'],vote['phase'],key],
                    separators=(',',':'),ensure_ascii=False).encode()
                mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                    bytes.fromhex(approval['signature']),data)
            size=messages.record(ident)['size_bytes']
            if expanded_bytes+size>MAX_BROADCAST_HINT_BYTES:
                if import_proposals:continue
                return ()
            expanded_bytes+=size
            payload=messages.payload(ident);envelope=wire.decode_json(payload)
            if (envelope['format'] not in (NETWORK,ORIGIN_NETWORK) or envelope['currency']!=currency
                    or envelope['region']!=region):continue
            raw=wire.make_frame('regional-bft',region,region,messages.content(ident),payload)
            frames.append(wire.inspect_frame(raw)[0]['message_id'])
        except (KeyError,TypeError,ValueError,mesh.InvalidSignature):
            # A hint failure is ordinary scheduling fallback, never admission.
            continue
    if frames:
        # Origin already orders fully retained candidates by live proposal and
        # phase. Keep that scheduling order; Native authority still comes only
        # from complete replay, signatures, caller heads and quorum checks.
        return tuple(dict.fromkeys(frames)) if import_proposals else tuple(sorted(set(frames)))
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
            if (envelope['format'] not in (NETWORK,ORIGIN_NETWORK) or envelope['currency']!=currency
                    or envelope['region']!=region):continue
            raw=wire.make_frame('regional-bft',region,region,messages.content(ident),payload)
            frames.append(wire.inspect_frame(raw)[0]['message_id'])
        except (KeyError,TypeError,ValueError,mesh.InvalidSignature):
            continue
    return tuple(sorted(set(frames)))


def _carriage_current(messages,height):
    current=set()
    for ident,body,_,_ in messages.bodies():
        message=signed_body(body)
        proposal=message.get('Proposal');finalized=body.get('Finalized')
        context=message.get('Vote',message.get('Timeout',{})).get('context',{})
        if ((proposal is not None and proposal['snapshot']['statement']['height']==height+1)
                or (finalized is not None and finalized['statement']['height']==height)
                or context.get('parent_height')==height):current.add(ident)
    return current


def _carriage_pair_key(pair):
    content,ident,peer=pair
    return ident,peer,content


def carriage_frontier(messages,selected,height,previous=(None,None)):
    """Two process-local scheduling positions, never an authorization witness."""
    current=_carriage_current(messages,height)
    groups=([p for p in selected if p[1] in current],
            [p for p in selected if p[1] not in current])
    return tuple(_carriage_pair_key(rows[-1]) if rows else old
                 for rows,old in zip(groups,previous))


def carriage_batch(messages, pending, height, cursor, *, prepare_first=False, proposal_context=None,
                   class_position=None, first_proposal=None, first_prepare=None):
    """Reserve carriage for this native-observed height and retained history.

    Classification schedules already retained complete bytes only. It never
    validates an envelope or supplies a ledger, quorum or signing decision.
    """
    current = _carriage_current(messages,height)
    active = [pair for pair in pending if pair[1] in current]
    history = [pair for pair in pending if pair[1] not in current]

    def take(rows, count, after=None):
        if not rows:
            return []
        if after is not None:
            # New complete messages can insert before a positional cursor.
            # Seek after the last actually queued immutable pair instead.
            ordered=sorted(rows,key=_carriage_pair_key)
            keys=[_carriage_pair_key(pair) for pair in ordered]
            offset=bisect_right(keys,after)%len(ordered)
            return (ordered[offset:]+ordered[:offset])[:count]
        # Durable cursor advances by four per published batch. Rotate each
        # class by one so a stable odd/even class cannot pin its first slots.
        offset = (cursor // 4) % len(rows)
        return (rows[offset:] + rows[:offset])[:count]

    positions=class_position if class_position is not None else (None,None)
    if active and history:
        selected = take(active, 2,positions[0]) + take(history, 2,positions[1])
        # A short class donates its spare slot without starving either class.
        if len(selected) < 4:
            selected += [pair for pair in take(active + history, 4)
                         if pair not in selected][:4 - len(selected)]
    else:
        selected=take(active or history,4,positions[0] if active else positions[1])
    if prepare_first:
        # Already Native-authenticated complete rows schedule carriage only.
        # Replace a selected Commit by its still-waiting same-peer Prepare in
        # that same slot; do not move history or consume a fifth place. Once
        # queued, the dependency leaves pending and the Commit resumes service.
        intents={};prepares={};proposals={};proposal_intents={};prepare_candidates={}
        context_fields={'currency','region','epoch','previous','parent_height','parent_block','parent_state'}
        proposal_scope=(type(proposal_context) is dict and set(proposal_context)==context_fields
                        and proposal_context['parent_height']==height)
        for ident,body,value,local in messages.bodies():
            proposal=signed_body(body).get('Proposal')
            if proposal_scope and local and proposal is not None and value is not None:
                statement=proposal['snapshot']['statement']
                if (statement['height']==height+1 and all(statement[k]==proposal_context[k]
                        for k in ('currency','region','epoch','previous'))):
                    proposal_intents[ident]=wire.canonical(
                        [proposal_context,proposal['round'],value,proposal['leader']['key']])
            vote=signed_body(body).get('Vote')
            if vote is None:continue
            intent=wire.canonical([vote['context'],vote['round'],vote['value'],vote['approval']['key']])
            intents[ident]=(vote['phase'],intent)
            if (proposal_scope and local and value is not None and vote['phase']=='Prepare'
                    and vote['context']==proposal_context and vote['value']==value):
                prepare_candidates[ident]=(vote['round'],vote['approval']['key'])
        for pair in active:
            phase,intent=intents.get(pair[1],(None,None))
            if phase=='Prepare':prepares.setdefault((intent,pair[2]),pair)
            proposal_intent=proposal_intents.get(pair[1])
            if proposal_intent is not None:proposals.setdefault((proposal_intent,pair[2]),pair)
        # Only the fresh local Propose publication may close its configured
        # recipient set in this original four-item unit. One history place
        # remains even for three recipients. Later/recovered broadcasts keep
        # the ordinary two/two reservation and the independent history frontier.
        closed_proposal=False
        if (proposal_scope and type(first_proposal) is tuple and len(first_proposal)==3
                and type(first_proposal[0]) is int and 0<=first_proposal[0]<32
                and type(first_proposal[1]) is str and type(first_proposal[2]) is tuple
                and 0<len(first_proposal[2])<=3
                and all(type(peer) is str for peer in first_proposal[2])
                and len(set(first_proposal[2]))==len(first_proposal[2])):
            fresh_round,own_key,recipients=first_proposal
            matching=[]
            for ident,body,_,_ in messages.bodies():
                proposal=signed_body(body).get('Proposal')
                if (ident in proposal_intents and proposal['round']==fresh_round
                        and proposal['leader']['key']==own_key):matching.append(ident)
            if len(matching)==1:
                copies=[pair for pair in active if pair[1]==matching[0]]
                if (len(copies)==len(recipients)
                        and {pair[2] for pair in copies}==set(recipients)):
                    selected=sorted(copies,key=_carriage_pair_key)
                    selected+=take(history,min(2,4-len(selected)),positions[1])
                    selected+=[pair for pair in take(active+history,4)
                               if pair not in selected][:4-len(selected)]
                    closed_proposal=True
        # A just-Native-signed, fully retained own Prepare gets the same bounded
        # first recipient closure. It cannot supersede a fresh own Proposal or
        # bypass the same-peer dependencies below. No leader/online preference.
        if (not closed_proposal and proposal_scope and type(first_prepare) is tuple
                and len(first_prepare)==3 and type(first_prepare[0]) is int
                and 0<=first_prepare[0]<32 and type(first_prepare[1]) is str
                and type(first_prepare[2]) is tuple and 0<len(first_prepare[2])<=3
                and all(type(peer) is str for peer in first_prepare[2])
                and len(set(first_prepare[2]))==len(first_prepare[2])):
            fresh_round,own_key,recipients=first_prepare
            matching=[ident for ident,binding in prepare_candidates.items()
                      if binding==(fresh_round,own_key)]
            if len(matching)==1:
                copies=[pair for pair in active if pair[1]==matching[0]]
                if (len(copies)==len(recipients)
                        and {pair[2] for pair in copies}==set(recipients)):
                    selected=sorted(copies,key=_carriage_pair_key)
                    selected+=take(history,min(2,4-len(selected)),positions[1])
                    selected+=[pair for pair in take(active+history,4)
                               if pair not in selected][:4-len(selected)]
        for index,pair in enumerate(selected):
            if pair not in active:continue
            phase,intent=intents.get(pair[1],(None,None))
            # A same-peer own Proposal is the earliest still-waiting ancestor.
            # Its value comes from complete Native authentication, never a
            # Python candidate hash. Only the identical complete fresh context,
            # round, value and leader/own-voter key may match this scheduling hint.
            dependencies=[]
            if phase in ('Prepare','Commit'):dependencies.append(proposals.get((intent,pair[2])))
            if phase=='Commit':dependencies.append(prepares.get((intent,pair[2])))
            for dependency in dependencies:
                if dependency is not None and dependency not in selected:
                    selected[index]=dependency
                    break
    return selected


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
        mesh.require((set(config) in (fields,fields|{'startup_native_history_head'}) and config['format'] in (FORMAT,ORIGIN_RUNTIME_FORMAT))
                     or (set(config)==fields|{'joint_epoch'} and config['format']==JOINT_FORMAT)
                     or (set(config)==role_fields and roles),
                     'BFT configuration fields/version invalid')
        startup_head=config.get('startup_native_history_head')
        if 'startup_native_history_head' in config:
            mesh.hex32(startup_head)
            mesh.require(startup_head!='0'*64,'explicit nonzero startup Native history head required')
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
                if startup_head is None:check_cold_retained(self)
                else:check_retained_pinned(self,startup_head)
            else:
                self.state = {'format':self.format,'binding':self.binding,'messages':Messages(),'height':0,'tip':self.region,'snapshot_cache':[],'cursor':0}
                if startup_head is not None:check_retained_pinned(self,startup_head)
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
            if self.format==ORIGIN_RUNTIME_FORMAT:
                finality=self.native.call('bft-origin-current-finality')
                mesh.require(type(finality) is dict and set(finality)=={'format','currency','region','height','rules','snapshot','ledger_changed','signing_authority'}
                    and finality['format']=='RLD-ORIGIN-CURRENT-FINALITY-V2'
                    and finality['currency']==self.native.currency and finality['region']==self.region
                    and finality['height']==self.state['height']
                    and finality['rules']=='RLD-REGIONAL-BFT-COMPLETE-ORIGIN-NETWORK-FIXTURE-V2'
                    and finality['ledger_changed'] is False and finality['signing_authority'] is False,
                    'origin startup native finality binding differs')
                local=[] if finality['snapshot'] is None else [finality['snapshot']]
                mesh.require(not local or local[0]['statement']['region']==self.region
                    and local[0]['statement']['height']==self.state['height'],
                    'origin startup current local certificate differs')
            else:
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
        self._carriage_round = None
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
        if getattr(self,'format',None) in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None:
            from regional_bft_local_envelope import pack
            envelope,verified=pack(self,body)
            self._retain_checked(envelope,verified,sync=False,local=True)
        else:
            self.retain(self.envelope(body),sync=False,local=True)

    def sign(self, request):
        before_sign=getattr(self,'before_sign',None)
        if before_sign is not None:before_sign()
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
        trace=getattr(self,'contact_trace',None)
        def timeout_event(stage):
            if trace is not None and kind=='Timeout' and context is not None:
                try:trace.event(stage,scope_id=mesh.digest(context),attempt=selected['round'])
                except Exception:
                    try:trace.reject()
                    except Exception:pass
        timeout_event('timeout_requested')
        try:
            self._sign(request)
            succeeded = True
        finally:
            timeout_event('timeout_retained' if succeeded else 'timeout_failed')
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
        if getattr(self,'format',None)==ORIGIN_RUNTIME_FORMAT and self.joint is None:
            from regional_bft_sign_envelope import sign
            operation=getattr(self,'_tick_operation',None)
            native_head=getattr(self,'_sign_native_head',None) if operation is not None else None
            if native_head is None:
                observed=self.native.call('history-head')
                mesh.require(observed['currency']==self.native.currency and observed['region']==self.region,
                             'composed Native head domain differs')
                native_head=mesh.hex32(observed['history_head'])
            self._sign_stage('pending',self.save_head,dict(self.head,pending=request))
            result,envelope,checked,status=self._sign_stage('native',sign,self,request,native_head)
            self._sign_stage('response',self.save_head,
                dict(self.head,head=result['head'],pending=None,outbox=result['message']))
            # Independent caller head is durable before any local retention or
            # carriage release. A failed retention leaves the original outbox.
            self._sign_stage('outbox',self._retain_checked,envelope,checked,False,True)
            self.save_head(dict(self.head,outbox=None))
            if operation is not None:
                scope=wire.canonical({'binding':self.signing_binding,'head':self.head,
                    'native':[self.native.currency,self.native.authority,str(self.native.ledger)]})
                self._composed_phase_observation=(operation,scope,wire.canonical(status))
            self.entered_at=time.monotonic()
            return
        self._sign_stage('status', self.signer_status)
        self._sign_stage('pending', self.save_head, dict(self.head,pending=request))
        result=self._sign_stage('native', self.with_json, 'bft-sign',request,'--signer-dir',self.signer,'--expected-head',self.head['head'],'--key-file',self.key_file)
        self._sign_stage('response', self.save_head, dict(self.head,head=result['head'],pending=None,outbox=result['message']))
        self._sign_stage('outbox', self.flush_outbox)
        # Give a newly persisted local phase time to propagate. Native one-vote
        # rules bound these resets; arbitrary peer traffic cannot renew a timer.
        self.entered_at=time.monotonic()

    def envelope(self, body):
        if getattr(self,'format',None) in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None:
            from regional_bft_local_envelope import pack
            return pack(self,body)[0]
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
        self._keyless_drain_observation=None
        retained=(getattr(self,'format',None) in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None
                  and (self.key_file is None or not self.key_file.exists()))
        args=['bft-loop-status','--signer-dir',self.signer,'--expected-head',self.head['head']]
        if retained:args.append('--include-retained-messages')
        value=self.native.call(*args)
        fields={'format','native','signer','signing_authority','independent_freshness_qualified'}
        if retained:fields.add('retained_messages')
        origin=getattr(self,'format',None)==ORIGIN_RUNTIME_FORMAT and self.joint is None
        if origin:fields.add('native_history_head')
        expected_format=(('RLD-BFT-LOOP-ORIGIN-RETAINED-OBSERVATION-V2' if retained else
                          'RLD-BFT-LOOP-ORIGIN-OBSERVATION-V2') if origin else
                         ('RLD-BFT-LOOP-RETAINED-OBSERVATION-V1' if retained else
                          'RLD-BFT-LOOP-OBSERVATION-V1'))
        mesh.require(set(value)==fields
                     and value['format']==expected_format
                     and value['signing_authority'] is False and value['independent_freshness_qualified'] is False,
                     'BFT loop observation domain differs')
        status=value['signer']
        mesh.require(status['binding']==self.signing_binding and status['head']==self.head['head'],
                     'BFT signer differs from separately retained caller head')
        if origin:self._sign_native_head=mesh.hex32(value['native_history_head'])
        drain=None
        if retained:
            from regional_bft_keyless_drain import current_commits
            drain=current_commits(value['native']['context'],value['retained_messages'],
                                  self.key,self.head['head'])
        context=self._observe_context(value['native']['context'])
        self._keyless_drain_observation=drain
        return context,status

    def phase_status(self):
        """Same-tick scheduling only; every next signature fully replays again."""
        observed=getattr(self,'_composed_phase_observation',None)
        operation=getattr(self,'_tick_operation',None)
        if observed is not None and operation is not None and observed[0] is operation:
            scope=wire.canonical({'binding':self.signing_binding,'head':self.head,
                'native':[self.native.currency,self.native.authority,str(self.native.ledger)]})
            if (observed[1]==scope and self.head['pending'] is None and self.head['outbox'] is None
                    and len(observed[2])<=8*1024*1024):
                return wire.decode_json(observed[2])
        return self.signer_status()

    def observe(self):
        return self._observe_context(self.native.call('bft-context')['context'])

    def _observe_context(self, value):
        mesh.require(value['parent_height']>=self.state['height']
                     and (value['parent_height']!=self.state['height'] or value['parent_block']==self.state['tip']),
                     'BFT native ledger rolled back beneath retained runtime observation')
        if value['parent_height']!=self.state['height']:
            self.save(dict(self.state,height=value['parent_height'],tip=value['parent_block']))
        if getattr(self,'format',None)==ORIGIN_RUNTIME_FORMAT and self.joint is None:
            # Start a new parent's initial interval at its complete Native
            # observation, including receive/finalize before the next tick.
            # Reobserving identical evidence cannot renew either timer. This
            # process-local timestamp grants no signer or ledger authority.
            context=wire.canonical(value)
            seen=getattr(self,'_phase_context_started',None)
            if seen is None or seen[0]!=context:
                self._phase_context_started=(context,time.monotonic())
        if getattr(self,'format',None) in (FORMAT,ORIGIN_RUNTIME_FORMAT):
            context=wire.canonical(value)
            if context!=getattr(self,'_carriage_context',None):
                mesh.forget_carriage_position(getattr(self,'_carriage_priority_key',None))
                self._carriage_priority_key=None
                self._carriage_round=None
            self._carriage_context=context
        return value

    def retain(self, envelope, sync=True, local=False):
        # A retained signed body does not authenticate a later envelope's proof.
        # Check every complete envelope before deduplication and let newly
        # certified dependencies reach native sync without replacing old bytes.
        if envelope.get('format')==ORIGIN_NETWORK:self.observe_origin_conflicts(envelope)
        verified=self.with_json('bft-network-check',envelope)
        self._retain_checked(envelope,verified,sync,local)

    def observe_origin_conflicts(self,envelope):
        # Native authenticates finality incidents even when normal body checking
        # refuses. This cannot install evidence, finalize a block or grant a vote.
        mesh.require(len(wire.canonical(envelope))<=wire.MAX_PAYLOAD,'origin conflict wire capacity')
        head=self.native.call('history-head')
        mesh.require(type(head) is dict and head.get('currency')==self.native.currency
            and head.get('region')==self.region,'origin conflict native head domain differs')
        mesh.hex32(head['history_head'])
        return self.with_json('bft-origin-network-observe-conflicts',envelope,
            '--expected-head',head['history_head'])

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
        if sync and envelope['format']==ORIGIN_NETWORK:
            # No Python proof cache authorizes this path. Native re-authenticates
            # the original whole envelope under this separately read current head.
            head=self.native.call('history-head')
            mesh.require(type(head) is dict and head.get('currency')==self.native.currency
                and head.get('region')==self.region,'origin sync native head domain differs')
            mesh.hex32(head['history_head'])
            self.with_json('bft-origin-network-sync',envelope,'--expected-head',head['history_head'])
            self.observe()
        elif sync and any(f not in self.state['snapshot_cache'] for f in fingerprints):
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
        # Preserve authenticated incidents first, then complete all Native
        # body authentication before any dependency sync or message retention.
        started=time.monotonic()
        synchronized=False
        try:
            # Capacity selection grants no rights. Unsupported cases retain the
            # original all-authenticate-before-sync path; never fall back after
            # a mutating Native call or refuse a new proof based on body dedup.
            if supports_origin_receive(self,envelopes) and len(set(self.state['messages']) |
                    {mesh.digest(e['body']) for e in envelopes})<=MAX_MESSAGES:
                checked,context=receive_origin(self,envelopes)
                self._observe_context(context)
                synchronized=True
            else:
                for envelope in envelopes:
                    if envelope.get('format')==ORIGIN_NETWORK:self.observe_origin_conflicts(envelope)
                checked=inspect_live_batch(self,envelopes)
        except (OSError,ValueError,subprocess.TimeoutExpired):
            for _ in raws:self.observation.event('receive-end',started,succeeded=False)
            raise
        for envelope,verified in zip(envelopes,checked):
            succeeded=False;started=time.monotonic()
            try:
                self._retain_checked(envelope,verified,sync=not synchronized)
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
        # A Service may publish a complete Propose before its own Prepare.
        # That consumes this unit's original carriage selection, never an
        # additional four-item enqueue opportunity at the ordinary tail.
        if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                and getattr(self,'_tick_operation',None) is not None):
            if getattr(self,'_broadcast_unit_done',False):return
            self._broadcast_unit_done=True
        # A unit already consumed by early Propose has made no Prepare attempt.
        # Keep that small hint for the next unit, but discard it before every
        # fallible attempt. Restart and failed publication retain original paths.
        fresh_prepare=getattr(self,'_first_prepare_carriage',None)
        self._first_prepare_carriage=None
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
                'carriage_round':getattr(self,'_carriage_round',None),
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
        previous_position=getattr(self,'_broadcast_class_position',None)
        self._broadcast_class_position=None
        class_scope=None;class_position=None
        pairs=[(content,ident,peer) for content,ident in rows for peer in recipients]
        carriage_node=getattr(self,'carriage_node',None)
        with (carriage_node() if carriage_node is not None else mesh.Node(self.transport)) as node:
            proposal_context=None
            # Only the admitted base profile and an actual Native observation
            # can install this scheduling hint. Epoch/role profiles fall back.
            if (self.format in (FORMAT,ORIGIN_RUNTIME_FORMAT) and getattr(self,'_retained_native_authenticated',False)
                    and getattr(self,'_carriage_context',None) is not None):
                context=wire.decode_json(self._carriage_context)
                if self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None:proposal_context=context
                frames=commit_carriage_frames(self.state['messages'],context,
                                             tuple(self.peers),self.native.currency,self.region,
                                             getattr(self,'_carriage_round',None),
                                             import_proposals=self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None)
                scope=mesh.digest(dict(binding=self.binding,context=context,round=getattr(self,'_carriage_round',None),keys=sorted(self.peers),
                    native=[self.native.authority,self.native.currency,str(self.native.ledger)]))
                self._carriage_priority_key=(node.set_carriage_priority(scope,frames,ordered_frames=True)
                    if self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                    else node.set_carriage_priority(scope,frames))
            retained=set()
            for summary in node.summaries().values():
                if summary['source']==node.id and summary['kind']=='regional-bft':
                    retained.add((summary['export_id'],summary['destination']))
            pending=[pair for pair in pairs if (pair[0],pair[2]) not in retained]
            if proposal_context is not None:
                domain=wire.canonical(dict(format=self.format,binding=self.binding,
                    native=[self.native.authority,self.native.currency,str(self.native.ledger)],
                    region=self.region,node_id=self.node_id,transport=self.transport,
                    context=proposal_context,peers=sorted(self.peers.items()),
                    limits=[MAX_MESSAGES,MAX_STATE,wire.MAX_PAYLOAD,mesh.MAX_CONTACTS,4,
                            MAX_CARRIAGE_FRONTIER_BYTES]))
                if len(domain)<=MAX_CARRIAGE_FRONTIER_BYTES:
                    class_scope=domain
                    class_position=(previous_position[1] if previous_position is not None
                        and previous_position[0]==domain else (None,None))
            if pending:
                fresh_proposal=getattr(self,'_first_proposal_carriage',None)
                first_proposal=(fresh_proposal+(tuple(recipients),)
                    if proposal_context is not None and type(fresh_proposal) is tuple
                    and len(fresh_proposal)==2 else None)
                first_prepare=(fresh_prepare+(tuple(recipients),)
                    if proposal_context is not None and type(fresh_prepare) is tuple
                    and len(fresh_prepare)==2 else None)
                batch_pairs=carriage_batch(self.state['messages'],pending,
                                          self.state['height'],self.state['cursor'],
                                          prepare_first=self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None,
                                          proposal_context=proposal_context,
                                          class_position=class_position,
                                          first_proposal=first_proposal,
                                          first_prepare=first_prepare)
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
                if class_position is not None:
                    class_position=carriage_frontier(self.state['messages'],batch_pairs,
                                                    self.state['height'],class_position)
            complete=all((content,peer) in retained for content,_,peer in pairs)
        if pending:self.save(dict(self.state,cursor=(self.state['cursor']+4)%(2**63)))
        if (class_scope is not None and len(class_scope)+len(wire.canonical(class_position))
                <=MAX_CARRIAGE_FRONTIER_BYTES):
            self._broadcast_class_position=(class_scope,class_position)
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
            if (getattr(self,'format',None)==ORIGIN_RUNTIME_FORMAT and self.joint is None
                    and getattr(self,'_retained_native_authenticated',False)):
                self._first_prepare_carriage=(proposal['round'],self.key)
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
        from regional_bft_submission_observation import event
        event(self,'consensus_tick_started')
        started = time.monotonic()
        succeeded = False
        self._tick_operation=object()
        self._timeout_refresh_used=False
        self._initial_proposal_wait_used=False
        self._finalization_phase_used=False
        self._broadcast_unit_done=False
        self._composed_phase_observation=None
        self._sign_native_head=None
        try:
            result = self._tick()
            succeeded = True
            return result
        finally:
            event(self,'consensus_tick_finished')
            self._tick_operation=None
            self._composed_phase_observation=None
            self._sign_native_head=None
            observation = getattr(self, 'observation', None)
            if observation is not None:
                observation.operation('consensus-tick', started, succeeded)
                observation.event('tick-end', started, succeeded=succeeded)

    def _tick(self):
        mesh.require(not self.failed, 'BFT runtime requires restart after persistence failure')
        self._keyless_drain_observation=None
        if self.head['pending'] is not None:
            self.reconcile()
        self.flush_outbox()
        from regional_bft_submission_observation import read_submissions
        read_submissions(self)
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
        from regional_bft_submission_observation import event
        event(self,'consensus_context_observed',scope_id=mesh.digest(context),attempt=round_number,
              selected=context['parent_height'])
        if self.format in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None:self._carriage_round=round_number
        slot=(mesh.digest(context),round_number)
        if self.slot!=slot:
            entered=time.monotonic()
            seen=getattr(self,'_phase_context_started',None)
            if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                    and round_number==0 and seen is not None
                    and seen[0]==wire.canonical(context)
                    and (self.slot is None or self.slot[0]!=slot[0])):
                entered=seen[1]
            self.slot,self.entered_at=slot,entered
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
                    return self._finish_local_finalization(certificate,context,round_number,status)
        if not stopped:
            current_proposals=self.signed(context,round_number,'Proposal')
            for proposal,value in current_proposals:
                # A persisted Prepare and Commit cannot use another Prepare
                # aggregate here. The finalization path above still requires
                # both complete Native quorums before certifying any value.
                prepared=(None if active['prepared'] is not None and active['committed'] is not None
                          else self.quorum(context,round_number,'Prepare',value))
                if active['prepared'] is None:
                    if not self._try_prepare(proposal):
                        continue
                    phase_advanced = True
                    if (prepared is None and self.format==ORIGIN_RUNTIME_FORMAT
                            and self.joint is None):
                        # The fully retained own Prepare may be the third exact
                        # vote. Reaggregate through Native after its independent
                        # caller head and complete envelope have been persisted.
                        prepared=self.quorum(context,round_number,'Prepare',value)
                    if prepared is not None:
                        fresh = Runtime.phase_status(self)['state']
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
                can_propose=(not current_proposals and not future and leader==self.key
                             and (proposed_round>round_number or not active['proposed'])
                             and (proposed_round==0 or tc is not None))
                wait=getattr(self,'before_initial_proposal',None)
                if (can_propose and self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                        and proposed_round==round_number==0 and active['prepared'] is None
                        and active['committed'] is None and callable(wait)
                        and not self._initial_proposal_wait_used
                        and time.monotonic()-self.entered_at<self.block_interval):
                    # A bounded Service wait services the original interval in
                    # this contact unit, before broadcast/outgoing work. A new
                    # complete Native observation must follow the wait; no old
                    # caller/head projection may authorize its phase request.
                    self._initial_proposal_wait_used=True
                    if wait(self.entered_at+self.block_interval):
                        self._tick_operation=object()
                        self._composed_phase_observation=None
                        self._sign_native_head=None
                        return self._tick()
                if can_propose and time.monotonic()-self.entered_at>=self.block_interval:
                    highs=[v['high'] for v in tc['votes'] if v['high'] is not None] if tc else []
                    high=max(highs,key=lambda q:q['round'])['value'] if highs else None
                    proposed={'round':proposed_round,'snapshot':self.candidate(context,high),'timeout':tc}
                    self.sign({'Propose':proposed})
                    publish=getattr(self,'after_local_proposal',None)
                    if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                            and callable(publish)):
                        # Complete Native authentication and independent head /
                        # outbox retention already returned successfully. The
                        # following Prepare can fail without suppressing this
                        # immutable, independently authorized evidence.
                        self._first_proposal_carriage=(proposed_round,self.key)
                        try:publish()
                        finally:self._first_proposal_carriage=None
                    phase_advanced = True
                    if self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None:
                        # Propose already retained its independent caller head
                        # and complete Native-checked envelope. Do not wait a
                        # whole contact unit merely to request our own Prepare.
                        # This observation schedules only: Prepare still fully
                        # replays and checks both current heads under Native locks.
                        fresh=Runtime.phase_status(self)['state']
                        if (fresh is not None and fresh['context']==context
                                and fresh['round']==proposed_round and fresh['proposed']
                                and fresh['prepared'] is None and fresh['committed'] is None):
                            for proposal,_ in self.signed(context,proposed_round,'Proposal'):
                                if (proposal['leader']['key']==self.key
                                        and wire.canonical(proposal['snapshot'])==wire.canonical(proposed['snapshot'])
                                        and wire.canonical(proposal['timeout'])==wire.canonical(proposed['timeout'])):
                                    self._try_prepare(proposal)
                                    break
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
                    refresh=getattr(self,'before_timeout',None)
                    if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                            and callable(refresh) and not self._timeout_refresh_used):
                        self._timeout_refresh_used=True
                        if refresh():
                            # Authentication may advance Native state or caller
                            # heads. Discard every old operation projection and
                            # reobserve through Native before any phase request.
                            self._tick_operation=object()
                            self._composed_phase_observation=None
                            self._sign_native_head=None
                            return self._tick()
                    self.sign({'Timeout':{'context':context,'round':round_number}})
                    phase_advanced = True
        if phase_advanced:
            status = Runtime.phase_status(self)
            fresh = status['state']
            if fresh is not None and fresh['context'] == context:
                round_number = fresh['round']
                self.slot = (mesh.digest(context), round_number)
            else:
                round_number = None
                self.slot = None
            if self.format in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None:self._carriage_round=round_number
            if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                    and fresh is not None and fresh['context']==context
                    and fresh['committed'] is not None):
                # A newly durable own Commit can complete the quorum in this
                # unit. Counts/phase telemetry authorize nothing: both full
                # Native aggregates, certification and installation still run.
                for proposal,value in self.signed(context,round_number,'Proposal'):
                    if value!=fresh['committed']:continue
                    committed=self.quorum(context,round_number,'Commit',value)
                    if committed is None:continue
                    prepared=self.quorum(context,round_number,'Prepare',value)
                    if prepared is None:continue
                    certificate=self.with_json('bft-certify',{'proposal':proposal,'prepared':prepared,'committed':committed})
                    return self._finish_local_finalization(certificate,context,round_number,status)
        self._broadcast_after_observation()
        return self.report(context,round_number,status,stopped)

    def _finish_local_finalization(self, certificate, context, round_number, status):
        self.with_json('finalize',certificate)
        self.retain_local_body({'Finalized':certificate})
        fresh=self.observe()
        proceed=getattr(self,'after_local_finalization',None)
        if (self.format==ORIGIN_RUNTIME_FORMAT and self.joint is None
                and not getattr(self,'_finalization_phase_used',False)
                and callable(proceed) and fresh['parent_height']>context['parent_height']
                and fresh['parent_height']<self.stop_height
                and self.key_file is not None and self.key_file.exists()
                and self.head['head'] is not None and self.head['pending'] is None
                and self.head.get('outbox') is None
                and sorted(self.peers)[fresh['parent_height']%4]==self.key):
            # Native installation, complete local envelope retention and the
            # new-parent observation have all completed durably. Service may
            # schedule one successor phase before its outgoing tail. This is
            # no authorization cache: reopen both Native heads, honor the same
            # interval/round fences and keep the unit's original intake quota.
            self._finalization_phase_used=True
            if proceed():
                self._tick_operation=object()
                self._composed_phase_observation=None
                self._sign_native_head=None
                return self._tick()
        self.broadcast()
        return self.report(context,round_number,status,stopped=self.state['height']>=self.stop_height)

    def _broadcast_after_observation(self):
        """A keyless Native observation is separate from an occupied mesh lease.

        Only the typed pre-Node scheduling refusal may defer this broadcast.
        Native/caller/outbox checks, delayed finalization and all retained bytes
        still precede this point. Never defer active signing, epochs, corruption,
        persistence failures or untyped OS errors; never claim enqueue/custody.
        """
        from interstellar_tcp import MeshTurnPending
        self._carriage_deferred=False
        try:self.broadcast()
        except MeshTurnPending:
            if not (self.format in (FORMAT,ORIGIN_RUNTIME_FORMAT) and self.joint is None
                    and getattr(self,'_retained_native_authenticated',False) is True
                    and (self.key_file is None or not self.key_file.exists())
                    and self.head['head'] is not None and self.head['pending'] is None
                    and self.head.get('outbox') is None):
                raise
            self._carriage_deferred=True
            observation=getattr(self,'observation',None)
            if observation is not None:observation.event('keyless-carriage-deferred')

    def report(self, context, round_number, status, stopped):
        return {'format':self.format,'currency':self.native.currency,'region':self.region,'validator':self.key,
                'height':self.state['height'],'round':None if status['state'] is None else round_number,'native_records':status['records'],
                'retained_messages':len(self.state['messages']),'autonomous_signing_enabled':self.key_file is not None and self.key_file.exists() and self.head['head'] is not None,
                'joint_epoch_lifecycle_enabled':self.joint is not None,'joint_active_slot':self.joint.active if self.joint is not None else None,
                'explicit_stop_height_reached':self.state['height']>=self.stop_height,'caller_head_pending':self.head['pending'] is not None,
                'caller_head_rollback_qualification':False,'independent_bft_qualified':False,
                'physical_interstellar_route_qualified':False,'local_ground_timing_only':True,
                **({'carriage_deferred':True} if getattr(self,'_carriage_deferred',False) else {}),
                **({'native_keyless_drain':self._keyless_drain_observation}
                   if getattr(self,'_keyless_drain_observation',None) is not None else {})}
