"""Explicit pinned, one-transition ground lifecycle; Rust owns all authority.

Old and new keys, native journals and independently retained caller heads stay
separate. A late new key without its boundary journal remains read-only. No
advertisement supplies keys, endpoints, pins or a membership/config update.
"""
import fcntl
import os
from pathlib import Path
import subprocess
from dataclasses import dataclass

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT = 'RLD-REGIONAL-BFT-NODE-JOINT-V1'
MAX_LOOP_OBSERVATION = 8 * 1024 * 1024
_LOOP_OBSERVATION = object()


@dataclass(frozen=True)
class JointLoopStatus:
    """One fresh Native query, confined to the exact ordinary loop operation.

    This is a scheduling observation. Signing still performs the normal fresh
    native signer/head check and atomic Native expected-head validation.
    """
    runtime: object
    operation: object
    scope: bytes
    status: bytes
    issued: object

    @classmethod
    def capture(cls, runtime, operation, status):
        if runtime.head['head'] is None or status.get('head') is None:
            return None  # The keyless Python observation is not a Native journal query.
        scope = wire.canonical({'binding': runtime.signing_binding, 'head': runtime.head})
        encoded = wire.canonical(status)
        if len(scope) + len(encoded) > MAX_LOOP_OBSERVATION:
            return None
        return cls(runtime, operation, scope, encoded, _LOOP_OBSERVATION)

    def read(self, runtime, operation):
        if (self.issued is not _LOOP_OBSERVATION or self.runtime is not runtime
                or self.operation is not operation
                or len(self.scope) + len(self.status) > MAX_LOOP_OBSERVATION
                or self.scope != wire.canonical({'binding': runtime.signing_binding, 'head': runtime.head})):
            return None
        status = wire.decode_json(self.status)
        mesh.require(status['binding'] == runtime.signing_binding
                     and status['head'] == runtime.head['head'],
                     'same-loop Native signer observation differs from caller binding/head')
        return status


def signed_body(body):
    return body.get('Signed', body.get('EpochSigned', {}).get('message', {}))


class JointEpoch:
    def __init__(self, runtime, config, old_validators, current):
        from regional_bft_node import private
        self.r = runtime
        mesh.require(current.get('rules')=='RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1',
                     'joint lifecycle requires explicit signed native admission')
        mesh.require(set(config) == {'key', 'key_file', 'signer_dir', 'head_file',
                                     'approval_dir', 'approval_head', 'validators', 'select_height'},
                     'joint lifecycle configuration fields differ')
        mesh.integer(config['select_height'], 1, 63)
        self.select_height = config['select_height']
        self.old = dict(key=runtime.key, key_file=runtime.key_file, signer=runtime.signer,
                        head_path=runtime.head_path, peers=self.peers(old_validators))
        self.new = dict(key=mesh.hex32(config['key']), key_file=private(config['key_file'], missing=True),
                        signer=private(config['signer_dir'], True, missing=True),
                        head_path=private(config['head_file']), peers=self.peers(config['validators']))
        mesh.require(set(self.old['peers']).isdisjoint(self.new['peers'])
                     and self.new['key'] in self.new['peers']
                     and self.old['peers'][self.old['key']] == self.new['peers'][self.new['key']],
                     'joint lifecycle needs explicit disjoint keys on the pinned local carrier')
        self.approval_dir = private(config['approval_dir'], True)
        self.approval_path = private(config['approval_head'])
        protected = (runtime.root, runtime.native.ledger, self.old['signer'], self.new['signer'], self.approval_dir)
        for path in (self.new['head_path'], self.approval_path):
            private(path.parent, True)
            mesh.require(all(p != path.parent and p not in path.parents for p in protected),
                         'joint caller head must survive every native/runtime directory backup')
            mesh.require(path.parent != self.old['head_path'].parent, 'joint caller directories must be separate')
            fd=os.open(path.parent/'.bft-runtime.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            runtime.extra_locks.append(fd)
            private(path.parent/'.bft-runtime.lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        mesh.require(self.new['head_path'].parent != self.approval_path.parent,
                     'new voting and candidate caller directories must be separate')
        self.approval_binding = dict(currency=runtime.native.currency, region=runtime.region, key=self.new['key'])
        self.approval = mesh.load(self.approval_path, 8*1024*1024)
        mesh.require(set(self.approval)=={'format','binding','head','pending','outbox'}
                     and self.approval['format']==FORMAT and self.approval['binding']==self.approval_binding,
                     'joint candidate caller binding differs')
        mesh.hex32(self.approval['head'])
        self.active = 'old'
        mesh.require(current['keys'] in [list(self.old['peers']), list(self.new['peers'])],
                     'current native membership is outside explicit joint configuration')

    @staticmethod
    def peers(validators):
        mesh.require(isinstance(validators,list) and len(validators)==4
                     and all(set(v)=={'key','node_id'} for v in validators), 'joint peer mapping fields')
        keys=[mesh.hex32(v['key']) for v in validators]
        ids=[mesh.hex32(v['node_id']) for v in validators]
        mesh.require(keys==sorted(set(keys)) and len(set(ids))==4, 'joint keys/carrier mapping duplicate or unordered')
        return dict(zip(keys,ids))

    def switch(self, name):
        slot=getattr(self,name)
        self.active=name
        for attr in ('key','key_file','signer','head_path','peers'):
            setattr(self.r,attr,slot[attr])
        self.r.signing_binding=dict(currency=self.r.native.currency,region=self.r.region,key=slot['key'])
        self.r.head=self.r.load_head(slot['head_path'],self.r.signing_binding,allow_initialization=name=='new')

    def save_approval(self, value):
        mesh.require(not self.r.failed and len(wire.canonical(value))<=8*1024*1024,
                     'joint candidate caller-head persistence unavailable/capacity')
        try:
            mesh.atomic(self.approval_path,value)
        except BaseException:
            self.r.failed=True
            raise
        self.approval=value

    def approval_status(self):
        status=self.r.native.call('signer-status','--signer-dir',self.approval_dir)
        mesh.require(status['binding']==self.approval_binding and status['lock_head']==self.approval['head'],
                     'candidate signer differs from separately retained caller head')
        return status

    def candidate_body(self, proposal, approval, previous):
        return {'EpochApproval':{'format':'RLD-JOINT-EPOCH-APPROVAL-V1','proposal':proposal,
                                 'previous_epochs':previous,'role':'New','approval':approval}}

    def reconcile_approval(self):
        pending=self.approval['pending']
        if pending is not None:
            try:
                result=self.r.with_json('signer-recover-handoff',pending['proposal'],
                    '--signer-dir',self.approval_dir,'--expected-lock',self.approval['head'])
            except (OSError,ValueError,subprocess.TimeoutExpired):
                self.approval_status() # Unchanged exact native head only; never adopt a different head.
                self.save_approval(dict(self.approval,pending=None))
            else:
                body=self.candidate_body(pending['proposal'],result['approval'],pending['previous_epochs'])
                self.save_approval(dict(self.approval,head=result['lock_head'],pending=None,outbox=body))
        if self.approval['outbox'] is not None:
            self.r.retain(self.r.envelope(self.approval['outbox']),sync=False,local=True)
            self.save_approval(dict(self.approval,outbox=None))
        self.approval_status()

    def initialize_new(self, current):
        head=self.r.head
        if head['head'] is not None:
            return
        # A surviving marker is recorded before native directory creation. Only
        # that exact empty journal may recover an interrupted initialization.
        if head['initialization'] is None:
            mesh.require(not self.new['signer'].exists(),
                         'new native journal cannot be adopted without retained initialization')
            proofs=current['epochs']
            mesh.require(proofs and proofs[-1]['statement']['validators']==list(self.new['peers']),
                         'new slot lacks native activation authority')
            if proofs[-1]['statement'] not in self.approval_status()['handoff_statements']:
                return # No durable local participation: catchup cannot create custody.
            if current['context']['parent_height'] != proofs[-1]['statement']['closing_height']:
                return # Late configured key remains read-only; no empty backdated journal.
            observation=self.r.native.call('bft-init-observation')
            self.r.save_head(dict(head,initialization=observation))
        if not self.new['signer'].exists():
            if current['context']['parent_height']!=self.r.head['initialization']['pin']['height']:
                return # Retain interrupted marker; late missing journal stays read-only.
            self.r.native.call('bft-init','--signer-dir',self.new['signer'],'--key',self.new['key'])
        status=self.r.native.call('bft-status','--signer-dir',self.new['signer'])
        mesh.require(status['records']==0 and status['binding']==self.r.signing_binding
                     and status['creation']==self.r.head['initialization'],
                     'interrupted new initialization is not the exact retained empty journal')
        self.r.save_head(dict(self.r.head,head=status['head'],initialization=None))

    def advance(self, status_sink=None):
        current=self.r.native.call('bft-context')
        name='new' if current['keys']==list(self.new['peers']) else 'old'
        mesh.require(current['keys']==list(getattr(self,name)['peers']), 'native membership escaped pinned joint plan')
        if name!=self.active:
            self.switch(name)
            self.r.slot=None
        if name=='new':
            self.initialize_new(current)
            if self.r.head['pending'] is not None:self.r.reconcile()
            self.r.flush_outbox()
            status = self.r.signer_status()
            if status_sink is not None:
                status_sink.append(status)
        return current

    def startup(self):
        # Recover old exact fences and outboxes even when native activation is
        # already installed. They retain their original key/head/journal.
        self.switch('old')
        if self.r.head['pending'] is not None:self.r.reconcile()
        self.r.signer_status()
        self.r.flush_outbox()
        self.reconcile_approval()
        self.advance()

    def decorate(self, body):
        if 'Signed' in body:
            message=body['Signed']
            if 'EpochApproval' in message:
                receipt=message['EpochApproval']
                scope=self.r.native.call('bft-epoch-proposal','--checkpoint',receipt['statement']['closing_checkpoint'])
                mesh.require(scope['proposal'] is not None and scope['proposal']['statement']==receipt['statement'],
                             'retained old fence does not match exact native selection')
                return {'EpochApproval':{'format':'RLD-JOINT-EPOCH-APPROVAL-V1',**scope,
                                         'role':'Old','approval':receipt['approval']}}
            return {'EpochSigned':{'message':message,'epochs':self.r.native.call('bft-context')['epochs']}}
        return body

    def plan_command(self, context):
        if self.active!='old' or context['parent_height']+1!=self.select_height:
            return None
        epochs=self.r.native.call('bft-context')['epochs']
        return {'Reconfigure':{'currency':context['currency'],'region':context['region'],
            'previous_epoch':context['epoch'],'number':len(epochs)+1,'validators':list(self.new['peers'])}}

    def tick(self):
        return self._tick()

    def tick_for_native_loop(self, operation):
        statuses = []
        stopped = self._tick(statuses)
        if not stopped and len(statuses) == 1:
            return JointLoopStatus.capture(self.r, operation, statuses[0]) or False
        return stopped

    def _tick(self, status_sink=None):
        self.reconcile_approval()
        current=self.advance(status_sink)
        if self.active=='new':return False
        scope=self.r.native.call('bft-epoch-proposal')
        proposal=scope['proposal']
        if proposal is None:return False
        s=proposal['statement']
        mesh.require(s['validators']==list(self.new['peers']) and s['closing_height']==self.select_height,
                     'selected membership differs from explicit local joint intent')
        if self.r.key_file.exists() and self.r.signer_status()['state']['epoch_fence'] is None:
            self.r.sign({'EpochFence':{'context':current['context'],**scope}})
        already=any(body.get('EpochApproval',{}).get('role')=='New'
                    and body['EpochApproval']['approval']['key']==self.new['key']
                    and body['EpochApproval']['proposal']['statement']==s
                    for _,body,_,_ in self.r.state['messages'].bodies())
        if self.new['key_file'].exists() and not already:
            self.approval_status()
            self.save_approval(dict(self.approval,pending=scope))
            result=self.r.with_json('sign-handoff',proposal,'--signer-dir',self.approval_dir,
                '--expected-lock',self.approval['head'],'--key-file',self.new['key_file'])
            body=self.candidate_body(proposal,result['approval'],scope['previous_epochs'])
            self.save_approval(dict(self.approval,head=result['lock_head'],pending=None,outbox=body))
            self.reconcile_approval()
        votes={}
        for _,body,_,_ in self.r.state['messages'].bodies():
            vote=body.get('EpochApproval')
            if vote and vote['proposal']['statement']==s:
                votes[vote['role'],vote['approval']['key']]=vote
        if sum(k[0]=='Old' for k in votes)>=3 and sum(k[0]=='New' for k in votes)>=3:
            complete=self.r.with_json('bft-epoch-combine',[votes[k] for k in sorted(votes)])
            envelope=self.r.envelope({'EpochActivation':complete})
            self.r.retain(envelope,local=True)
            self.advance()
        return True # Selected old era never falls through to ordinary timeout signing.
