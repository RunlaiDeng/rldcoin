"""Pinned multi-era role lifecycle. Native journals alone authorize custody/votes.

Carrier, local slot and readiness are distinct. Every caller directory is
separate from native/runtime backups. V1 private state is never converted.
"""
import fcntl
import os
from pathlib import Path
import subprocess

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_joint_epoch import JointEpoch

FORMAT = 'RLD-REGIONAL-BFT-NODE-JOINT-ROLES-V1'
RULES = 'RLD-REGIONAL-BFT-JOINT-ROLES-FIXTURE-V1'
APPROVAL = 'RLD-JOINT-EPOCH-APPROVAL-V2'
MAX_CALLER = 8*1024*1024


def readonly_head():
    return dict(head=None, pending=None, outbox=None)


class RoleJoint:
    def __init__(self, runtime, config, current):
        from regional_bft_node import private
        self.r = runtime
        mesh.require(current['rules'] == RULES, 'role lifecycle requires explicitly signed native role admission')
        transitions = config['handoffs']
        mesh.require(isinstance(transitions, list) and 1 <= len(transitions) <= 16,
                     'role handoff configuration count')
        self.maps = [JointEpoch.peers(config['validators'])]
        mesh.require(list(self.maps[0]) == current['initial_keys'], 'role initial mapping differs from signed native admission')
        self.heights, self.slots = [], []
        self.directories, self.callers = [], []
        self.slots.append(self.slot(config['initial_slot'], 0))
        historical = set(self.maps[0])
        for n, item in enumerate(transitions, 1):
            mesh.require(set(item) == {'select_height', 'validators', 'slot'}, 'role handoff configuration fields')
            mesh.integer(item['select_height'], 1, 63)
            height = item['select_height']
            mesh.require(not self.heights or height > self.heights[-1], 'role selection heights must increase')
            peers = JointEpoch.peers(item['validators'])
            previous = self.maps[-1]
            mesh.require(peers != previous and set(peers)-set(previous)
                         and not (set(peers)-set(previous)) & historical,
                         'role configuration repeats membership or retired keys')
            mesh.require(all(previous[k] == peers[k] for k in set(previous)&set(peers)),
                         'continuing key must retain its explicit local carrier')
            self.maps.append(peers)
            self.heights.append(height)
            historical.update(peers)
            self.slots.append(self.slot(item['slot'], n))
        mesh.require(len(set(self.directories)) == len(self.directories), 'role native directories must remain separate')
        parents = [p.parent for p in self.callers]
        mesh.require(len(set(parents)) == len(parents), 'role caller directories must remain separate')
        for parent in parents:
            mesh.require(all(parent != p and p not in parent.parents
                             for p in [runtime.root, runtime.native.ledger, *self.directories]),
                         'role caller must survive every native/runtime backup')
            mesh.require(all(parent == p or (p not in parent.parents and parent not in p.parents) for p in parents),
                         'role caller directories cannot contain one another')
            fd = os.open(parent/'.bft-runtime.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
            runtime.extra_locks.append(fd)
            private(parent/'.bft-runtime.lock')
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        for n, slot in enumerate(self.slots):
            if slot is None:
                continue
            mesh.require(self.maps[n].get(slot['key']) == runtime.node_id, 'role slot differs from pinned local carrier')
            if n and slot['key'] in self.maps[n-1]:
                mesh.require(self.slots[n-1] is not None and self.slots[n-1]['key'] == slot['key'],
                             'continuing role slot needs its original configured custody')
        self.relay_peers = set(v for peers in self.maps for v in peers.values())
        self.active = None
        self.switch(self.current_index(current))

    def slot(self, config, number):
        from regional_bft_node import private
        if config is None:
            return None
        fields = {'key', 'key_file', 'signer_dir', 'head_file'}
        mesh.require(isinstance(config, dict) and set(config) == fields | ({'ready_dir', 'ready_head'} if number else set()),
                     'role local custody slot fields')
        slot = dict(key=mesh.hex32(config['key']), key_file=private(config['key_file'], missing=True),
                    signer=private(config['signer_dir'], True, missing=number > 0),
                    head_path=private(config['head_file']))
        private(slot['head_path'].parent, True)
        self.directories.append(slot['signer'])
        self.callers.append(slot['head_path'])
        binding = dict(currency=self.r.native.currency, region=self.r.region, key=slot['key'])
        self.r.load_head(slot['head_path'], binding, allow_initialization=number > 0)
        if number:
            slot.update(ready_dir=private(config['ready_dir'], True, missing=True),
                        ready_path=private(config['ready_head']))
            private(slot['ready_path'].parent, True)
            self.directories.append(slot['ready_dir'])
            self.callers.append(slot['ready_path'])
            slot['ready_binding'] = dict(binding, role='New', number=number)
            self.load_ready(slot)
        return slot

    def load_ready(self, slot):
        value = mesh.load(slot['ready_path'], MAX_CALLER)
        fields = {'format', 'binding', 'head', 'scope', 'native_binding', 'initialization', 'pending', 'outbox'}
        mesh.require(set(value) == fields and value['format'] == FORMAT and value['binding'] == slot['ready_binding'],
                     'role readiness caller binding differs')
        if value['head'] is not None:
            mesh.hex32(value['head'])
            mesh.require(value['scope'] is not None and value['native_binding'] is not None and value['initialization'] is None,
                         'retained readiness lacks exact native purpose')
        elif value['initialization'] is None:
            mesh.require(all(value[k] is None for k in ('scope', 'native_binding', 'pending', 'outbox')),
                         'uninitialized readiness has unbound response/state')
        else:
            mesh.require(value['scope'] is not None and value['native_binding'] is not None
                         and value['pending'] is None and value['outbox'] is None,
                         'readiness initialization has signing state')
        return value

    def save_ready(self, slot, value):
        mesh.require(not self.r.failed and len(wire.canonical(value)) <= MAX_CALLER, 'role readiness caller unavailable/capacity')
        try:
            mesh.atomic(slot['ready_path'], value)
        except BaseException:
            self.r.failed = True
            raise

    def current_index(self, current):
        for retained in current['epochs']:
            statement = retained['statement']
            number = statement['number']
            mesh.integer(number, 1, len(self.heights))
            mesh.require(statement['validators'] == list(self.maps[number])
                         and statement['closing_height'] == self.heights[number-1],
                         'retained native role chain escaped pinned configuration')
        proof = current['active_epoch_proof']
        n = 0 if proof is None else proof['statement']['number']
        mesh.integer(n, 0, len(self.heights))
        mesh.require(current['keys'] == list(self.maps[n]), 'native active keys escaped pinned role configuration')
        if n:
            s = proof['statement']
            mesh.require(s['currency'] == self.r.native.currency and s['region'] == self.r.region
                         and s['validators'] == list(self.maps[n]) and s['closing_height'] == self.heights[n-1]
                         and s['activation'] == 'RLD-BFT-JOINT-ROLES-V1', 'native activation differs from pinned role intent')
        return n

    def switch(self, n):
        self.active = n
        slot = self.slots[n]
        self.r.peers = self.maps[n]
        self.r.slot = None
        if slot is None:
            self.r.key = self.r.key_file = self.r.signer = self.r.head_path = None
            self.r.signing_binding = None
            self.r.head = readonly_head()
        else:
            for attr in ('key', 'key_file', 'signer', 'head_path'):
                setattr(self.r, attr, slot[attr])
            self.r.signing_binding = dict(currency=self.r.native.currency, region=self.r.region, key=slot['key'])
            self.r.head = self.r.load_head(slot['head_path'], self.r.signing_binding, allow_initialization=n > 0)

    def check_ready_marker(self, slot, value):
        marker = value['initialization']
        mesh.require(isinstance(marker, dict) and set(marker) == {'head', 'binding', 'creation', 'scope'}
                     and marker['scope'] == value['scope'] and marker['binding'] == value['native_binding'],
                     'readiness initialization purpose changed')
        mesh.hex32(marker['head'])
        binding = marker['binding']
        mesh.require(set(binding) == {'currency', 'region', 'key', 'role', 'statement'}
                     and all(binding[k] == slot['ready_binding'][k] for k in ('currency', 'region', 'key', 'role')),
                     'readiness initialization owner changed')
        mesh.hex32(binding['statement'])
        statement = marker['scope']['proposal']['statement']
        number = slot['ready_binding']['number']
        mesh.require(statement['number'] == number and statement['validators'] == list(self.maps[number])
                     and statement['closing_height'] == self.heights[number-1],
                     'readiness initialization escaped pinned plan')
        return marker

    def check_voter_marker(self, n, marker):
        mesh.require(isinstance(marker, dict) and set(marker) == {'head', 'binding', 'creation'}
                     and marker['binding'] == self.r.signing_binding,
                     'voter initialization owner changed')
        mesh.hex32(marker['head'])
        pin = marker['creation']['pin']
        mesh.require(pin['currency'] == self.r.native.currency and pin['region'] == self.r.region
                     and pin['height'] == self.heights[n-1], 'voter initialization escaped pinned boundary')
        return marker

    def ready_status(self, slot, value=None):
        value = self.load_ready(slot) if value is None else value
        if value['head'] is None:
            mesh.require(not slot['ready_dir'].exists() or value['initialization'] is not None,
                         'unanchored native readiness cannot be adopted')
            return None
        status = self.r.native.call('joint-ready-status', '--ready-dir', slot['ready_dir'])
        scope = dict(format=APPROVAL, **value['scope'], role='New',
                     approval=dict(key=slot['key'], signature=''))
        mesh.require(status['head'] == value['head'] and status['binding'] == value['native_binding'] and status['scope'] == scope,
                     'native readiness differs from separately retained purpose/head')
        return status

    def initialize_ready(self, slot, scope=None):
        value = self.load_ready(slot)
        if value['head'] is not None:
            if scope is not None:
                mesh.require(value['scope'] == scope, 'readiness cannot change selected purpose')
            return value
        marker = value['initialization']
        if marker is None:
            if scope is None or not slot['key_file'].exists():
                self.ready_status(slot, value)
                return value
            mesh.require(not slot['ready_dir'].exists(), 'readiness creation cannot adopt an existing directory')
            marker = self.r.with_json('joint-ready-init', scope, '--ready-dir', slot['ready_dir'], '--key', slot['key'], '--observe-only')
            value = dict(value, scope=scope, native_binding=marker['binding'], initialization=marker)
            self.save_ready(slot, value) # Preview/purpose is durable before native creation.
        marker = self.check_ready_marker(slot, value)
        if not slot['ready_dir'].exists():
            context = self.r.native.call('bft-context')['context']
            pin = marker['creation']['pin']
            if context['parent_height'] != pin['height'] or context['epoch'] != pin['epoch']:
                return value # Retained missing creation stays read-only after the boundary.
            preview = self.r.with_json('joint-ready-init', value['scope'], '--ready-dir', slot['ready_dir'], '--key', slot['key'], '--observe-only')
            mesh.require(preview == marker, 'readiness preview changed beneath pending initialization')
            self.r.with_json('joint-ready-init', value['scope'], '--ready-dir', slot['ready_dir'], '--key', slot['key'])
        recovered = self.r.with_json('joint-ready-recover-init', marker, '--ready-dir', slot['ready_dir'])
        mesh.require(recovered == marker, 'readiness recovered a different initialization')
        value = dict(value, head=marker['head'], initialization=None)
        self.save_ready(slot, value)
        self.ready_status(slot, value)
        return value

    def reconcile_ready(self, slot):
        value = self.initialize_ready(slot)
        if value['head'] is None:
            return
        if value['pending'] is not None:
            mesh.require(value['pending'] == value['scope'], 'pending readiness differs from retained purpose')
            try:
                result = self.r.native.call('joint-ready-sign', '--ready-dir', slot['ready_dir'], '--expected-head', value['head'], '--recover-only')
            except (OSError, ValueError, subprocess.TimeoutExpired):
                self.ready_status(slot, value) # Only an unchanged authenticated exact head may clear unsigned review.
                value = dict(value, pending=None)
            else:
                value = dict(value, head=result['head'], pending=None, outbox=result['approval'])
            self.save_ready(slot, value)
        if value['outbox'] is not None:
            self.r.retain(self.r.envelope({'EpochApproval': value['outbox']}), sync=False, local=True)
            value = dict(value, outbox=None)
            self.save_ready(slot, value)
        self.ready_status(slot, value)

    def voter_args(self, n, proof):
        slot = self.slots[n]
        ready = self.load_ready(slot)
        args = ['--signer-dir', slot['signer'], '--key', slot['key'], '--ready-dir', slot['ready_dir'], '--expected-ready-head', ready['head']]
        if slot['key'] in self.maps[n-1]:
            old = self.slots[n-1]
            binding = dict(currency=self.r.native.currency, region=self.r.region, key=old['key'])
            head = self.r.load_head(old['head_path'], binding, allow_initialization=n-1 > 0)
            mesh.require(head['head'] is not None and head['pending'] is None and head['outbox'] is None,
                         'continuing voter has unreconciled old caller custody')
            args += ['--old-signer-dir', old['signer'], '--expected-old-head', head['head']]
        return args

    def initialize_voter(self, n, current):
        slot = self.slots[n]
        if slot is None or not n or self.r.head['head'] is not None:
            return
        marker = self.r.head['initialization']
        if marker is None:
            mesh.require(not slot['signer'].exists(), 'unanchored role voter cannot be adopted')
            if not slot['key_file'].exists():
                return
            ready = self.ready_status(slot)
            proof = current['active_epoch_proof']
            if ready is None or not ready['approved'] or proof['statement']['closing_height'] != current['context']['parent_height']:
                return
            args = self.voter_args(n, proof)
            marker = self.r.with_json('joint-voter-init', proof, *args, '--observe-only')
            self.r.save_head(dict(self.r.head, initialization=marker))
        marker = self.check_voter_marker(n, marker)
        if not slot['signer'].exists():
            pin = marker['creation']['pin']
            if current['context']['parent_height'] != pin['height'] or current['context']['epoch'] != pin['epoch']:
                return
            proof = current['active_epoch_proof']
            args = self.voter_args(n, proof)
            preview = self.r.with_json('joint-voter-init', proof, *args, '--observe-only')
            mesh.require(preview == marker, 'voter preview changed beneath pending initialization')
            self.r.with_json('joint-voter-init', proof, *args)
        recovered = self.r.with_json('joint-voter-recover-init', marker, '--signer-dir', slot['signer'])
        mesh.require(recovered == marker, 'voter recovered a different initialization')
        self.r.save_head(dict(self.r.head, head=marker['head'], initialization=None))

    def advance(self, *, check_voter=True):
        current = self.r.native.call('bft-context')
        n = self.current_index(current)
        if n != self.active:
            if self.r.head['pending'] is not None:
                self.r.reconcile()
            self.r.flush_outbox()
            self.switch(n)
        self.initialize_voter(n, current)
        if self.r.head['pending'] is not None:
            self.r.reconcile()
        self.r.flush_outbox()
        if check_voter:
            self.r.signer_status()
        return current

    def startup(self):
        for n, slot in enumerate(self.slots):
            if slot is not None and n:
                self.reconcile_ready(slot)
            if slot is None:
                continue
            self.switch(n)
            if self.r.head['head'] is None:
                if self.r.head['initialization'] is not None and slot['signer'].exists():
                    marker = self.check_voter_marker(n, self.r.head['initialization'])
                    recovered = self.r.with_json('joint-voter-recover-init', marker, '--signer-dir', slot['signer'])
                    mesh.require(recovered == marker, 'startup voter initialization differs')
                    self.r.save_head(dict(self.r.head, head=marker['head'], initialization=None))
                else:
                    mesh.require(not slot['signer'].exists(), 'startup cannot adopt unanchored voter')
                    continue
            if self.r.head['pending'] is not None:
                self.r.reconcile()
            self.r.signer_status()
            self.r.flush_outbox()
        self.advance()

    def retained_directories(self):
        return [s['signer'] for s in self.slots if s is not None and s['signer'].exists()]

    def decorate(self, body):
        if 'Signed' in body:
            message = body['Signed']
            if 'EpochApproval' in message:
                receipt = message['EpochApproval']
                scope = self.r.native.call('bft-epoch-proposal', '--checkpoint', receipt['statement']['closing_checkpoint'])
                mesh.require(scope['proposal'] is not None and scope['proposal']['statement'] == receipt['statement'],
                             'old role response differs from exact native selection')
                return {'EpochApproval': dict(format=APPROVAL, **scope, role='Old', approval=receipt['approval'])}
            return {'EpochSigned': dict(message=message, epochs=self.r.native.call('bft-context')['epochs'])}
        return body

    def plan_command(self, context):
        n = self.active
        if n >= len(self.heights) or context['parent_height']+1 != self.heights[n]:
            return None
        return {'Reconfigure': dict(currency=context['currency'], region=context['region'], previous_epoch=context['epoch'],
                                   number=n+1, validators=list(self.maps[n+1]))}

    def tick(self):
        return self._tick(check_voter=True)

    def tick_for_native_loop(self):
        # Runtime immediately performs its ordinary fresh signer_status after
        # a false result. No observation is retained or reused across calls.
        return self._tick(check_voter=False)

    def _tick(self, *, check_voter):
        from regional_bft_node import private
        for slot in self.slots[1:]:
            if slot is not None:
                self.reconcile_ready(slot)
        current = self.advance(check_voter=check_voter)
        n = self.active
        if n >= len(self.heights):
            return False
        scope = self.r.native.call('bft-epoch-proposal')
        proposal = scope['proposal']
        if proposal is None:
            return False
        s = proposal['statement']
        if current['active_epoch_proof'] is not None and s == current['active_epoch_proof']['statement']:
            return False # The certified closing belongs to the already installed era, not another pending plan.
        mesh.require(s['number'] == n+1 and s['validators'] == list(self.maps[n+1])
                     and s['closing_height'] == self.heights[n], 'native selection escaped pinned role intent')
        if not check_voter:
            # A pending handoff may mutate custody before Runtime regains
            # control. Authenticate the actual head before that branch too.
            self.r.signer_status()
        if self.r.key_file is not None and self.r.key_file.exists() and self.r.head['head'] is not None:
            if self.r.signer_status()['state']['epoch_fence'] is None:
                self.r.sign({'EpochFence': dict(context=current['context'], **scope)})
        slot = self.slots[n+1]
        if slot is not None and slot['key_file'].exists():
            value = self.initialize_ready(slot, scope)
            status = self.ready_status(slot, value)
            if status is not None and not status['approved']:
                private(slot['key_file'])
                self.save_ready(slot, dict(value, pending=scope))
                result = self.r.native.call('joint-ready-sign', '--ready-dir', slot['ready_dir'],
                                          '--expected-head', value['head'], '--key-file', slot['key_file'])
                self.save_ready(slot, dict(value, head=result['head'], pending=None, outbox=result['approval']))
                self.reconcile_ready(slot)
        votes = {}
        for _, body, _, _ in self.r.state['messages'].bodies():
            vote = body.get('EpochApproval')
            if vote and vote['proposal']['statement'] == s:
                votes[vote['role'], vote['approval']['key']] = vote
        if sum(k[0] == 'Old' for k in votes) >= 3 and sum(k[0] == 'New' for k in votes) >= 3:
            proof = self.r.with_json('bft-epoch-combine', [votes[k] for k in sorted(votes)])
            self.r.retain(self.r.envelope({'EpochActivation': proof}), local=True)
            self.advance()
        return True
