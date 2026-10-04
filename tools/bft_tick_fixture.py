"""Exact public Runtime methods with fake native requests, never authorization.

No ledger, keys, old private fixtures, signature validation or native timing is
constructed. Counters describe this deterministic request sequence only.
"""
import ast
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from regional_bft_joint_epoch import JointEpoch, JointLoopStatus, FORMAT as JOINT_FORMAT

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT/'regional_bft_node.py'
VALUE = 'same-certified-snapshot-statement'
CONTEXT = dict(currency='fixture', region='earth', epoch='era-2', previous='parent-block',
               parent_height=10, parent_block='parent-block')
TRACES = {}


class BodyStore:
    def __init__(self): self.rows = []
    def bodies(self): return iter(self.rows)
    def __len__(self): return len(self.rows)
    def add(self, body, value=None):
        self.rows.append((str(len(self.rows)), body, value, False))


class Clock:
    def __init__(self): self.now = 1
    def monotonic(self): return self.now


def methods(source=SOURCE, clock_override=None):
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Runtime')
    names = {'tick', '_tick', 'signed', 'quorum', 'timeout_certificate', 'report', '_try_prepare'}
    extracted = ast.Module(body=[ast.ClassDef(name='ExactRuntime', bases=[], keywords=[],
        body=[n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names],
        decorator_list=[])], type_ignores=[])
    clock = Clock() if clock_override is None else clock_override
    def require(condition, text):
        if not condition: raise ValueError(text)
    scope = dict(mesh=SimpleNamespace(require=require, digest=lambda v: hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()),
                 time=clock, signed_body=lambda b: b.get('Signed', b.get('EpochSigned',{}).get('message',{})),
                 JOINT_FORMAT=JOINT_FORMAT, JointEpoch=JointEpoch, JointLoopStatus=JointLoopStatus)
    exec(compile(ast.fix_missing_locations(extracted), str(source), 'exec'), scope)
    return scope['ExactRuntime'], clock


ExactRuntime, clock = methods()


class Fixture(ExactRuntime):
    def __init__(self, round_number=0, prepared=None):
        clock.now = 1
        self.failed = False
        self.head = dict(head='separately-retained-fake-head', pending=None)
        self.native = SimpleNamespace(ledger=Path('/intentionally-absent-fake-native-ledger'), currency='fixture')
        self.format, self.region = 'fixture', 'earth'
        self.joint = SimpleNamespace(tick=lambda: False, active=2)
        self.key = 'key-3'
        self.key_file = SimpleNamespace(exists=lambda: True)
        self.peers = dict.fromkeys(['key-0', 'key-1', 'key-2', 'key-3'])
        self.block_interval, self.round_timeout, self.stop_height = 1, 20, 11
        self.messages = BodyStore()
        self.state = dict(messages=self.messages, height=10)
        self.native_state = dict(context=copy.deepcopy(CONTEXT), round=round_number,
                                 prepared=prepared, committed=None, proposed=False)
        self.native_records = 0
        self.slot = (hashlib.sha256(json.dumps(CONTEXT,sort_keys=True).encode()).hexdigest(), round_number)
        self.entered_at = 0
        self.requests, self.counts, self.scans, self.qc_calls = [], Counter(), Counter(), []

    def observe(self):
        self.counts['bft-context'] += 1
        return copy.deepcopy(CONTEXT)

    def signer_status(self):
        self.counts['bft-status'] += 1
        return dict(state=copy.deepcopy(self.native_state), records=self.native_records)

    def flush_outbox(self): pass
    def broadcast(self): self.counts['broadcast'] += 1

    def signed(self, context, round_number, kind, phase=None, value=None):
        self.scans[(kind,phase)] += 1
        return super().signed(context, round_number, kind, phase, value)

    def with_json(self, action, payload):
        self.counts[action] += 1
        if action == 'bft-quorum':
            first = payload[0]
            self.qc_calls.append(dict(round=first['round'], phase=first['phase'], value=first['value'], signers=len(payload)))
            return dict(round=first['round'], phase=first['phase'], value=first['value'], votes=payload)
        if action == 'bft-timeout-certificate': return dict(votes=payload)
        raise AssertionError('unexpected fake native action: '+action)

    def sign(self, request):
        kind, payload = next(iter(request.items()))
        n = payload['round'] if kind == 'Timeout' else payload['proposal']['round'] if kind == 'Commit' else payload['round']
        self.requests.append(dict(kind=kind, round=n))
        self.counts['bft-sign:'+kind] += 1
        # These state effects match the public native bft.rs phase transitions,
        # but this model performs no validation and grants no signature rights.
        if kind == 'Prepare':
            if n < self.native_state['round']: raise ValueError('fake old round')
            if n == self.native_state['round'] and self.native_state['prepared'] is not None:
                raise ValueError('fake already prepared')
            self.native_state.update(round=n, prepared=VALUE, committed=None, proposed=False)
        elif kind == 'Commit':
            if n != self.native_state['round'] or self.native_state['prepared'] != VALUE:
                raise ValueError('fake commit lacks own current prepare')
            self.native_state['committed'] = VALUE
        elif kind == 'Timeout':
            if n != self.native_state['round']: raise ValueError('fake timeout old round')
            self.native_state.update(round=n+1, prepared=None, committed=None, proposed=False)
        else: raise AssertionError(kind)
        self.native_records += 1
        self.entered_at = clock.now

    def proposal(self, round_number, variants=1):
        statement = dict(currency='fixture', region='earth', epoch='era-2', previous='parent-block', height=11)
        p = dict(round=round_number, snapshot=dict(statement=statement), timeout='fake-already-verified', leader='fake')
        for variant in range(variants):
            # Distinct complete body bytes, identical native Proposal/snapshot.
            self.messages.add(dict(EpochSigned=dict(message=dict(Proposal=copy.deepcopy(p)), epochs=[dict(variant=variant)])), VALUE)

    def votes(self, round_number, phase, count):
        for n in range(count):
            self.messages.add(dict(EpochSigned=dict(message=dict(Vote=dict(context=copy.deepcopy(CONTEXT),
                round=round_number, phase=phase, value=VALUE, approval=dict(key='key-'+str(n)))), epochs=[])), VALUE)

    def capture(self, name, observations):
        TRACES[name] = dict(requests=self.requests, native_command_counts=dict(self.counts),
            body_scan_counts={str(k):v for k,v in self.scans.items()}, quorum_request_rows=self.qc_calls,
            status_after=copy.deepcopy(self.native_state), records_after=self.native_records, observations=observations)
