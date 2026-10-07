"""Startup contention, exact refusals and unchanged live/custody semantics."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import Runtime, FORMAT
from regional_contact_campaign import public, seeds
from regional_contact_node import Native, Service, startup_config
from regional_native_startup import (
    Inspection, LOCK_REFUSAL, MAX_CONTENTION_SECONDS, MAX_LOCK_REFUSALS,
)


class Clock:
    def __init__(self): self.now = 0.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


class ScriptNative:
    def __init__(self, results): self.results, self.calls = list(results), []
    def call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        value = self.results.pop(0)
        if isinstance(value, Exception): raise value
        return value


class BudgetTests(unittest.TestCase):
    def test_exact_read_lock_refusal_retries_same_complete_request(self):
        native = ScriptNative([ValueError(LOCK_REFUSAL), {'verified': True}])
        clock = Clock()
        inspection = Inspection(native, clock)
        result = inspection.call('bft-network-check', '--file', 'unchanged.json')
        self.assertEqual(result, {'verified': True})
        self.assertEqual(native.calls[0], native.calls[1])
        self.assertEqual(inspection.lock_refusals, 1)
        self.assertGreater(inspection.contention_seconds, 0)

    def test_explicit_startup_plan_and_empty_history_keep_same_shared_lock_budget(self):
        for request in (('bft-network-check-plan','--file','complete-plan.json','--expected-head','7'*64),
                        ('history-check','--expected-head','7'*64)):
            native=ScriptNative([ValueError(LOCK_REFUSAL),{'verified':True}])
            inspection=Inspection(native,Clock())
            self.assertEqual(inspection.call(*request),{'verified':True})
            self.assertEqual(native.calls,[ (request,{}), (request,{}) ])
            native=ScriptNative([ValueError(LOCK_REFUSAL)]*200)
            inspection=Inspection(native,Clock())
            with self.assertRaises(ValueError):inspection.call(*request)
            self.assertAlmostEqual(inspection.contention_seconds,MAX_CONTENTION_SECONDS)
            self.assertLessEqual(inspection.lock_refusals,MAX_LOCK_REFUSALS)
            native=ScriptNative([ValueError('invalid pinned complete proof'),'must not run'])
            with self.assertRaisesRegex(ValueError,'invalid pinned'):Inspection(native,Clock()).call(*request)
            self.assertEqual(len(native.calls),1)

    def test_mutating_and_recovery_commands_never_retry(self):
        requests = [
            ('bft-sign',), ('bft-sign', '--recover-only'), ('bft-init',),
            ('bft-sync',), ('finalize',), ('joint-ready-recover-init',),
            ('channel-owner-sign',), ('channel-owner-recover',),
            ('history-restore',), ('bft-epoch-activate',),
        ]
        for request in requests:
            with self.subTest(request=request):
                native = ScriptNative([ValueError(LOCK_REFUSAL), 'must not run'])
                with self.assertRaisesRegex(ValueError, 'operation would block'):
                    Inspection(native, Clock()).call(*request)
                self.assertEqual(len(native.calls), 1)

    def test_other_errors_and_altered_error_text_fail_immediately(self):
        for error in [ValueError('invalid signature'), ValueError('RESTORING'),
                      ValueError(LOCK_REFUSAL + ' changed'), OSError('unsafe file')]:
            with self.subTest(error=error):
                native = ScriptNative([error, 'must not run'])
                with self.assertRaises(type(error)):
                    Inspection(native, Clock()).call('contact-status')
                self.assertEqual(len(native.calls), 1)

    def test_constructor_budget_shared_across_reads_without_fake_success(self):
        native = ScriptNative([ValueError(LOCK_REFUSAL), 'authenticated first']
                              + [ValueError(LOCK_REFUSAL)] * 200)
        inspection = Inspection(native, Clock())
        self.assertEqual(inspection.call('contact-status'), 'authenticated first')
        with self.assertRaisesRegex(ValueError, 'operation would block'):
            inspection.call('proof')
        self.assertAlmostEqual(inspection.contention_seconds, MAX_CONTENTION_SECONDS)
        self.assertLessEqual(inspection.lock_refusals, MAX_LOCK_REFUSALS)

    def test_refusal_count_bounds_a_clock_that_does_not_advance(self):
        clock = Clock()
        clock.sleep = lambda _: None
        native = ScriptNative([ValueError(LOCK_REFUSAL)] * 200)
        inspection = Inspection(native, clock)
        with self.assertRaisesRegex(ValueError, 'operation would block'):
            inspection.call('bft-context')
        self.assertEqual(len(native.calls), MAX_LOCK_REFUSALS)


BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(
    Path(__file__).resolve().parent / 'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class NativeStartupTests(unittest.TestCase):
    def setUp(self):
        # Retain exact native fixtures even on failure. The scope runner supplies
        # a private destination; this is never a public artifact directory.
        base = os.environ.get('RLD_STARTUP_FIXTURE_ROOT')
        if base:
            self.root = Path(base) / self._testMethodName
            self.root.mkdir(mode=0o700)
        else:
            self.root = Path(tempfile.mkdtemp(prefix='rld-native-startup-')).resolve()
        helper = BINARY.with_name('contact-fixture')
        result = subprocess.run([str(helper), 'bootstrap', '--bft'],
                                capture_output=True, timeout=30, check=True)
        bootstrap = wire.decode_json(result.stdout)
        path = self.root / 'bootstrap.json'
        path.write_bytes(wire.canonical(bootstrap))
        self.pin = bootstrap['currency']['implementation']  # diagnostic only
        self.currency = bootstrap['admissions'][0]['currency']
        self.native = Native(BINARY, self.root/'ledger', public(1), self.currency)
        self.region = self.native.call('init', '--bootstrap', path, '--region', 'earth')['region']
        self.held = self.timer = self.runtime = self.service = None

    def tearDown(self):
        if self.timer: self.timer.join(5)
        self.release()
        if self.runtime: self.runtime.close()
        if self.service: self.service.close()

    def hold(self, release_after=None):
        self.held = os.open(self.native.ledger/'LOCK', os.O_RDWR)
        fcntl.flock(self.held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if release_after is not None:
            self.timer = threading.Timer(release_after, self.release)
            self.timer.start()

    def release(self):
        if self.held is not None:
            descriptor, self.held = self.held, None
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def config(self, n=0):
        state = self.root/f'mesh-{n}'
        identity = mesh.initialize(state, self.currency, self.region, 'startup-test')
        return dict(format=mesh.VERSION, state=str(state), network=self.currency, contacts=[]), identity['node_id']

    def test_default_startup_waits_for_real_lock_then_initializes_identity(self):
        head = self.native.call('history-head')['history_head']
        self.hold(.15)
        config = startup_config(self.native)
        self.assertTrue((self.native.ledger/'transport/config.json').exists())
        self.assertEqual(config['network'], self.currency)
        self.assertEqual(self.native.call('history-head')['history_head'], head)

    def test_persistent_lock_times_out_without_creating_transport(self):
        self.hold()
        with self.assertRaisesRegex(ValueError, 'operation would block'):
            startup_config(self.native)
        self.assertFalse((self.native.ledger/'transport').exists())

    def test_service_constructor_waits_but_live_native_remains_unwrapped(self):
        config, _ = self.config()
        self.hold(.15)
        self.service = Service(self.native, config, None, parallel_carriage=False)
        self.assertIs(self.service.native, self.native)
        self.hold()
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'operation would block'):
            self.service.native.call('contact-status')
        self.assertLess(time.monotonic() - started, 1)

    def test_runtime_constructor_waits_preserves_head_and_live_refuses_lock(self):
        transport, node_id = self.config()
        validators = seeds('earth')
        peers = [node_id] + [self.config(n)[1] for n in range(1, 4)]
        signer = self.root/'voter'
        head = self.native.call('bft-init', '--signer-dir', signer, '--key', public(validators[0]))['head']
        caller = self.root/'caller'
        caller.mkdir(mode=0o700)
        retained = dict(format=FORMAT, binding=dict(currency=self.currency, region=self.region,
            key=public(validators[0])), head=head, pending=None, outbox=None)
        mesh.atomic(caller/'head.json', retained)
        config = dict(format=FORMAT, state=str(self.root/'runtime'), signer_dir=str(signer),
            head_file=str(caller/'head.json'), key_file=str(self.root/'absent-key.json'),
            key=public(validators[0]), miner=public(10),
            validators=[dict(key=public(seed), node_id=peers[n]) for n,seed in enumerate(validators)],
            block_interval=1, round_timeout=60, stop_height=24)
        path = self.root/'bft-config.json'
        mesh.atomic(path, config)
        self.hold(.15)
        self.runtime = Runtime(self.native, transport, path)
        self.assertIs(self.runtime.native, self.native)
        self.assertEqual(mesh.load(caller/'head.json', 8192), retained)
        self.assertEqual(self.runtime.signer_status()['records'], 0)
        self.hold()
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'operation would block'):
            self.runtime.observe()
        self.assertLess(time.monotonic() - started, 1)


if __name__ == '__main__': unittest.main()
