"""Small native two-handoff receive fixture; no ordinary full-cycle claim.

Setup carries native consensus/activation certificates explicitly. The target
then cold-opens an ordinary Service and performs real bounded mesh/native receive.
All keys/value are fresh no-value fixture inputs; no failed fixture is opened.
"""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_contact_node import Service
from regional_contact_campaign import public
import test_regional_bft_joint_roles_lifecycle as lifecycle

BINARY=lifecycle.BINARY


class SecondRoleReceiveTests(unittest.TestCase):
    setUp = lifecycle.RoleLifecycleTests.setUp
    tearDown = lifecycle.RoleLifecycleTests.tearDown
    open = lifecycle.RoleLifecycleTests.open
    close = lifecycle.RoleLifecycleTests.close
    slot = lifecycle.RoleLifecycleTests.slot
    activation = lifecycle.RoleLifecycleTests.activation
    def checkpoint_current(self, commands=()):
        runtime = self.runtimes[2]
        context = runtime.native.call('bft-context')['context']
        active = {r.key: r for r in self.runtimes.values() if r.key is not None}
        keys = runtime.native.call('bft-context')['keys']
        leader = active[keys[context['parent_height'] % 4]]
        candidate = runtime.with_json('bft-candidate', list(commands), '--miner', public(10))

        def sign(r, request, kind):
            r.sign(request)
            retained = r.native.call('bft-retained-messages', '--signer-dir', r.signer)
            return next(m[kind] for m in reversed(retained) if kind in m)

        proposal = sign(leader, {'Propose': dict(round=0, snapshot=candidate, timeout=None)}, 'Proposal')
        prepared = runtime.with_json('bft-quorum', sorted(
            [sign(active[k], {'Prepare': proposal}, 'Vote') for k in keys],
            key=lambda v: v['approval']['key']))
        committed = runtime.with_json('bft-quorum', sorted(
            [sign(active[k], {'Commit': dict(proposal=proposal, prepared=prepared)}, 'Vote') for k in keys],
            key=lambda v: v['approval']['key']))
        certificate = runtime.with_json('bft-certify', dict(proposal=proposal, prepared=prepared, committed=committed))
        for r in self.runtimes.values():
            r.with_json('finalize', certificate)
            r.observe()
        return certificate

    def second_activation(self):
        self.activation()
        self.open(4)
        for r in self.runtimes.values():
            r.joint.advance()
        self.checkpoint_current()
        runtime = self.runtimes[2]
        context = runtime.native.call('bft-context')['context']
        plan = runtime.joint.plan_command(context)
        self.assertIsNotNone(plan)
        self.checkpoint_current([plan])
        scope = runtime.native.call('bft-epoch-proposal')
        self.assertEqual(scope['proposal']['statement']['number'], 2)
        for r in self.runtimes.values():
            self.assertTrue(r.joint.tick())
        proof = copy.deepcopy(scope['proposal'])
        for n in (0, 2, 3):
            r = self.runtimes[n]
            old = r.native.call('bft-retained-messages', '--signer-dir', r.signer)
            proof['old_approvals'].append(next(m['EpochApproval']['approval'] for m in reversed(old) if 'EpochApproval' in m))
        for n in (0, 2, 3):
            slot = self.slot(n, 2)
            status = runtime.native.call('joint-ready-status', '--ready-dir', slot['ready_dir'])
            proof['new_approvals'].append(status['approval']['approval'])
        for collection in ('old_approvals', 'new_approvals'):
            proof[collection].sort(key=lambda a: a['key'])
        for r in self.runtimes.values():
            r.with_json('install-epoch', proof)
            r.joint.advance()
        for r in self.runtimes.values():
            self.assertEqual(r.native.call('bft-context')['active_epoch_proof']['statement']['number'], 2)
            self.assertEqual(r.joint.active, 2)

    def caller_inventory(self):
        paths = []
        for config in self.c.configs.values():
            if config['initial_slot']:
                paths.append(Path(config['initial_slot']['head_file']))
            for handoff in config['handoffs']:
                if handoff['slot']:
                    paths.extend(Path(handoff['slot'][key]) for key in ('head_file', 'ready_head'))
        return {str(p): p.read_bytes() for p in paths}

    def test_historical_installed_proof_skips_only_exact_bytes_after_full_envelope_check(self):
        self.second_activation()
        target=self.runtimes[2]
        observation=target.native.call('bft-installed-epochs')
        self.assertEqual([p['statement']['number'] for p in observation['proofs']],[1,2])
        self.assertEqual(observation['epoch'],target.native.call('bft-context')['context']['epoch'])
        historical=observation['proofs'][0]
        envelope=target.envelope({'EpochActivation':historical})
        before=self.caller_inventory()
        ledger=target.native.call('status')
        with patch.object(target,'with_json',wraps=target.with_json) as calls:
            target.retain(envelope)
        actions=[c.args[0] for c in calls.call_args_list]
        self.assertEqual(actions.count('bft-network-check'),1)
        self.assertNotIn('bft-epoch-activate',actions)
        self.assertEqual(self.caller_inventory(),before)
        self.assertEqual(target.native.call('status'),ledger)
        stored=target.state['messages'][mesh.digest(envelope['body'])]['envelope']
        bad=copy.deepcopy(envelope)
        # A later same-body envelope still needs every carried proof checked.
        signed=bad['evidence']['snapshots'][0]['snapshot']['bft']['committed']['votes'][0]['approval']
        signature=signed['signature']
        signed['signature']=('0' if signature[0]!='0' else '1')+signature[1:]
        with patch.object(target,'with_json',wraps=target.with_json) as calls:
            with self.assertRaises(ValueError):target.retain(bad)
        self.assertEqual([c.args[0] for c in calls.call_args_list],['bft-network-check'])
        self.assertEqual(target.state['messages'][mesh.digest(envelope['body'])]['envelope'],stored)
        self.assertEqual(self.caller_inventory(),before)
        self.assertEqual(target.native.call('status'),ledger)
        call=target.native.call
        for field in ('currency','region'):
            wrong=copy.deepcopy(observation);wrong[field]='f'*64
            def substitute(action,*args):
                return wrong if action=='bft-installed-epochs' else call(action,*args)
            with patch.object(target.native,'call',side_effect=substitute), patch.object(target,'with_json',wraps=target.with_json) as calls:
                with self.assertRaises(ValueError):target.retain(envelope)
            self.assertEqual([c.args[0] for c in calls.call_args_list],['bft-network-check'])
            self.assertEqual(self.caller_inventory(),before)
            self.assertEqual(call('status'),ledger)

    def test_cold_second_era_service_receives_new_votes_submission_and_proof_variants(self):
        self.second_activation()
        target = self.runtimes[2]
        context = target.native.call('bft-context')['context']
        for number in range(6):
            target.sign({'Timeout': dict(context=context, round=number)})
        old_payloads = [target.state['messages'].payload(i) for i in target.state['messages']][-8:]
        original = target.envelope({'Signed': target.native.call('bft-retained-messages', '--signer-dir', target.signer)[-1]})
        original_id = mesh.digest(original['body'])
        stored_original = target.state['messages'][original_id]['envelope']
        self.c.checkpoint('proxima')
        complete = target.native.call('proof')['snapshots'] + self.c.cli('proxima', 1, 'proof')['snapshots']
        changed = target.with_json('bft-network-pack', dict(original, evidence={'snapshots': complete}))
        self.assertNotEqual(wire.canonical(changed), wire.canonical(stored_original))
        self.assertEqual(changed['body'], stored_original['body'])
        bad = copy.deepcopy(changed)
        signature = bad['evidence']['snapshots'][-1]['snapshot']['bft']['committed']['votes'][0]['approval']['signature']
        bad['evidence']['snapshots'][-1]['snapshot']['bft']['committed']['votes'][0]['approval']['signature'] = ('0' if signature[0] != '0' else '1') + signature[1:]
        fresh = self.runtimes[4]
        fresh.sign({'Timeout': dict(context=context, round=0)})
        new_vote = fresh.envelope({'Signed': fresh.native.call('bft-retained-messages', '--signer-dir', fresh.signer)[-1]})
        self.assertIn('EpochSigned', new_vote['body'])

        wallet = self.c.root/'queue-wallet'
        initial = target.native.call('wallet-init', '--wallet-dir', wallet, '--owner', public(10))
        request = dict(owner=public(10), inputs=None, outputs=[dict(owner=public(14), amount='1')], remote=None, fee='1', valid_for_blocks=8)
        prepared = target.with_json('wallet-prepare', request, '--wallet-dir', wallet, '--expected-wallet-head', initial['wallet_head'])
        key = self.c.file('queue-owner-key', dict(secret_key=(bytes([10])*32).hex()))
        key.chmod(0o600)
        signed = target.with_json('wallet-sign', prepared, '--wallet-dir', wallet, '--expected-wallet-head', initial['wallet_head'], '--review', prepared['review_commitment'], '--key-file', key)
        before_ledger = target.native.call('status')
        target.with_json('bft-submit', signed['commands'])
        queue = target.native.ledger/'bft-submissions'
        submission = wire.decode_json(next(queue.iterdir()).read_bytes())
        self.assertIn('EpochSubmission', submission['body'])
        self.assertEqual(target.native.call('status'), before_ledger)
        heads = self.caller_inventory()

        # Ordinary non-BFT contact carriage is a malformed opaque export; it
        # must consume its fair background opportunity then fail native checks.
        ordinary = wire.make_frame('source-sync', self.c.regions['proxima'], target.region, 'f'*64, b'{"fixture_invalid_contact":true}')
        raw_packets = [*[wire.make_frame('regional-bft', target.region, target.region, hashlib.sha256(p).hexdigest(), p) for p in old_payloads],
                       *[wire.make_frame('regional-bft', target.region, target.region, hashlib.sha256(wire.canonical(e)).hexdigest(), wire.canonical(e)) for e in (new_vote, submission, changed, bad)], ordinary]
        source_root = self.c.root/'wave2-source-mesh'
        source_identity = mesh.initialize(source_root, self.c.currency, target.region, 'isolated-relay')
        source_config = dict(format=mesh.VERSION, state=str(source_root), network=self.c.currency, contacts=[])
        target_config = mesh.load(self.c.root/'mesh-config-2.json', 65536)
        source_id, target_id = source_identity['node_id'], self.c.node_ids[2]
        forward, backward = self.c.root/'wave2-forward', self.c.root/'wave2-backward'
        source_config = dict(source_config, contacts=[dict(peer=target_id, inbox=str(backward), outbox=str(forward))])
        target_config = dict(target_config, contacts=[dict(peer=source_id, inbox=str(forward), outbox=str(backward))])
        with mesh.Node(target_config) as node:
            advert = node.exchange(source_id)
        with mesh.Node(source_config) as node:
            node.receive(advert, target_id)
            for packet in raw_packets:
                node.enqueue(packet, target_id)
        for _ in range((len(raw_packets)+mesh.MAX_PACKET_BATCH-1)//mesh.MAX_PACKET_BATCH + 2):
            with mesh.Node(source_config) as node:
                bundle = node.exchange(target_id)
            with mesh.Node(target_config) as node:
                node.receive(bundle, source_id)
                reply = node.exchange(source_id)
            with mesh.Node(source_config) as node:
                node.receive(reply, target_id)
        with mesh.Node(target_config) as node:
            received_contents = {s['export_id'] for s in node.summaries().values() if s['destination'] == target_id}
        for label, envelope in [('vote', new_vote), ('submission', submission), ('valid-proof', changed), ('invalid-proof', bad)]:
            self.assertIn(hashlib.sha256(wire.canonical(envelope)).hexdigest(), received_contents, label)
        path = self.c.root/'bft-config-2.json'
        mesh.atomic(path, dict(self.c.configs[2], stop_height=3))
        self.close(2)
        service = Service(target.native, target_config, None, bft_config=path)
        self.addCleanup(service.close)
        self.assertEqual(service.bft.joint.active, 2)
        self.assertEqual(self.caller_inventory(), heads)
        rejected = []
        checked_payloads = []
        successful_payloads = []
        rejected_payloads = []
        ordinary_attempts = []
        receive = service.bft.receive_many
        def observe(raws):
            payloads = [wire.inspect_frame(raw)[1] for raw in raws]
            checked_payloads.extend(payloads)
            try:
                result = receive(raws)
            except ValueError:
                rejected_payloads.extend(payloads)
                raise
            successful_payloads.extend(payloads)
            return result
        apply = service.native.apply
        def observe_contact(raw, miner):
            ordinary_attempts.append(raw)
            return apply(raw, miner)
        with patch.object(service.bft, 'receive_many', side_effect=observe), patch.object(service.native, 'apply', side_effect=observe_contact):
            for _ in range(2*len(raw_packets)+4):
                rejected.extend(service.tick()['rejected'])
                if ordinary in ordinary_attempts and all(wire.canonical(e) in successful_payloads for e in (new_vote, submission, changed)) and wire.canonical(bad) in rejected_payloads:
                    break
        self.assertTrue(all(wire.canonical(e) in successful_payloads for e in (new_vote, submission, changed)))
        self.assertIn(wire.canonical(bad), rejected_payloads)
        self.assertIn(ordinary, ordinary_attempts)
        self.assertTrue(any('native rejected' in r['reason'] for r in rejected))
        self.assertEqual(service.bft.state['messages'][original_id]['envelope'], stored_original)
        self.assertTrue(service.bft.state['messages'].record(original_id)['local'])
        self.assertIn(mesh.digest(new_vote['body']), service.bft.state['messages'])
        self.assertIn(mesh.digest(submission['body']), service.bft.state['messages'])
        self.assertEqual(self.caller_inventory(), heads)
        after_ledger = target.native.call('status')
        for field in ('height', 'tip', 'state', 'ledger', 'finality', 'validator_epoch'):
            self.assertEqual(after_ledger[field], before_ledger[field], field)
        remote_statement = self.c.cli('proxima', 1, 'proof')['snapshots'][0]['statement']
        self.assertTrue(any(s['statement'] == remote_statement for s in target.native.call('proof')['snapshots']))
        report = service.tick()
        self.assertEqual(report['consensus']['height'], 3)
        self.assertEqual(report['consensus']['joint_active_slot'], 2)
        self.assertTrue(report['consensus']['explicit_stop_height_reached'])
        self.assertEqual(self.caller_inventory(), heads)


if __name__ == '__main__':
    unittest.main()
