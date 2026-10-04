"""Actual CLI role custody; controller-carried ground sample, not node autonomy."""
import copy
import os
from pathlib import Path
import tempfile
import unittest

from regional_bft_campaign import Campaign as BftCampaign
from regional_contact_campaign import public, seeds

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class Campaign(BftCampaign):
    def invoke(self, command, success=True, helper=False):
        command = list(command)
        if helper and command[-2:] == ['bootstrap', '--bft']:
            command[-1] = '--bft-joint-roles'
        return super().invoke(command, success, helper)

    def signer(self, name, n):
        if name == 'earth' and hasattr(self, 'role_voters'):
            return self.role_voters[n]
        return super().signer(name, n)

    def sign(self, name, n, request, success=True, recover=False, expected=None):
        if name != 'earth' or not hasattr(self, 'role_voters'):
            return super().sign(name, n, request, success, recover, expected)
        args = ['bft-sign', '--file', self.file('vote-request', request), '--signer-dir', self.signer(name, n),
                '--expected-head', expected or self.heads[name, n]]
        if recover:
            args += ['--recover-only']
        else:
            args += ['--key-file', self.role_keys[n]]
        result = self.cli(name, n, *args, success=success)
        if success:
            self.heads[name, n] = result['head']
            self.save_heads()
        return result


class RoleCustodyTests(unittest.TestCase):
    def test_real_cli_roles_readiness_rollover_new_consensus_and_unchanged_old_custody(self):
        with tempfile.TemporaryDirectory(prefix='rld-role-cli-') as temp:
            c = Campaign(BINARY, Path(temp).resolve()/'fixture')
            old_seeds = seeds('earth')
            successor = sorted([*old_seeds[1:], 62], key=public)
            context = c.cli('earth', 1, 'bft-context')['context']
            plan = dict(currency=c.currency, region=c.regions['earth'], previous_epoch=context['epoch'],
                        number=1, validators=[public(s) for s in successor])
            closing = c.checkpoint('earth', [{'Reconfigure': plan}])
            # Fresh joining carrier catches up without old signing participation.
            c.cli('earth', 0, 'finalize', '--file', c.file('joining-closing', closing))
            scope = c.cli('earth', 1, 'bft-epoch-proposal')
            proof = copy.deepcopy(scope['proposal'])
            for n in (1, 2, 3):
                context = c.cli('earth', n, 'bft-context')['context']
                result = c.sign('earth', n, {'EpochFence': dict(context=context, **scope)})
                proof['old_approvals'].append(result['message']['EpochApproval']['approval'])
            readies, ready_heads, keyfiles = {}, {}, {}
            scope_file = c.file('ready-scope', scope)
            fresh_key = c.file('joining-key', {'secret_key': (bytes([62])*32).hex()})
            fresh_key.chmod(0o600)
            for seed in successor:
                keyfile = fresh_key if seed == 62 else c.root/f'earth-{old_seeds.index(seed)}-key.json'
                ready = c.root/f'ready-{seed}'
                initialized = c.cli('earth', 1, 'joint-ready-init', '--ready-dir', ready, '--key', public(seed), '--file', scope_file)
                unsigned = c.cli('earth', 1, 'joint-ready-sign', '--ready-dir', ready, '--expected-head', initialized['head'], '--recover-only', success=False)
                self.assertIn('cannot first-sign', unsigned['reason'])
                signed = c.cli('earth', 1, 'joint-ready-sign', '--ready-dir', ready, '--expected-head', initialized['head'], '--key-file', keyfile)
                recovered = c.cli('earth', 1, 'joint-ready-sign', '--ready-dir', ready, '--expected-head', initialized['head'], '--key-file', '/absent-private-key', '--recover-only')
                self.assertEqual(signed['approval'], recovered['approval'])
                self.assertEqual(signed['head'], recovered['head'])
                self.assertTrue(recovered['recovered_exact_retry'])
                readies[seed], ready_heads[seed], keyfiles[seed] = ready, signed['head'], keyfile
                proof['new_approvals'].append(signed['approval']['approval'])
            proof['old_approvals'].sort(key=lambda a: a['key'])
            proof['new_approvals'] = sorted(proof['new_approvals'], key=lambda a: a['key'])[:3]
            proof_file = c.file('activation', proof)
            for n in range(4):
                c.cli('earth', n, 'install-epoch', '--file', proof_file)
            old_dirs = [c.root/f'earth-{n}-signer' for n in range(4)]
            old_head_file = c.file('retained-old-role-heads', {str(n): c.heads['earth', n] for n in range(4)})
            old_head_file.chmod(0o600)
            def old_inventory():
                return {str(p.relative_to(c.root)): (p.read_bytes(), p.stat().st_uid, p.stat().st_mode, p.stat().st_nlink)
                        for p in [old_head_file, *[p for directory in old_dirs for p in directory.rglob('*') if p.is_file()]]}
            original = old_inventory()
            original_heads = dict(c.heads)
            voters, voter_keys = [], []
            for n, seed in enumerate(successor):
                target = c.root/f'new-voter-{n}'
                args = ['joint-voter-init', '--signer-dir', target, '--key', public(seed),
                        '--ready-dir', readies[seed], '--expected-ready-head', ready_heads[seed], '--file', proof_file]
                if seed in old_seeds:
                    old_n = old_seeds.index(seed)
                    denied = c.cli('earth', n, *args, success=False)
                    self.assertIn('original old journal', denied['reason'])
                    self.assertFalse(target.exists())
                    args += ['--old-signer-dir', old_dirs[old_n], '--expected-old-head', original_heads['earth', old_n]]
                result = c.cli('earth', n, *args)
                c.heads['earth', n] = result['head']
                voters.append(target)
                voter_keys.append(keyfiles[seed])
            # Separate original heads are needed during creation even when slots reorder.
            self.assertEqual(old_inventory(), original)
            c.role_voters, c.role_keys = voters, voter_keys
            terminal = c.checkpoint('earth', online=(0, 1, 2, 3))
            self.assertEqual(terminal['statement']['height'], 2)
            self.assertNotEqual(terminal['statement']['epoch'], closing['statement']['epoch'])
            for n in range(4):
                status = c.cli('earth', n, 'bft-status', '--signer-dir', voters[n])
                self.assertEqual(status['head'], c.heads['earth', n])
                self.assertEqual(status['creation']['pin']['epoch'], terminal['statement']['epoch'])
            self.assertEqual(old_inventory(), original)


if __name__ == '__main__':
    unittest.main()
