#!/usr/bin/env python3
"""Actual native CLI processes for the explicitly admitted no-value BFT profile.

Four separate replica stores and signer journals per region. The controller is
a ground message bus, not a qualified pacemaker or independent operator set.
Only public fixture keys are used. Private directories never enter the report.
"""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess

from regional_contact_campaign import public, seeds, save

NAMES = ('earth', 'proxima', 'andromeda')


def require(value, reason):
    if not value:
        raise ValueError(reason)


class Campaign:
    def __init__(self, binary, root):
        self.binary = Path(binary).resolve()
        self.helper = self.binary.with_name('contact-fixture')
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700)
        self.calls = self.helper_calls = self.rejections = 0
        self.heads, self.regions, self.certificates, self.checks = {}, {}, {}, []
        self.earth_forbidden = False
        self.offline_earth = None
        bootstrap = self.invoke([self.helper, 'bootstrap', '--bft'], helper=True)
        self.currency = bootstrap['admissions'][0]['currency']
        self.implementation = bootstrap['currency']['implementation']
        self.bootstrap = self.file('bootstrap', bootstrap)
        for name in NAMES:
            self.certificates[name] = []
            for n, seed in enumerate(seeds(name)):
                initialized = self.cli(name, n, 'init', '--bootstrap', self.bootstrap, '--region', name)
                self.regions[name] = initialized['region']
                key = self.root/f'{name}-{n}-key.json'
                save(key, {'secret_key': (bytes([seed])*32).hex()})
                key.chmod(0o600)
                result = self.cli(name, n, 'bft-init', '--signer-dir', self.signer(name, n), '--key', public(seed))
                self.heads[name, n] = result['head']
        self.save_heads()

    def file(self, name, value):
        path = self.root/(name+'.json')
        save(path, value)
        return path

    def node(self, name, n=1):
        return self.root/f'{name}-{n}'

    def signer(self, name, n):
        return self.root/f'{name}-{n}-signer'

    def save_heads(self):
        self.file('caller-retained-heads', {f'{name}-{n}': h for (name, n), h in self.heads.items()})

    def invoke(self, command, success=True, helper=False):
        if helper:
            self.helper_calls += 1
        else:
            self.calls += 1
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=30, check=False)
        require((result.returncode == 0) == success, 'native BFT CLI result differs: '+result.stderr.decode(errors='replace')[:1024])
        if not success:
            self.rejections += 1
            return {'rejected': True, 'reason': result.stderr.decode(errors='replace')}
        return json.loads(result.stdout)

    def cli(self, name, n, *args, success=True):
        require(not (name == 'earth' and self.earth_forbidden), 'Earth was queried during remote-only execution')
        return self.invoke([self.binary, '--dir', self.node(name, n), '--authority', public(1),
                            '--currency', self.currency, *args], success=success)

    def sign(self, name, n, request, success=True, recover=False, expected=None):
        path = self.file('vote-request', request)
        args = ['bft-sign', '--file', path, '--signer-dir', self.signer(name, n),
                '--expected-head', expected or self.heads[name, n]]
        if recover:
            args.append('--recover-only')
        else:
            args.extend(['--key-file', self.root/f'{name}-{n}-key.json'])
        result = self.cli(name, n, *args, success=success)
        if success:
            self.heads[name, n] = result['head']
            self.save_heads()
        return result

    def combine(self, name, votes, timeout=False, success=True):
        ordered = sorted(votes, key=lambda v: v['approval']['key'])
        path = self.file('votes', ordered)
        return self.cli(name, 1, 'bft-timeout-certificate' if timeout else 'bft-quorum', '--file', path, success=success)

    def checkpoint(self, name, commands=(), miner=10, online=(1, 2, 3), guard=False):
        context = self.cli(name, 1, 'bft-context')['context']
        candidate = self.cli(name, 1, 'bft-candidate', '--miner', public(miner),
                             '--commands', self.file('commands', list(commands)))
        round_number = 0
        timeout = None
        leader = context['parent_height'] % 4
        if leader not in online:
            votes = [self.sign(name, n, {'Timeout': {'context': context, 'round': 0}})['message']['Timeout'] for n in online]
            timeout = self.combine(name, votes, timeout=True)
            round_number, leader = 1, (leader+1) % 4
        request = {'Propose': {'round': round_number, 'snapshot': candidate, 'timeout': timeout}}
        if guard:
            before = self.heads[name, leader]
            self.sign(name, leader, request, recover=True, success=False)
            require(self.heads[name, leader] == before, 'recovery first-signed')
        proposed = self.sign(name, leader, request)
        proposal = proposed['message']['Proposal']
        if guard:
            recovered = self.sign(name, leader, request, recover=True)
            require(recovered['recovered_exact_retry'] and recovered['message'] == proposed['message'], 'exact response recovery differs')
        prepared_votes = [self.sign(name, n, {'Prepare': proposal})['message']['Vote'] for n in online]
        if guard:
            self.combine(name, prepared_votes[:2], success=False)
            self.combine(name, [prepared_votes[0], prepared_votes[0], prepared_votes[1]], success=False)
        prepared = self.combine(name, prepared_votes)
        commit_request = {'Commit': {'proposal': proposal, 'prepared': prepared}}
        committed_votes = [self.sign(name, n, commit_request)['message']['Vote'] for n in online]
        committed = self.combine(name, committed_votes)
        path = self.file('certificate-input', {'proposal': proposal, 'prepared': prepared, 'committed': committed})
        certificate = self.cli(name, 1, 'bft-certify', '--file', path)
        if guard:
            invalid = copy.deepcopy(certificate)
            invalid['bft']['committed']['votes'].pop()
            journal = (self.node(name, 1)/'journal.json').read_bytes()
            self.cli(name, 1, 'finalize', '--file', self.file('invalid-certificate', invalid), success=False)
            require((self.node(name, 1)/'journal.json').read_bytes() == journal, 'minority certificate changed native ledger')
        path = self.file('certified-block', certificate)
        for n in online:
            self.cli(name, n, 'finalize', '--file', path)
            journal = (self.node(name, n)/'journal.json').read_bytes()
            self.cli(name, n, 'finalize', '--file', path)
            require((self.node(name, n)/'journal.json').read_bytes() == journal, 'certificate retry duplicated effects')
        self.certificates[name].append(certificate)
        self.same_replicas(name, online)
        self.audit(name+': certified height '+str(certificate['statement']['height']))
        return certificate

    def same_replicas(self, name, indices):
        # Each status is an independent new native process and full journal replay.
        states = [self.cli(name, n, 'status') for n in indices]
        fields = ('height', 'tip', 'state', 'ledger', 'finality', 'validator_epoch')
        for state in states[1:]:
            require(all(state[f] == states[0][f] for f in fields), 'replicas disagree after complete native replay')

    def audit(self, phase):
        ledgers = [self.offline_earth if name == 'earth' and self.earth_forbidden
                   else self.cli(name, 1, 'status')['ledger'] for name in NAMES]
        issued = sum(int(l['minted']) for l in ledgers)
        liquid = sum(int(c['payment']['amount']) for l in ledgers for c in l['coins'].values())
        transit = sum(int(e['recipient']['amount']) for l in ledgers for e in l['exports'].values()) - sum(int(l['received']) for l in ledgers)
        require(issued == liquid+transit and transit >= 0, 'canonical-region conservation failed')
        self.checks.append({'phase': phase, 'issued': str(issued), 'liquid': str(liquid), 'pending_exports': str(transit), 'conserved': True})

    def wallet_payment(self, name, owner, destination, recipient, gross, destination_fee):
        wallet = self.root/f'{name}-owner-{owner}'
        initialized = self.cli(name, 1, 'wallet-init', '--wallet-dir', wallet, '--owner', public(owner))
        request = {'owner': public(owner), 'inputs': None, 'outputs': [], 'fee': '1', 'valid_for_blocks': 8,
                   'remote': {'destination': self.regions[destination], 'recipient': {'owner': public(recipient), 'amount': str(gross)},
                              'destination_fee': str(destination_fee)}}
        draft = self.cli(name, 1, 'wallet-prepare', '--wallet-dir', wallet, '--expected-wallet-head', initialized['wallet_head'],
                         '--file', self.file('wallet-request', request))
        key = self.file('fixture-owner-key', {'secret_key': (bytes([owner])*32).hex()})
        key.chmod(0o600)
        signed = self.cli(name, 1, 'wallet-sign', '--wallet-dir', wallet, '--expected-wallet-head', draft['wallet_head'],
                          '--file', self.file('reviewed-wallet', draft), '--review', draft['review_commitment'], '--key-file', key)
        self.checkpoint(name, signed['commands'])
        frame = self.cli(name, 1, 'contact-export', '--export', draft['draft']['intent_id'])
        return frame, {'currency': self.currency, 'source': self.regions[name], 'destination': self.regions[destination],
                       'export': draft['draft']['intent_id'], 'recipient': public(recipient), 'net_amount': str(gross-destination_fee)}

    def receive(self, name, frame, expected):
        path = self.file('carried-frame', frame)
        for n in (1, 2, 3):
            pending = self.cli(name, n, 'contact-apply', '--file', path)
            require(not pending['import_accepted'], 'transport alone authorized import')
        receipt_path = self.file('receipt-expectation', expected)
        receipt = self.cli(name, 1, 'wallet-receipt', '--file', receipt_path)
        require(receipt['state'] == 'VERIFIED_EVIDENCE_PENDING_IMPORT', 'evidence not independently verified')
        bundle = json.loads(base64.b64decode(frame['payload_b64'], validate=True))
        command = {'Import': {'snapshot': bundle['snapshot'], 'export': bundle['export']}}
        self.checkpoint(name, [command])
        receipt = self.cli(name, 1, 'wallet-receipt', '--file', receipt_path)
        require(receipt['state'] == 'IMPORT_ACCEPTED_IMMATURE', 'import maturity bypassed')
        self.checkpoint(name)
        self.checkpoint(name)
        receipt = self.cli(name, 1, 'wallet-receipt', '--file', receipt_path)
        require(receipt['original_output_spendable_now'] and receipt['local_finality_covers_import'], 'BFT import did not mature under actual local finality')
        before = self.cli(name, 1, 'status')['ledger']
        duplicate = self.cli(name, 1, 'contact-apply', '--file', path)
        require(duplicate['import_accepted'] and self.cli(name, 1, 'status')['ledger'] == before, 'duplicate carriage credited again')
        self.cli(name, 1, 'bft-candidate', '--miner', public(10), '--commands', self.file('duplicate-import', [command]), success=False)
        return receipt

    def run(self):
        original_journal = (self.signer('earth', 1)/'bft.json').read_bytes()
        self.checkpoint('earth', guard=True)
        current_journal = (self.signer('earth', 1)/'bft.json').read_bytes()
        signer_path = self.signer('earth', 1)/'bft.json'
        signer_path.write_bytes(original_journal)
        signer_path.chmod(0o600)
        try:
            context = self.cli('earth', 1, 'bft-context')['context']
            self.sign('earth', 1, {'Timeout': {'context': context, 'round': 0}}, success=False)
        finally:
            signer_path.write_bytes(current_journal)
            signer_path.chmod(0o600)
        self.checkpoint('earth')
        self.checkpoint('earth')
        require(self.cli('earth', 0, 'status')['height'] == 0, 'offline replica unexpectedly advanced')
        require(self.cli('earth', 0, 'bft-status', '--signer-dir', self.signer('earth', 0))['records'] == 0, 'offline voter signed')
        for certificate in self.certificates['earth']:
            self.cli('earth', 0, 'finalize', '--file', self.file('catch-up', certificate))
        self.same_replicas('earth', (0, 1, 2, 3))
        frame, expected = self.wallet_payment('earth', 10, 'proxima', 11, 97, 2)
        self.offline_earth = self.cli('earth', 1, 'status')['ledger']
        self.earth_forbidden = True
        try:
            receipt = self.receive('proxima', frame, expected)
            onward, onward_expected = self.wallet_payment('proxima', 11, 'andromeda', 12, 94, 1)
            onward_receipt = self.receive('andromeda', onward, onward_expected)
        finally:
            self.earth_forbidden = False
        self.audit('certified onward payment complete with no Earth calls during remote execution')
        return {'format': 'RLD-REGIONAL-BFT-GROUND-CAMPAIGN-V1', 'fixture_only': True, 'live_rld': False,
                'implementation': self.implementation, 'currency': self.currency, 'profile': 'RLD-REGIONAL-BFT-FIXTURE-V1',
                'replicas_per_region': 4, 'online_voters_per_region': 3, 'offline_initial_leader_progressed': True,
                'offline_replica_caught_up': True, 'old_signer_backup_latest_head_rejected': True,
                'transport_alone_did_not_credit': True, 'duplicate_import_rejected': True,
                'remote_execution_earth_calls': 0, 'first_recipient': receipt, 'onward_recipient': onward_receipt,
                'conservation_checks': self.checks, 'native_cli_calls': self.calls, 'helper_calls': self.helper_calls,
                'expected_rejections': self.rejections, 'message_bus': 'same-host controller-carried files',
                'independent_operators_qualified': False, 'autonomous_pacemaker_qualified': False,
                'validator_network_qualified': False, 'bft_reconfiguration_implemented': False,
                'external_monotonic_custody_qualified': False, 'physical_interstellar_route_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate')
    parser.add_argument('--root', type=Path, required=True, help='Fresh private fixture directory; never publish')
    parser.add_argument('--report', type=Path, required=True, help='Sanitized ground report')
    args = parser.parse_args()
    report = Campaign(args.binary, args.root).run()
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'conservation_checks': len(report['conservation_checks']), 'native_cli_calls': report['native_cli_calls'],
                      'expected_rejections': report['expected_rejections'], 'qualified_interstellar_bft': False}))


if __name__ == '__main__':
    main()
