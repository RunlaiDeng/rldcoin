"""Fresh, offline Native preparation for the explicit paged full-fault fixture.

Controller certificates/carriage qualify setup only. This entry never starts a
Runtime/socket, copies custody, restores a ledger, or recovers a signed response.
Generated bootstrap, mesh/TLS material and every custody file remain private.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from regional_bft_node import FORMAT
from regional_contact_campaign import public
from regional_fixture_native_json import decode_native_json
from regional_paged_fault_scope import RULES, safe, require, hex32, inventory

PROJECT = Path('/Users/galaxy/GitHub/rldcoin')
VALUE_RULES = '5852ea4ac2b57594cbf089e4468895ac1f7bc920c595e0a35ebf407e3864771f'
CAPS = {'earth': 27, 'proxima': 24, 'andromeda': 24}


def native_label(value):
    # Match the Native signed currency/admission label limit before writing genesis.
    require(type(value) is str and 1 <= len(value.encode('utf-8')) <= 32
            and all('a' <= c <= 'z' or '0' <= c <= '9' or c == '-' for c in value),
            'invalid Native fixture label')
    return value


def fresh_private_parent(path):
    path = safe(path)
    require(path.parent.is_dir() and not path.exists(), 'fresh existing-parent private directory required')
    path.mkdir(mode=0o700)
    return path


class Preparation:
    def __init__(self, project, root, binary, implementation, binary_sha, deadline):
        self.project, self.root, self.binary = map(safe, (project, root, binary))
        require(self.project == PROJECT and Path.cwd() == PROJECT, 'explicit migrated project required')
        require(self.root.is_relative_to(PROJECT/'tmp') and not self.root.exists(),
                'fresh root must be absent; no overwrite, copy, migration or retry')
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest() == hex32(binary_sha),
                'reviewed CLI pin differs')
        hex32(implementation)
        require(0 < deadline - time.monotonic() <= 180, 'one finite180-second deadline required')
        self.deadline, self.started, self.calls, self.files = deadline, time.monotonic(), [], 0
        self.root.mkdir(mode=0o700)
        self.file('fresh-creation', dict(format='RLD-PAGED-FAULT-FRESH-CREATION-V1',
            root_absent_before_creation=True, inode=self.root.stat().st_ino,
            controller_preparation_only=True, copies=0, network_starts=0,
            fixture_only=True, live_rld=False, implementation=implementation,
            binary_sha256=binary_sha))
        self.authority, self.keys = public(1), sorted(public(n) for n in range(2, 6))
        self.seeds = {public(n): n for n in range(2, 6)}
        self.origin = native_label('earth-fault-' + uuid.uuid4().hex[:16])
        self.currency = dict(format='RLD-REGIONAL-FIXTURE-V1', fixture_only=True,
            implementation=implementation, origin=self.origin, authority=self.authority,
            cap=str(10**35), block_reward=str(250000*10**24), maturity=2)
        raw = self.encode('currency', list(self.currency.values()))
        self.pin = hashlib.sha256(raw).hexdigest()
        self.currency['signature'] = self.authority_sign(raw)
        self.region_ids, admissions = {}, []
        for name in (self.origin, 'proxima', 'andromeda'):
            raw = self.encode('paged-bft-admission-v1', [self.pin, name, RULES, VALUE_RULES, self.keys])
            self.region_ids[name] = hashlib.sha256(raw).hexdigest()
            admissions.append(dict(currency=self.pin, region=name, rules=RULES,
                value_rules=VALUE_RULES, validators=self.keys, signature=self.authority_sign(raw)))
        self.bootstrap = self.file('signed-fresh-bootstrap', dict(currency=self.currency, admissions=admissions))
        self.regions = {}
        self.owner = None
        self.signed = []
        self.exports = []

    @staticmethod
    def encode(domain, value):
        return ('RLD-REGIONAL-FIXTURE-V1:'+domain+'\0').encode() + json.dumps(value, separators=(',', ':')).encode()

    @staticmethod
    def authority_sign(raw):
        return Ed25519PrivateKey.from_private_bytes(bytes([1])*32).sign(raw).hex()

    def remaining(self):
        value = self.deadline - time.monotonic()
        require(value > 0, 'one180-second Native preparation budget exhausted')
        return value

    def file(self, name, value):
        self.remaining()
        path = self.root/(name+'.json')
        require(not path.exists(), 'retain every original preparation input/response')
        mesh.atomic(path, value)
        return path

    def input(self, value):
        self.files += 1
        return self.file('inputs/item-'+str(self.files), value)

    def call(self, ledger, command, *args):
        require(safe(ledger).is_relative_to(self.root), 'Native may open only new fixture custody')
        require(command not in ('wallet-recover', 'contact-resume', 'history-restore',
                                'bft-recover', 'mine', 'accept'), 'preparation recovery/direct acceptance forbidden')
        before = time.monotonic()
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run([str(self.binary), '--dir', str(ledger),
                '--authority', self.authority, '--currency', self.pin, command, *map(str, args)],
                cwd=self.project, input=None, stdout=output, stderr=errors,
                timeout=min(30, self.remaining()), check=False)
            require(output.tell() <= 8*1024**2 and errors.tell() <= 65536, 'Native output capacity')
            errors.seek(0)
            require(result.returncode == 0, 'Native preparation refusal: '+errors.read(2048).decode(errors='replace'))
            output.seek(0)
            answer = decode_native_json(output.read(8*1024**2+1))
        self.calls.append(dict(command=command, wall_seconds=round(time.monotonic()-before, 6)))
        return answer

    def region(self, label):
        name = self.origin if label == 'earth' else label
        root = self.root/label
        root.mkdir(mode=0o700)
        rows = []
        for n, key in enumerate(self.keys):
            ledger, signer, caller = root/f'native-{n}', root/f'voter-{n}', root/f'caller-{n}'/'head.json'
            initial = self.call(ledger, 'init', '--bootstrap', self.bootstrap, '--region', name)
            require(initial['height'] == 0 and initial['region'] == self.region_ids[name], 'genesis binding')
            state = self.call(ledger, 'status')
            require(state['fixture_only'] is True and state['live_rld'] is False
                and state['ledger']['minted'] == state['ledger']['received'] == '0'
                and not any(state['ledger'][k] for k in ('coins', 'exports', 'imports')), 'zero-allocation Native genesis')
            context = self.call(ledger, 'bft-context')
            require(context['rules'] == RULES and context['keys'] == self.keys
                and context['context']['parent_height'] == 0, 'signed paged genesis membership')
            bound = self.call(ledger, 'bft-init', '--signer-dir', signer, '--key', key)
            mesh.atomic(caller, dict(format=FORMAT, binding=bound['binding'], head=bound['head'], pending=None, outbox=None))
            keyfile = self.file(f'{label}/public-fixture-key-{n}', dict(secret_key=(bytes([self.seeds[key]])*32).hex()))
            rows.append(dict(ledger=ledger, signer=signer, caller=caller, keyfile=keyfile))
        self.regions[label] = rows

    def vote(self, label, n, request):
        row = self.regions[label][n]
        old = mesh.load(row['caller'], 65536)
        require(old['pending'] is None and old['outbox'] is None, 'unfinished original voter request')
        mesh.atomic(row['caller'], dict(old, pending=request))
        answer = self.call(row['ledger'], 'bft-sign', '--file', self.input(request),
            '--signer-dir', row['signer'], '--expected-head', old['head'], '--key-file', row['keyfile'])
        require(answer['previous_head'] == old['head'] and answer['recovered_exact_retry'] is False,
                'one original signing request only')
        self.input(answer)
        mesh.atomic(row['caller'], dict(old, head=answer['head'], pending=None, outbox=None))
        return answer['message']

    def certify(self, label, commands):
        rows = self.regions[label]
        ledger = rows[0]['ledger']
        context = self.call(ledger, 'bft-context')['context']
        height = context['parent_height'] + 1
        require(height <= CAPS[label], 'original absolute height limit')
        candidate = self.call(ledger, 'bft-candidate', '--commands', self.input(commands),
                              '--miner', public(10 if label == 'earth' else 20))
        proposal = self.vote(label, (height-1)%4, dict(Propose=dict(round=0, snapshot=candidate, timeout=None)))['Proposal']
        def quorum(votes):
            return self.call(ledger, 'bft-quorum', '--file', self.input(sorted(votes, key=lambda v:v['approval']['key'])))
        prepared = quorum([self.vote(label, n, dict(Prepare=proposal))['Vote'] for n in range(4)])
        committed = quorum([self.vote(label, n, dict(Commit=dict(proposal=proposal, prepared=prepared)))['Vote'] for n in range(4)])
        certificate = self.call(ledger, 'bft-certify', '--file', self.input(dict(proposal=proposal, prepared=prepared, committed=committed)))
        require(certificate['statement']['height'] == height, 'complete new-height certificate')
        path = self.file(f'{label}/preparation-certificate-{height}', certificate)
        for row in rows:
            self.call(row['ledger'], 'finalize', '--file', path)
        print('native-preparation-step '+json.dumps(dict(region=label, height=height,
              elapsed_seconds=round(time.monotonic()-self.started, 3), setup_only=True)), flush=True)

    def sign_preparation(self, remote):
        ledger = self.regions['earth'][0]['ledger']
        owner = public(10)
        if self.owner is None:
            wallet = fresh_private_parent(self.root/'preparation-owner')/'wallet'
            caller = self.root/'preparation-owner'/'caller'/'head.json'
            initial = self.call(ledger, 'wallet-init', '--wallet-dir', wallet, '--owner', owner)
            mesh.atomic(caller, dict(binding=initial['binding'], head=initial['wallet_head'], pending=None))
            key = self.file('preparation-owner/public-fixture-key', dict(secret_key=(bytes([10])*32).hex()))
            self.owner = (wallet, caller, key)
        wallet, caller, key = self.owner
        state = self.call(ledger, 'status')
        coins = sorted((ident, coin) for ident, coin in state['ledger']['coins'].items()
            if coin['payment']['owner'] == owner and coin['mature'] <= state['height']
            and coin['payment']['amount'] == self.currency['block_reward'])
        require(coins, 'actual mature original origin reward input absent')
        ident, coin = coins[0]
        request = dict(owner=owner, inputs=[ident], outputs=[] if remote else [dict(owner=public(13), amount='95')],
            remote=None if remote is None else dict(destination=self.region_ids[remote],
                recipient=dict(owner=public(20), amount='3'), destination_fee='1'), fee='1', valid_for_blocks=8)
        old = mesh.load(caller, 65536)
        require(old['pending'] is None, 'unfinished original owner request')
        prepared = self.call(ledger, 'wallet-prepare', '--file', self.input(request),
                            '--wallet-dir', wallet, '--expected-wallet-head', old['head'])
        require(prepared['draft']['selected_input_total'] == coin['payment']['amount'], 'Native selected input amount')
        mesh.atomic(caller, dict(old, pending=dict(intent_id=prepared['draft']['intent_id'], review=prepared['review_commitment'])))
        signed = self.call(ledger, 'wallet-sign', '--file', self.input(prepared), '--wallet-dir', wallet,
            '--expected-wallet-head', old['head'], '--review', prepared['review_commitment'], '--key-file', key)
        require(signed['recovered_exact_retry'] is False and signed['previous_wallet_head'] == old['head']
                and signed['retained_approvals_complete'] is True, 'original complete owner approval')
        self.file('preparation-owner/signed-response-'+str(len(self.signed)), signed)
        mesh.atomic(caller, dict(old, head=signed['wallet_head'], pending=None))
        self.signed.append(signed)
        self.certify('earth', signed['commands'])
        require(ident not in self.call(ledger, 'status')['ledger']['coins'], 'Native input was not debited')
        return signed

    def import_preparation(self, label, signed):
        source = self.regions['earth'][0]['ledger']
        frame = self.call(source, 'contact-export', '--export', signed['intent_id'])
        path = self.file('preparation-contact-'+label, frame)
        bundle = decode_native_json(base64.b64decode(frame['payload_b64']))
        require(bundle['export'] == signed['intent_id'], 'Native carried export differs')
        for row in self.regions[label]:
            applied = self.call(row['ledger'], 'contact-apply', '--file', path)
            require(applied['evidence_verified'] is True and applied['import_accepted'] is False,
                    'transport cannot grant an import')
        self.certify(label, [dict(Import=dict(snapshot=bundle['snapshot'], export=signed['intent_id']))])
        for _ in range(4):
            self.certify(label, [])
        self.exports.append((label, signed['intent_id']))

    def inspect(self):
        all_states, heads = {}, []
        for label, rows in self.regions.items():
            states = []
            for n, row in enumerate(rows):
                head = self.call(row['ledger'], 'history-head')
                self.file(f'{label}/observed-native-head-{n}', head)
                checked = self.call(row['ledger'], 'history-check', '--expected-head', head['history_head'])
                state = self.call(row['ledger'], 'status')
                require(checked['history_head'] == head['history_head'] and checked['height'] == state['height']
                    and state['fixture_only'] is True and state['live_rld'] is False, 'complete fixed-head Native replay')
                bound = self.call(row['ledger'], 'bft-status', '--signer-dir', row['signer'])
                caller = mesh.load(row['caller'], 65536)
                require(bound['binding'] == caller['binding'] and bound['head'] == caller['head']
                    and caller['pending'] is None and caller['outbox'] is None, 'Native voter/caller custody differs')
                context = self.call(row['ledger'], 'bft-context')
                require(context['rules'] == RULES and context['keys'] == self.keys
                    and context['context']['parent_height'] == state['height'], 'current Native membership differs')
                states.append(state)
                heads.append(head)
            require(all(s == states[0] for s in states), 'all four complete Native states differ')
            all_states[label] = states
        require({k:v[0]['height'] for k,v in all_states.items()} == dict(earth=8, proxima=5, andromeda=5),
                'actual preparation heights differ; no metadata substitution')
        for label, export in self.exports:
            expected = dict(currency=self.pin, source=self.region_ids[self.origin], destination=self.region_ids[label],
                            export=export, recipient=public(20), net_amount='2')
            path = self.file('preparation-expectation-'+label, expected)
            for n, row in enumerate(self.regions[label]):
                receipt = self.call(row['ledger'], 'wallet-receipt', '--file', path)
                require(receipt['expected'] == expected and receipt['import_accepted'] is True
                    and receipt['maturity_reached'] is True and receipt['original_output_spendable_now'] is True
                    and receipt['original_output_remaining'] == '2' and receipt['import_height'] == 1
                    and receipt['mature_height'] == 3 and receipt['local_finality_covers_import'] is True
                    and receipt['quarantined'] is False, 'actual full Native import/maturity differs')
                self.file(f'{label}/preparation-receipt-{n}', receipt)
        wallet, caller, _ = self.owner
        old = mesh.load(caller, 65536)
        view = self.call(self.regions['earth'][0]['ledger'], 'wallet-view', '--wallet-dir', wallet,
                         '--expected-wallet-head', old['head'])
        require(len(view['signed']) == 3 and all(v['state'] == 'INCLUDED_IN_LOCAL_LEDGER' for v in view['signed'])
            and old['pending'] is None and old['head'] == self.signed[-1]['wallet_head'], 'original preparation owner custody')
        funding = []
        fresh_private_parent(self.root/'fault-owners')
        for label, seed, target, amount in (('earth', 13, 21, 95), ('proxima', 20, 15, 2), ('andromeda', 20, 16, 2)):
            ledger = self.regions[label][0]['ledger']
            state = all_states[label][0]
            coins = [(ident, coin) for ident, coin in state['ledger']['coins'].items()
                if coin['payment']['owner'] == public(seed) and coin['payment']['amount'] == str(amount)
                and coin['mature'] <= state['height']]
            require(len(coins) == 1, 'exact mature funding input absent or ambiguous')
            ident, coin = coins[0]
            root = fresh_private_parent(self.root/'fault-owners'/label)
            initial = self.call(ledger, 'wallet-init', '--wallet-dir', root/'wallet', '--owner', public(seed))
            caller = root/'caller'/'head.json'
            mesh.atomic(caller, dict(binding=initial['binding'], head=initial['wallet_head'], pending=None))
            self.file('fault-owners/'+label+'/public-fixture-key', dict(secret_key=(bytes([seed])*32).hex()))
            request = dict(owner=public(seed), inputs=[ident], outputs=[] if label == 'earth' else [dict(owner=public(target), amount='1')],
                remote=dict(destination=self.region_ids['proxima'], recipient=dict(owner=public(target), amount='10'), destination_fee='1')
                       if label == 'earth' else None, fee='1', valid_for_blocks=8)
            reviewed = self.call(ledger, 'wallet-prepare', '--file', self.file('fault-owners/'+label+'/request', request),
                '--wallet-dir', root/'wallet', '--expected-wallet-head', initial['wallet_head'])
            require(reviewed['wallet_head'] == initial['wallet_head']
                and reviewed['draft']['input_amounts'] == {ident: str(amount)}
                and reviewed['draft']['change'] == str(84 if label == 'earth' else 0), 'actual Native funding review')
            self.file('fault-owners/'+label+'/unsigned-review', reviewed)
            unchanged = self.call(ledger, 'wallet-view', '--wallet-dir', root/'wallet', '--expected-wallet-head', initial['wallet_head'])
            require(unchanged['signed'] == [] and mesh.load(caller, 65536)['pending'] is None,
                    'unsigned preparation must not sign or reserve')
            funding.append(dict(region=label, input_id=ident, amount=str(amount), mature_height=coin['mature'],
                native_height=state['height'], owner_head=initial['wallet_head'], review_sha256=hashlib.sha256(
                    (root/'unsigned-review.json').read_bytes()).hexdigest(), first_signed=False))
        return all_states, heads, funding

    def transport(self):
        pins = []
        for label in self.regions:
            for n in range(4):
                self.remaining()
                config = dict(format=mesh.VERSION, state=str(self.root/'mesh'/f'{label}-{n}'), network=self.pin, contacts=[])
                mesh.initialize(config['state'], self.pin, self.region_ids[self.origin if label == 'earth' else label], f'fault-{label}-{n}')
                pin = tcp.public_tls_identity(config)
                require(pin['network'] == self.pin, 'fresh TLS network binding')
                before = inventory(Path(config['state']))
                require(tcp.public_tls_identity(config) == pin and inventory(Path(config['state'])) == before,
                        'TLS retain/reopen changed private custody')
                with mesh.Node(config) as node:
                    require(node.id == pin['node_id'] and node.network == self.pin, 'fresh transport identity')
                self.file(f'transport-preparation/{label}-{n}', dict(config=config, pin=pin))
                pins.append(pin)
        require(len({p['node_id'] for p in pins}) == len({p['tls_cert_sha256'] for p in pins}) == 12,
                'all twelve fresh identities/certificates must be distinct')
        return pins

    def run(self):
        for label in CAPS:
            self.region(label)
        for _ in range(3):
            self.certify('earth', [])
        self.sign_preparation(None)
        for label in ('proxima', 'andromeda'):
            signed = self.sign_preparation(label)
            self.import_preparation(label, signed)
        self.certify('earth', [])
        self.certify('earth', [])
        states, heads, funding = self.inspect()
        transport = self.transport()
        self.remaining()
        self.file('native-prepared-observation', dict(format='RLD-PAGED-FAULT-NATIVE-PREPARED-OBSERVATION-V1',
            currency=self.pin, implementation=self.currency['implementation'], rules=RULES,
            root_inode=self.root.stat().st_ino, heads=heads, funding=funding,
            transport_pins=transport, controller_preparation_only=True,
            network_starts=0, full_fault_qualified=False, independent_freshness=False,
            configuration_bound=False, launch_authority=False))
        return states, funding
