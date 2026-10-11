"""Fresh no-value actual Origin Runtime caller publication and keyless restart.

All signing seeds are public fixture numbers. No independent custody or liveness claim.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import interstellar_mesh as mesh
from regional_contact_campaign import public
from regional_contact_node import Native
from regional_bft_node import Runtime, ORIGIN_RUNTIME_FORMAT
from test_regional_bft_node import BINARY


class OriginCallerTests(unittest.TestCase):
    def test_actual_composed_origin_sign_then_lost_response_recovers_without_key(self):
        with tempfile.TemporaryDirectory(prefix='rld-native-origin-caller-') as directory:
            root = Path(directory).resolve(); runtime = None
            package = json.loads(subprocess.check_output([str(BINARY.with_name('contact-fixture')), 'bootstrap', '--bft']))
            project = Path(__file__).resolve().parents[1]; source = project/'tools/regional-ledger/src'
            def encode(domain, value):
                return ('RLD-REGIONAL-FIXTURE-V1:'+domain+'\0').encode()+json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
            def ident(domain, value): return hashlib.sha256(encode(domain, value)).hexdigest()
            def sign(value): return Ed25519PrivateKey.from_private_bytes(bytes([86])*32).sign(value).hex()
            currency = package['currency']; origin = 'earth-caller-'+uuid.uuid4().hex[:16]
            currency.update(authority=public(86), origin=origin, cap=str(10**35), block_reward=str(250000*10**24))
            body = [currency[key] for key in ('format','fixture_only','implementation','origin','authority','cap','block_reward','maturity')]
            pin = ident('currency', body); currency['signature'] = sign(encode('currency', body))
            channels = hashlib.sha256(b'RLD-REGIONAL-CHANNEL-KERNEL-V8\0'+(source/'channel_rules.md').read_bytes()).hexdigest()
            issuance = hashlib.sha256(b'RLD-ISSUANCE-RESERVE-ERA-V1\0'+(project/'docs/spec/RESERVE-ERA-ISSUANCE-V1.md').read_bytes()).hexdigest()
            channel = ident('native-channel-profile-v1', [(source/'channel_profile.md').read_text(),channels,issuance])
            paged = ident('paged-bft-rules-v1', [(source/'paged_bft_profile.md').read_text(),channel])
            history = ident('complete-origin-history-bft-rules-v1', [(source/'origin_history_profile.md').read_text(),paged])
            profile = ident('complete-origin-network-bft-rules-v2', [(source/'origin_network_profile.md').read_text(),history])
            for admission in package['admissions']:
                if admission['region'] == 'earth': admission['region'] = origin
                admission.update(currency=pin, rules='RLD-REGIONAL-BFT-COMPLETE-ORIGIN-NETWORK-FIXTURE-V2', value_rules=profile)
                admission['signature'] = sign(encode('complete-origin-network-bft-admission-v2',
                    [admission[key] for key in ('currency','region','rules','value_rules','validators')]))
            def file(name, value):
                path = root/(name+'.json'); mesh.atomic(path, value); return path
            native = Native(BINARY, root/'node', public(86), pin)
            region = native.call('init','--bootstrap',file('bootstrap',package),'--region',origin)['region']
            keys = package['admissions'][0]['validators']; key = keys[0]
            seed = next(n for n in range(2,6) if public(n) == key)
            signer = root/'signer'; head = native.call('bft-init','--signer-dir',signer,'--key',key)['head']
            caller = root/'caller'; caller.mkdir(mode=0o700)
            head_file = caller/'head.json'; mesh.atomic(head_file,dict(format=ORIGIN_RUNTIME_FORMAT,
                binding=dict(currency=pin,region=region,key=key),head=head,pending=None,outbox=None))
            validators = []; transports = []
            for n in range(4):
                state = root/f'mesh-{n}'; mesh.initialize(state,pin,region,'fresh-caller-fixture')
                config = dict(format=mesh.VERSION,state=str(state),network=pin,contacts=[])
                with mesh.Node(config) as node: validators.append(dict(key=keys[n],node_id=node.id))
                transports.append(config)
            key_file = file('public-fixture-key',dict(secret_key=(bytes([seed])*32).hex()))
            config = file('bft-config',dict(format=ORIGIN_RUNTIME_FORMAT,state=str(root/'runtime'),signer_dir=str(signer),
                head_file=str(head_file),key_file=str(key_file),key=key,miner=public(10),validators=validators,
                block_interval=1,round_timeout=20,stop_height=3))
            try:
                runtime = Runtime(native,transports[0],config)
                request = dict(Timeout=dict(context=native.call('bft-context')['context'],round=0))
                runtime.sign(request) # Actual composed Origin signing/envelope/retention path.
                self.assertEqual(runtime.signer_status()['records'],1)
                next_request = dict(Timeout=dict(context=native.call('bft-context')['context'],round=1))
                runtime.save_head(dict(runtime.head,pending=next_request))
                signed = runtime.with_json('bft-sign',next_request,'--signer-dir',signer,
                    '--expected-head',runtime.head['head'],'--key-file',key_file)
                runtime.close(); runtime = None; key_file.unlink()
                runtime = Runtime(native,transports[0],config)
                self.assertEqual(runtime.head['head'],signed['head'])
                self.assertIsNone(runtime.head['pending']); self.assertIsNone(runtime.head['outbox'])
                self.assertEqual(runtime.signer_status()['records'],2)
                self.assertTrue(any(row['envelope']['body'] == {'Signed':signed['message']}
                    for row in runtime.state['messages'].values()))
                self.assertEqual(native.call('history-check','--expected-head',native.call('history-head')['history_head'])['height'],0)
            finally:
                if runtime: runtime.close()

if __name__ == '__main__': unittest.main()
