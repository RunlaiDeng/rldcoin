"""Fresh no-value transport identities, exact independent crypto and private-file refusal."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import interstellar_mesh as mesh
import interstellar_transfer as wire
import interstellar_crypto as crypto
from interstellar_crypto_reference import sign_reference,verify_reference

NETWORK='a'*64
DOMAINS=('advert','archive','exchange','hop','inventory','packet','receipt','receipt-route',
    'tcp-challenge','tcp-request','tcp-response')
class NativeCryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='rld-native-contact-crypto-')
        self.root=Path(self.tmp.name).resolve()
        with patch.object(mesh.Ed25519PrivateKey,'generate',side_effect=AssertionError('Python private generation')):
            self.identity=mesh.initialize(self.root/'mesh',NETWORK,'b'*64,'native fixture')
        self.config=dict(format=mesh.VERSION,state=str(self.root/'mesh'),network=NETWORK,contacts=[])
    def tearDown(self):self.tmp.cleanup()
    def body(self,node):
        return dict(format=mesh.VERSION,network=NETWORK,node_id=node.id,unicode='地球😀',
            nested=dict(amount='120000',fraction=1e-7,other=-0.0),frame='escape-free-ascii')
    def test_actual_node_uses_native_identity_without_python_private_read_and_exact_signatures(self):
        private_path=self.root/'mesh/identity.private.json'
        raw=private_path.read_bytes();fixture=json.loads(raw)
        # This key is read only in the independent test, never normal Node.
        reference=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture['private_key']))
        original=mesh.load
        def load(path,*args):
            if Path(path).name=='identity.private.json':raise AssertionError('Python loaded transport secret')
            return original(path,*args)
        with patch.object(mesh,'load',side_effect=load),mesh.Node(self.config) as node:
            self.assertIsInstance(node.key,crypto.NativeSigner)
            self.assertNotIn('private_key',node.key.identity)
            for kind in DOMAINS:
                body=self.body(node);native=mesh.sign(node.key,kind,body)
                expected=sign_reference(reference,kind,body)
                self.assertEqual(wire.canonical(native),wire.canonical(expected))
                self.assertEqual(mesh.verify(expected,kind,NETWORK),verify_reference(native,kind,NETWORK))
                altered=copy.deepcopy(native);altered['body']['nested']['amount']='120001'
                with self.assertRaises(ValueError):mesh.verify(altered,kind,NETWORK)
        self.assertEqual(private_path.read_bytes(),raw)
    def test_private_identity_change_links_modes_wrong_role_and_network_refuse(self):
        path=self.root/'mesh/identity.private.json';retained=path.read_bytes()
        with mesh.Node(self.config) as node:
            body=self.body(node)
            os.chmod(path,0o644)
            try:
                with self.assertRaises(ValueError):mesh.sign(node.key,'packet',body)
            finally:os.chmod(path,0o600)
            link=self.root/'mesh/identity-copy';os.link(path,link)
            try:
                with self.assertRaises(ValueError):mesh.sign(node.key,'packet',body)
            finally:link.unlink()
            modified=json.loads(retained);modified['private_key']='12'*32;path.write_bytes(wire.canonical(modified))
            try:
                with self.assertRaises(ValueError):mesh.sign(node.key,'packet',body)
            finally:path.write_bytes(retained)
            for changed in (dict(body,network='c'*64),dict(body,node_id='0'*64)):
                with self.assertRaises(ValueError):mesh.sign(node.key,'packet',changed)
            with self.assertRaises(ValueError):mesh.sign(node.key,'bft-commit',body)
        self.assertEqual(path.read_bytes(),retained)
        with self.assertRaises(ValueError):mesh.initialize(self.root/'mesh',NETWORK,'b'*64,'native fixture')
        self.assertEqual(path.read_bytes(),retained)
    def test_raw_duplicate_unknown_and_signature_encoding_refusal(self):
        with mesh.Node(self.config) as node:
            valid=mesh.sign(node.key,'packet',self.body(node))
            for field,value in [('public_key',valid['public_key'].upper()),('signature','0'*128),
                ('signature',valid['signature'].upper()),('unknown',True),('body',True)]:
                bad=copy.deepcopy(valid);bad[field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):mesh.verify(bad,'packet',NETWORK)
            with self.assertRaises(ValueError):mesh.verify(valid,'receipt',NETWORK)
            with self.assertRaises(ValueError):mesh.verify(valid,'packet','c'*64)
            engine=crypto.backend();raw=b'{"Verify":{"network":"'+NETWORK.encode()+b'","network":"'+NETWORK.encode()+b'","kind":"packet","signed":{}}}'
            memory=(crypto.ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
            result=engine.library.rld_contact_crypto(memory,len(raw))
            try:reply=wire.decode_json(crypto.ctypes.string_at(result.data,result.len))
            finally:engine.library.rld_contact_crypto_free(result)
            self.assertIs(reply['success'],False);self.assertIs(reply['ledger_authority'],False)
    def test_concurrent_native_calls_keep_separate_keys_and_library_binding(self):
        mesh.initialize(self.root/'second',NETWORK,'c'*64,'second native fixture')
        other=dict(self.config,state=str(self.root/'second'))
        with mesh.Node(self.config) as first,mesh.Node(other) as second:
            def run(number):
                node=first if number%2==0 else second
                body=dict(self.body(node),sequence=number)
                signed=mesh.sign(node.key,'inventory',body)
                return mesh.verify(signed,'inventory',NETWORK)==body
            with ThreadPoolExecutor(max_workers=4) as pool:self.assertTrue(all(pool.map(run,range(24))))
            with self.assertRaises(ValueError):crypto.bind_binary(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate',dict(format=crypto.FORMAT,implementation='0'*64))

    def test_changed_native_verification_provider_cannot_reuse_transit_witness(self):
        from test_interstellar_mesh import Fixture,NETWORK as fixture_network
        fixture=Fixture(self.root/'transit-fixture')
        with fixture.node('earth') as node:
            ident=node.enqueue(fixture.frame(),fixture.identities['andromeda']['node_id'])
            transit=node.state['messages'][ident]
        mesh.transit_check(transit,fixture_network,include_frame=False)
        class ChangedProvider:
            implementation='0'*64;path=Path('/model-only-changed-provider');library=object()
            def __init__(self):self.calls=0
            def call(self,request):self.calls+=1;raise ValueError('MODEL_CHANGED_PROVIDER_REFUSES')
        changed=ChangedProvider()
        with patch.object(crypto,'backend',return_value=changed):
            with self.assertRaisesRegex(ValueError,'MODEL_CHANGED_PROVIDER_REFUSES'):
                mesh.transit_check(transit,fixture_network,include_frame=False)
        self.assertGreater(changed.calls,0)

    def test_changed_native_provider_reauthenticates_retained_archive_index(self):
        from test_interstellar_mesh import MeshTests
        fixture=MeshTests();fixture.setUp()
        try:
            fixture.archived_index_fixture()
            with fixture.f.node('earth'):pass
            engine=crypto.backend()
            validator=mesh.Node.archive_entry
            with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
                with fixture.f.node('earth'):pass
                self.assertEqual(checked.call_count,0)
                # Only the validation namespace changes for this model; real
                # native verification must execute again for every index entry.
                with patch.object(crypto,'validation_domain',return_value=(crypto.FORMAT,'model-changed',str(engine.path),id(engine.library))):
                    with fixture.f.node('earth'):pass
                self.assertGreater(checked.call_count,0)
        finally:fixture.tearDown()

if __name__=='__main__':unittest.main()
