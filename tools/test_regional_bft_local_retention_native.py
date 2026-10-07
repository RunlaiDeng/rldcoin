"""Fresh no-value Native history; real local construction and refusal boundaries."""
import copy
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_network_campaign import Campaign
from regional_bft_node import Runtime
from regional_contact_campaign import public
from regional_contact_node import Native
from regional_paged_fault_scope import inventory

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


@contextmanager
def fixture_directory():
    retained=os.environ.get('RLD_LOCAL_RETENTION_FIXTURE')
    if retained is not None:
        path=Path(retained).resolve();path.mkdir(mode=0o700)
        yield path
    else:
        with tempfile.TemporaryDirectory(prefix='rld-local-retention-native-') as directory:
            yield Path(directory).resolve()


class NativeLocalRetentionTests(unittest.TestCase):
    def test_complete_historical_responses_and_finalized_bytes_match_original_full_path(self):
        with fixture_directory() as directory:
            c=Campaign(BINARY,Path(directory).resolve()/'fixture');runtime=None
            try:
                for _ in range(2):c.checkpoint('earth',online=(0,1,2,3))
                config=c.configs[1];head=Path(config['head_file']);value=mesh.load(head,8192)
                mesh.atomic(head,dict(value,head=c.heads['earth',1]))
                def custody():
                    return (inventory(c.node('earth',1)),inventory(c.signer('earth',1)),hashlib.sha256(head.read_bytes()).hexdigest())
                before=custody();native=Native(BINARY,c.node('earth',1),public(1),c.currency)
                runtime=Runtime(native,mesh.load(c.root/'mesh-config-1.json',65536),c.root/'bft-config-1.json')
                self.assertEqual(runtime.state['height'],2)
                original_messages=native.call('bft-retained-messages','--signer-dir',c.signer('earth',1))
                retained=list(runtime.state['messages'].bodies())
                self.assertTrue(original_messages)
                for message in original_messages:
                    self.assertTrue(any(body=={'Signed':message} and local for _,body,_,local in retained))
                finals=[body['Finalized'] for _,body,_,local in retained if local and 'Finalized' in body]
                self.assertEqual(len(finals),1);self.assertEqual(finals[0]['statement']['height'],2)
                for ident,body,_,local in retained:
                    self.assertTrue(local)
                    original=runtime.envelope(body)
                    runtime.with_json('bft-network-check',original)
                    self.assertEqual(wire.canonical(original),runtime.state['messages'].payload(ident))
                self.assertEqual(custody(),before)
                changed=copy.deepcopy(finals[0]);changed['bft']['committed']['votes'][0]['approval']['signature']='00'*64
                state=wire.canonical(__import__('regional_bft_retention').pack_state(runtime.state))
                with self.assertRaises(ValueError):runtime.retain_local_body({'Finalized':changed})
                self.assertEqual(wire.canonical(__import__('regional_bft_retention').pack_state(runtime.state)),state)
                self.assertEqual(custody(),before)
            finally:
                if runtime is not None:runtime.close()
                c.cleanup()


if __name__=='__main__':unittest.main()
