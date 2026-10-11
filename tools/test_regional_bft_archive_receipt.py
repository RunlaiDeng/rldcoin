"""Archive receipt-binding models only, no native ledger/custody authority."""
import copy
import hashlib
from types import SimpleNamespace
import unittest
from regional_bft_native_archive import checked

class ArchiveReceiptTests(unittest.TestCase):
    def test_byte_domain_count_and_authority_substitution_refuse(self):
        runtime=SimpleNamespace(native=SimpleNamespace(currency='1'*64),region='2'*64,format='model',key='key')
        raw=b'{}';receipt=dict(format='RLD-NATIVE-BFT-ARCHIVE-RECEIPT-V1',currency='1'*64,region='2'*64,
            runtime_format='model',key='key',state_sha256=hashlib.sha256(raw).hexdigest(),state_bytes=2,message_count=0,
            new_envelopes_authenticated=0,full_cold_authentication_required=True,ledger_changed=False,signing_authority=False)
        self.assertEqual(checked(runtime,receipt,raw,0,0),receipt['state_sha256'])
        for key,value in [('state_sha256','0'*64),('currency','0'*64),('region','0'*64),('runtime_format','wrong'),
            ('key','wrong'),('state_bytes',True),('message_count',False),('new_envelopes_authenticated',True),
            ('full_cold_authentication_required',False),('ledger_changed',True),('signing_authority',True),('unknown',True)]:
            bad=copy.deepcopy(receipt);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):checked(runtime,bad,raw,0,0)

if __name__=='__main__':unittest.main()
