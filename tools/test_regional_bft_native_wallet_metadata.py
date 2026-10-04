import json
from pathlib import Path
import tempfile
import unittest
from verify_regional_bft_role_lifecycle import read_native_wallet_metadata

class NativeWalletMetadataTests(unittest.TestCase):
    def test_native_struct_order_is_observation_not_mesh_canonical(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'wallet.json';raw=b'{"creation":{},"binding":{},"records":[]}'
            p.write_bytes(raw)
            self.assertEqual(read_native_wallet_metadata(d),json.loads(raw))
            self.assertEqual(p.read_bytes(),raw)
    def test_duplicate_and_nonfinite_refuse_unchanged(self):
        for raw in (b'{"records":[],"records":[1]}',b'{"records":NaN}'):
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)/'wallet.json';p.write_bytes(raw)
                with self.assertRaises(ValueError):read_native_wallet_metadata(d)
                self.assertEqual(p.read_bytes(),raw)
    def test_pending_file_or_dangling_symlink_refuses_before_read(self):
        for link in (False,True):
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)/'wallet.next'
                if link:p.symlink_to(Path(d)/'missing')
                else:p.write_bytes(b'retain')
                with self.assertRaisesRegex(ValueError,'pending'):read_native_wallet_metadata(d)
                self.assertTrue(p.is_symlink() if link else p.read_bytes()==b'retain')
    def test_bound_and_metadata_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'wallet.json';p.write_bytes(b' '* (8*1024*1024+1))
            with self.assertRaisesRegex(ValueError,'byte bound'):read_native_wallet_metadata(d)
            target=Path(d)/'target';target.write_bytes(b'{}');p.unlink();p.symlink_to(target)
            with self.assertRaisesRegex(ValueError,'unsafe'):read_native_wallet_metadata(d)
            self.assertEqual(target.read_bytes(),b'{}')
if __name__=='__main__':unittest.main()
