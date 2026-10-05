"""Creation-label boundary exposed by the actual refused Native bootstrap."""
import unittest
import tempfile
from pathlib import Path
from regional_paged_fault_prepare import native_label, fresh_private_parent


class LabelBoundary(unittest.TestCase):
    def test_existing_native_label_boundary_before_genesis(self):
        self.assertEqual(native_label('a'*32), 'a'*32)
        self.assertEqual(native_label('earth-fault-'+'0'*16), 'earth-fault-'+'0'*16)
        for label in ('earth-fault-prep-'+'0'*16, '', 'earth_A', 'é', '１', 1, True):
            with self.subTest(label=label), self.assertRaises(ValueError):
                native_label(label)

    def test_native_wallet_parent_freshness_without_creation_or_merge(self):
        with tempfile.TemporaryDirectory(dir=Path('/Users/galaxy/GitHub/rldcoin/tmp')) as directory:
            root = Path(directory)
            parent = fresh_private_parent(root/'owner')
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse((parent/'wallet').exists())
            with self.assertRaises(ValueError):
                fresh_private_parent(parent)
            with self.assertRaises(ValueError):
                fresh_private_parent(root/'missing'/'owner')
            (root/'link').symlink_to(parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                fresh_private_parent(root/'link'/'new')


if __name__ == '__main__':
    unittest.main()
