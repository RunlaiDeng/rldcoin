import json
from pathlib import Path
import tempfile
import unittest
from verify import capture, unique

class SourceTests(unittest.TestCase):
    def fixture(self,root):
        for name in ('crates','vectors','spec','docs/spec'):(root/name).mkdir(parents=True,exist_ok=True)
        for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'):(root/name).write_text(name)
        (root/'crates/a.rs').write_text('original')

    def test_content_paths_and_membership_change_commitment_but_root_location_does_not(self):
        with tempfile.TemporaryDirectory() as temp:
            a=Path(temp)/'one';b=Path(temp)/'two';self.fixture(a);self.fixture(b)
            initial=capture(a);self.assertEqual(initial,capture(b))
            (a/'crates/a.rs').write_text('modified');self.assertNotEqual(initial['commitment'],capture(a)['commitment'])
            (a/'crates/a.rs').write_text('original');(a/'crates/a.rs').rename(a/'crates/b.rs');self.assertNotEqual(initial['commitment'],capture(a)['commitment'])
            (a/'crates/b.rs').rename(a/'crates/a.rs');(a/'crates/new.rs').write_text('');self.assertNotEqual(initial['commitment'],capture(a)['commitment'])
            (a/'crates/new.rs').unlink();self.assertEqual(initial,capture(a))
            (a/'crates/.env').write_text('ignored');(a/'docs/PLAN_STATUS.md').write_text('not source');self.assertEqual(initial,capture(a))

    def test_symlink_special_names_and_duplicate_manifest_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            bad=root/'crates/link.rs';bad.symlink_to('a.rs')
            with self.assertRaises(ValueError):capture(root)
            bad.unlink();bad=root/'crates/bad\\name.rs';bad.write_text('')
            with self.assertRaises(ValueError):capture(root)
        with self.assertRaises(ValueError):json.loads('{"format":1,"format":2}',object_pairs_hook=unique)
if __name__=='__main__':unittest.main()
