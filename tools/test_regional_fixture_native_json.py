import tempfile
import unittest
from pathlib import Path
from regional_fixture_native_json import decode_native_json, read_native_json


class NativeJsonFixture(unittest.TestCase):
    def test_native_field_order_is_not_mesh_state_canonical_order(self):
        self.assertEqual(decode_native_json(b'{"region":1,"currency":2}'),
                         dict(region=1, currency=2))

    def test_duplicates_and_nonfinite_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":-Infinity}', b'{"a":1e999}', b'{"a":-1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_native_json(raw)

    def test_exact_byte_bound_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.json'
            path.write_bytes(b'{"a":1}')
            self.assertEqual(read_native_json(path, 7), {'a': 1})
            with self.assertRaises(ValueError):
                read_native_json(path, 6)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                read_native_json(link, 7)
            with self.assertRaises(ValueError):
                read_native_json(path, True)


if __name__ == '__main__':
    unittest.main()
