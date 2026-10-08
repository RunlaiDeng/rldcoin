"""Synthetic declarations only; actual Native rejection is separately required."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import interstellar_transfer as wire
import regional_archive_parts_candidate as parts
import regional_origin_history_carriage as carriage


class OriginCarriageTests(unittest.TestCase):
    scope = dict(source='1'*64, destination='2'*64, export='3'*64, currency='4'*64)

    def proof(self):
        # Intentionally not an authentic Native certificate. Byte APIs may
        # retain it but never call it verified or create a Native ledger.
        return wire.canonical(dict(source=self.scope['source'], destination=self.scope['destination'],
            export=self.scope['export'], snapshots=[dict(statement=dict(
                region=self.scope['source'], currency=self.scope['currency'], height=1),
                unauthenticated_padding='x'*(wire.MAX_PAYLOAD+1))]))

    def test_complete_parts_keep_exact_bytes_and_do_not_authenticate(self):
        raw = self.proof()
        frames = carriage.make_frames(raw, **self.scope)
        pieces = []
        for frame in frames:
            header, piece = wire.inspect_frame(frame, self.scope['source'], self.scope['destination'])
            self.assertEqual(header['export_id'], self.scope['export'])
            self.assertLessEqual(len(frame), wire.MAX_FRAME)
            self.assertLessEqual(len(piece), wire.MAX_PAYLOAD)
            pieces.append(piece)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'proof.json'
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                carriage.retain_proof(pieces[:-1], hashlib.sha256(raw).hexdigest(), len(raw), target, **self.scope)
            self.assertFalse(target.exists())
            carriage.retain_proof(pieces[::-1], hashlib.sha256(raw).hexdigest(), len(raw), target, **self.scope)
            self.assertEqual(target.read_bytes(), raw)
            with self.assertRaisesRegex(ValueError, 'absent'):
                carriage.retain_proof(pieces, hashlib.sha256(raw).hexdigest(), len(raw), target, **self.scope)

    def test_wrong_scope_order_bool_and_extra_ledger_refuse_before_retention(self):
        original = wire.decode_json(self.proof())
        variants = []
        for field in ('source', 'destination', 'export'):
            changed = dict(original, **{field:'9'*64})
            variants.append(changed)
        for height in (True, 0, 2):
            changed = wire.decode_json(self.proof())
            changed['snapshots'][0]['statement']['height'] = height
            variants.append(changed)
        variants.extend([dict(original, snapshots=[]), dict(original, ledger={})])
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'never.json'
            for value in variants:
                raw = wire.canonical(value)
                with self.assertRaises(ValueError):
                    carriage.retain_proof(parts.split_object(raw), hashlib.sha256(raw).hexdigest(), len(raw), target, **self.scope)
                self.assertFalse(target.exists())
        changed = dict(self.scope, currency='9'*64)
        with self.assertRaises(ValueError):
            carriage.make_frames(self.proof(), **changed)


if __name__ == '__main__':
    unittest.main()
