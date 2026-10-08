"""Byte-retention adversaries only; synthetic packs have no Native authority."""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import interstellar_transfer as wire
import regional_export_archive_carriage as carriage


class ArchiveCarriageTests(unittest.TestCase):
    def payload(self):
        raw = b'public synthetic bytes, not a Native certificate'
        name = hashlib.sha256(raw).hexdigest()
        manifest = wire.canonical(dict(format=carriage.ARCHIVE, scope={},
            packs=[dict(hash=name, bytes=len(raw))], count=16, head='1'*64))
        return wire.canonical(dict(format=carriage.FORMAT,
            manifest_b64=base64.b64encode(manifest).decode(),
            objects={name+'.pack':base64.b64encode(raw).decode()}))

    def test_exact_public_bytes_and_existing_target_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'candidate'
            payload=self.payload()
            self.assertEqual(carriage.retain_candidate(payload,target),'1'*64)
            self.assertEqual(carriage.pack_candidate(target),payload)
            before={str(p.relative_to(target)):p.read_bytes() for p in target.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(ValueError,'absent'):
                carriage.retain_candidate(payload,target)
            self.assertEqual(before,{str(p.relative_to(target)):p.read_bytes() for p in target.rglob('*') if p.is_file()})
            self.assertFalse((target/'CANDIDATE_RETAINING').exists())

    def test_paths_duplicate_missing_corrupt_and_oversize_refuse_before_writes(self):
        payload=self.payload();original=wire.decode_json(payload)
        variants=[]
        for names in ({'../key.json':'AA=='},{},dict(original['objects'],extra='AA==')):
            variants.append(dict(original,objects=names))
        name=next(iter(original['objects']))
        variants.append(dict(original,objects={name:'AA=='}))
        variants.append(dict(original,objects={name:'!'*4}))
        for count in (True,0,2**63):
            manifest=wire.decode_json(base64.b64decode(original['manifest_b64']));manifest['count']=count
            variants.append(dict(original,manifest_b64=base64.b64encode(wire.canonical(manifest)).decode()))
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'never-created'
            for value in variants:
                with self.assertRaises((ValueError,TypeError)):
                    carriage.retain_candidate(wire.canonical(value),target)
                self.assertFalse(target.exists())
            with patch.object(wire,'MAX_PAYLOAD',len(payload)-1):
                with self.assertRaises(ValueError):carriage.retain_candidate(payload,target)
                self.assertFalse(target.exists())

    def test_ordinary_two_hop_delivery_and_return_are_separate_phases(self):
        from test_interstellar_mesh import Fixture
        import interstellar_mesh as mesh
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Fixture(Path(temporary)/'mesh')
            fixture.rounds(2)
            payload=self.payload()
            frame=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,payload)
            with fixture.node('earth') as source:
                packet=source.enqueue(frame,fixture.identities['andromeda']['node_id'])
            fixture.rounds(2)
            with fixture.node('andromeda') as destination:
                mesh.receipt_matches(destination.receipts()[packet],destination.transit(packet))
                self.assertEqual(destination.receipts()[packet]['body']['outcome'],
                                 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            with fixture.node('earth') as source:
                self.assertNotIn(packet,source.receipts())
            returned=False
            for _ in range(6):
                fixture.rounds(1)
                with fixture.node('earth') as source:
                    if packet in source.receipts():
                        mesh.receipt_matches(source.receipts()[packet],source.transit(packet))
                        self.assertFalse(source.status()['payment_authorized'])
                        returned=True
                        break
            self.assertTrue(returned,'ordinary return receipt not observed')
            mesh._verified_transits.clear()
            with fixture.node('andromeda') as destination:
                transit=destination.transit(packet)
                mesh.receipt_matches(destination.receipts()[packet],transit)
                arrived=base64.b64decode(transit['packet']['body']['frame'],validate=True)
                self.assertEqual(arrived,frame)
                _,carried=wire.inspect_frame(arrived,'1'*64,'3'*64)
                self.assertEqual(carried,payload)
            target=Path(temporary)/'received'
            carriage.retain_candidate(carried,target)
            self.assertEqual(carriage.pack_candidate(target),payload)

    def test_explicit_lossless_manifest_preserves_bytes_and_refuses_missing_originals(self):
        value=wire.decode_json(self.payload())
        manifest=wire.decode_json(base64.b64decode(value['manifest_b64']))
        manifest['format']=carriage.LOSSLESS_ARCHIVE
        manifest['original_packs']=[dict(hash='2'*64,bytes=4096)]
        # Synthetic encoded bytes are not inflated or authenticated as Native.
        # Only the actual Native inspector can verify a complete compressed pack.
        encode=lambda m:wire.canonical(dict(value,
            manifest_b64=base64.b64encode(wire.canonical(m)).decode()))
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'candidate'
            raw=encode(manifest)
            carriage.retain_candidate(raw,target)
            self.assertEqual(carriage.pack_candidate(target),raw)
            variants=[dict(manifest,original_packs=[]),dict(manifest,original_packs=[{}]),
                      dict(manifest,original_packs=[dict(hash='../x',bytes=4096)]),
                      dict(manifest,original_packs=[dict(hash='2'*64,bytes=True)]),
                      dict(manifest,original_packs=[dict(hash='2'*64,bytes=carriage.MAX_DECODED_OBJECT+1)]),
                      dict(manifest,format=carriage.ARCHIVE)]
            for variant in variants:
                denied=Path(temporary)/'denied'
                with self.assertRaises(ValueError):carriage.retain_candidate(encode(variant),denied)
                self.assertFalse(denied.exists())

    def test_partial_write_retains_sentinel_and_never_resumes_or_grants_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'interrupted'
            real=wire.write_new
            def fail_manifest(path,data):
                if path.name=='packed.json':raise OSError('manifest publication denied')
                return real(path,data)
            with patch.object(wire,'write_new',side_effect=fail_manifest):
                with self.assertRaises(OSError):carriage.retain_candidate(self.payload(),target)
            self.assertTrue((target/'CANDIDATE_RETAINING').exists())
            self.assertTrue(list((target/'packs').iterdir()))
            with self.assertRaises(ValueError):carriage.retain_candidate(self.payload(),target)


if __name__=='__main__':unittest.main()
