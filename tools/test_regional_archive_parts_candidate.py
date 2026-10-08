"""Synthetic byte-only multipart adversaries; Native proof verification separate."""
import base64
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_transfer as wire
import regional_archive_parts_candidate as parts
import regional_export_archive_carriage as archive


class ObjectPartsTests(unittest.TestCase):
    def source(self, raw):
        digest = hashlib.sha256(raw).hexdigest()
        manifest = wire.canonical(dict(format=archive.ARCHIVE, scope={},
            packs=[dict(hash=digest, bytes=len(raw))], count=416, head='1'*64))
        return manifest, {digest+'.pack': parts.split_object(raw)}, hashlib.sha256(manifest).hexdigest()

    def test_object_above_original_payload_requires_all_parts_before_retention(self):
        raw=b'x'*(wire.MAX_PAYLOAD+1)  # Synthetic object, never a Native certificate.
        self.assertGreater(len(raw),wire.MAX_PAYLOAD)
        manifest,objects,pin=self.source(raw)
        leaf=next(iter(objects))
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'fresh'
            with self.assertRaisesRegex(ValueError,'incomplete'):
                parts.retain_archive(manifest,{leaf:objects[leaf][:-1]},pin,target)
            self.assertFalse(target.exists())
            parts.retain_archive(manifest,{leaf:objects[leaf][::-1]},pin,target)
            self.assertEqual((target/'packed.json').read_bytes(),manifest)
            self.assertEqual((target/'packs'/leaf).read_bytes(),raw)
            self.assertTrue(all(len(part)<=wire.MAX_PAYLOAD for part in objects[leaf]))
            with self.assertRaisesRegex(ValueError,'absent'):
                parts.retain_archive(manifest,objects,pin,target)

    def test_mixed_duplicate_bad_sizes_corruption_and_wrong_manifest_refuse(self):
        raw=b'a'*(parts.DATA_BYTES+3);manifest,objects,pin=self.source(raw);leaf=next(iter(objects))
        original=list(objects[leaf]);variants=[original+[original[0]],original[:1]]
        for key,value in [('object_bytes',True),('parts',True),('part',True),('part',2),
                          ('data_b64',base64.b64encode(b'b'*parts.DATA_BYTES).decode()),
                          ('data_b64','!!!!')]:
            fragment=wire.decode_json(original[0]);fragment[key]=value
            variants.append([wire.canonical(fragment),original[1]])
        variants.append([parts.split_object(b'b'*(parts.DATA_BYTES+3))[0],original[1]])
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'never'
            for variant in variants:
                with self.assertRaises(ValueError):parts.retain_archive(manifest,{leaf:variant},pin,target)
                self.assertFalse(target.exists())
            for inventory in ({},dict(objects,extra=original),{'../key':original}):
                with self.assertRaises(ValueError):parts.retain_archive(manifest,inventory,pin,target)
                self.assertFalse(target.exists())
            with self.assertRaises(ValueError):parts.retain_archive(manifest,objects,'9'*64,target)
            self.assertFalse(target.exists())

    def test_explicit_segmentation_keeps_whole_hash_and_never_creates_empty_parts(self):
        raw=b'public synthetic object'*100
        pieces=parts.split_object(raw,2)
        self.assertEqual(parts.assemble_object(pieces[::-1],hashlib.sha256(raw).hexdigest(),len(raw)),raw)
        for count in (True,0,parts.MAX_PARTS+1):
            with self.assertRaises(ValueError):parts.split_object(raw,count)
        with self.assertRaises(ValueError):parts.split_object(b'x',2)
        with self.assertRaises(ValueError):parts.split_object(b'x'*(parts.DATA_BYTES+1),1)

    def test_peak_capacity_and_partial_write_preserve_original_bounds_and_residue(self):
        manifest,objects,pin=self.source(b'public bytes')
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'candidate'
            with patch.object(wire,'MAX_QUEUE_FILES',3):
                with self.assertRaises(ValueError):parts.retain_archive(manifest,objects,pin,target)
            with patch.object(wire,'MAX_QUEUE_BYTES',len(manifest)+12):
                with self.assertRaises(ValueError):parts.retain_archive(manifest,objects,pin,target)
            self.assertFalse(target.exists())
            real=wire.write_new
            def fail(path,data):
                if path.name=='packed.json':raise OSError('manifest unavailable')
                return real(path,data)
            with patch.object(wire,'write_new',side_effect=fail):
                with self.assertRaises(OSError):parts.retain_archive(manifest,objects,pin,target)
            self.assertTrue((target/'CANDIDATE_RETAINING').exists())
            self.assertTrue(list((target/'packs').iterdir()))
            with self.assertRaises(ValueError):parts.retain_archive(manifest,objects,pin,target)


if __name__=='__main__':unittest.main()
