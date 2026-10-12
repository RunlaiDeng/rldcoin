"""Actual native/Python codec interoperability and bounded ABI refusal."""
import ctypes
import hashlib
import random
import unittest
from unittest.mock import patch
import zlib
import interstellar_crypto as crypto
import interstellar_spool_codec as codec
import interstellar_spool_codec_native as native
import interstellar_spool_codec_reference as reference
import interstellar_transfer as wire

class NativeSpoolCodecTests(unittest.TestCase):
    def test_mutual_interoperability_exact_bytes_and_capacity_metadata(self):
        rng = random.Random(913)
        for raw in (b'x', bytes(range(256)) * 512, b'0' * 1000000,
                    rng.randbytes(120000), b'\x00\xff{"signed":true}' * 1100):
            limit = max(len(raw) + 1024, 4096)
            for sender, receiver in ((native, reference), (reference, native)):
                with self.subTest(size=len(raw), sender=sender.__name__):
                    encoded = sender.encode(raw, limit=limit)
                    self.assertEqual(receiver.decode(encoded, limit=limit), raw)
                    self.assertEqual(native.expanded_size(encoded[:codec.HEADER_SIZE],
                                     encoded_size=len(encoded), limit=limit), len(raw))
                    self.assertEqual(encoded[:codec.HEADER_SIZE], reference.MAGIC +
                                     len(raw).to_bytes(8, 'big') + hashlib.sha256(raw).digest())

    def test_default_codec_never_calls_python_compressor_or_decompressor(self):
        raw = b'exact signed exchange' * 500
        native._profile()
        with (patch.object(zlib, 'compress', side_effect=AssertionError('Python compressor')),
              patch.object(zlib, 'decompressobj', side_effect=AssertionError('Python decompressor'))):
            self.assertEqual(codec.decode(codec.encode(raw, limit=20000), limit=20000), raw)

    def test_complete_limit_and_incompressible_capacity_refusal(self):
        raw = b'a' * native.MAX_BYTES
        encoded = native.encode(raw, limit=native.MAX_BYTES)
        self.assertEqual(reference.decode(encoded, limit=native.MAX_BYTES), raw)
        self.assertEqual(native.decode(reference.encode(raw, limit=native.MAX_BYTES),
                                       limit=native.MAX_BYTES), raw)
        for limit in (0, -1, True, native.MAX_BYTES + 1):
            with self.assertRaises(ValueError):native.encode(b'x', limit=limit)
        with self.assertRaises(ValueError):native.encode(random.Random(14).randbytes(4096), limit=4096)
        with self.assertRaises(ValueError):native.decode(encoded, limit=len(raw) - 1)

    def test_exact_payload_binding_and_unknown_control_refuse_without_partial_output(self):
        raw = b'authenticated elsewhere' * 100
        for request in ({'Encode':dict(limit=4096,size_bytes=len(raw),sha256='0'*64)},
                        {'Encode':dict(limit=4096,size_bytes=len(raw)+1,sha256=hashlib.sha256(raw).hexdigest())},
                        {'Encode':dict(limit=4096,size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),extra=1)},
                        {'Decode':dict(limit=4096,size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())}):
            with self.assertRaises(ValueError):native._invoke(request,raw)

    def test_both_native_buffers_are_released_once_on_success_and_refusal(self):
        native._profile();engine=crypto.backend()
        free=engine.library.rld_contact_crypto_free
        for raw, mode in ((b'complete'*100,'Encode'),(b'invalid','Decode')):
            released=[]
            def release(buffer):
                released.append((buffer.len, bool(buffer.data)));free(buffer)
            with patch.object(engine.library,'rld_contact_crypto_free',side_effect=release):
                if mode=='Encode':native.encode(raw,limit=4096)
                else:
                    with self.assertRaises(ValueError):native.decode(raw,limit=4096)
            self.assertEqual(len(released),2)
            self.assertGreater(released[1][0],0)
            self.assertEqual(released[0][0]==0,mode=='Decode')

    def test_forged_success_metadata_never_releases_payload_to_caller(self):
        original=native._invoke
        def forged(request,raw=b''):
            value,data=original(request,raw)
            if type(request) is dict:
                value=dict(value);value['sha256']='0'*64
            return value,data
        native._profile()
        with patch.object(native,'_invoke',side_effect=forged):
            with self.assertRaises(ValueError):native.encode(b'exact'*100,limit=4096)

    def test_native_abi_refuses_oversized_unreadable_payload_and_control(self):
        native._profile();engine=crypto.backend()
        operation=engine.library.rld_contact_spool_codec
        for oversized_control in (False,True):
            def refused(control,size):
                result=operation(control,native.MAX_CONTROL+1 if oversized_control else size,
                                 None,0 if oversized_control else native.MAX_BYTES+1)
                try:self.assertEqual(result.payload.len,0)
                finally:engine.library.rld_contact_crypto_free(result.payload)
                receipt=wire.decode_json(ctypes.string_at(result.receipt.data,result.receipt.len))
                self.assertIs(receipt['success'],False)
                self.assertIsNone(receipt['value'])
                self.assertEqual(receipt['error'],'native spool codec ABI bounds differ')
                self.assertIs(receipt['ledger_authority'],False)
                return result.receipt
            # Oversized control is deliberately unreadable, so its rejection
            # binds an empty control rather than the caller's invalid length.
            expected='receipt binding differs' if oversized_control else 'ABI bounds differ'
            with self.assertRaisesRegex(ValueError,expected):
                engine.invoke(refused,'Info')

if __name__=='__main__':unittest.main()
