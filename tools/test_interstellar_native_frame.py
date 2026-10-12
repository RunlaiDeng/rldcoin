"""Actual native frame bytes against the independent historical Python oracle."""
import base64
import copy
import ctypes
import hashlib
import random
import unittest
from unittest.mock import patch
import interstellar_transfer as wire
import interstellar_frame_native as native
import interstellar_frame_reference as reference
from interstellar_crypto import backend

SOURCE='1'*64
DESTINATION='2'*64
EXPORT='3'*64

class NativeFrameTests(unittest.TestCase):
    def envelope(self,**fields):
        return wire.canonical(dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency=SOURCE,
                                   region=SOURCE,evidence={'snapshots':[]},body={'opaque':True},**fields))

    def test_all_kinds_exact_bytes_message_ids_and_mutual_inspection(self):
        for kind in sorted(wire.KINDS|wire.CONTROL_KINDS):
            for payload in (bytes(range(256))*32,random.Random(91).randbytes(1000),b'one'):
                destination=DESTINATION;export=EXPORT
                if kind=='regional-bft':
                    destination=SOURCE;payload=self.envelope();export=hashlib.sha256(payload).hexdigest()
                old=reference.make_frame(kind,SOURCE,destination,export,payload)
                actual=native.make_frame(kind,SOURCE,destination,export,payload)
                self.assertEqual(actual,old)
                self.assertEqual(native.inspect_frame(old,SOURCE,destination),reference.inspect_frame(actual,SOURCE,destination))

    def test_full_payload_limit_binary_and_smaller_caller_limits(self):
        raw=bytes(range(256))*(native.MAX_PAYLOAD//256)
        data=native.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,raw)
        self.assertEqual(data,reference.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,raw))
        self.assertEqual(native.inspect_frame(data)[1],raw)
        with patch.object(wire,'MAX_PAYLOAD',len(raw)-1),self.assertRaises(ValueError):native.inspect_frame(data)
        with patch.object(wire,'MAX_FRAME',len(data)-1),self.assertRaisesRegex(ValueError,'bound'):native.inspect_frame(data)
        with patch.object(wire,'MAX_PAYLOAD',0),self.assertRaises(ValueError):native.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,b'x')
        with patch.object(wire,'MAX_FRAME',native.MAX_FRAME+1),self.assertRaises(ValueError):native.inspect_frame(data)

    def test_changed_fields_noncanonical_duplicate_and_bad_base64_refuse(self):
        data=reference.make_frame('finalized-import',SOURCE,DESTINATION,EXPORT,b'complete original payload')
        frame=wire.decode_json(data)
        for key,value in (('message_id','0'*64),('payload_sha256','0'*64),('payload_b64','eA=='),
                          ('payload_b64',frame['payload_b64']+'='),('payload_b64',frame['payload_b64'][:-1]+'!'),
                          ('source_chain_id',DESTINATION),('export_id','ABC'*22),('extra',True)):
            changed=copy.deepcopy(frame);changed[key]=value
            raw=wire.canonical(changed)
            for inspect in (native.inspect_frame,reference.inspect_frame):
                with self.subTest(key=key,inspect=inspect.__module__),self.assertRaises(ValueError):inspect(raw)
        for raw in (data+b' ',data.replace(b'"format":',b'"format":"duplicate","format":',1),b'[]',b'{}'):
            for inspect in (native.inspect_frame,reference.inspect_frame):
                with self.assertRaises(ValueError):inspect(raw)
        with self.assertRaisesRegex(ValueError,'wrong source'):native.inspect_frame(data,DESTINATION)
        with self.assertRaisesRegex(ValueError,'wrong destination'):native.inspect_frame(data,None,SOURCE)

    def test_regional_opaque_construction_and_exact_envelope_binding(self):
        value=wire.decode_json(self.envelope())
        variants=[value,dict(value,format='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3',origins=[])]
        invalid=[dict(value,format='RLD-REGIONAL-BFT-NETWORK-V1'),dict(value,region=DESTINATION),
                 dict(value,currency='wrong'),dict(value,unexpected=0),
                 dict(value,format='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3',origins=[{}]*5),
                 dict(value,format='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3',origins=None)]
        for envelope in variants+invalid:
            payload=wire.canonical(envelope);export=hashlib.sha256(payload).hexdigest()
            frame=native.make_frame('regional-bft',SOURCE,SOURCE,export,payload)
            self.assertEqual(frame,reference.make_frame('regional-bft',SOURCE,SOURCE,export,payload))
            if envelope in variants:
                self.assertEqual(native.inspect_frame(frame),reference.inspect_frame(frame))
            else:
                for inspect in (native.inspect_frame,reference.inspect_frame):
                    with self.assertRaises(ValueError):inspect(frame)
        payload=self.envelope();frame=native.make_frame('regional-bft',SOURCE,SOURCE,EXPORT,payload)
        with self.assertRaisesRegex(ValueError,'consensus carriage binding'):native.inspect_frame(frame)

    def test_default_uses_no_python_payload_base64(self):
        native._profile()
        with (patch.object(base64,'b64encode',side_effect=AssertionError('Python encode')),
              patch.object(base64,'b64decode',side_effect=AssertionError('Python decode'))):
            data=wire.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,b'complete payload')
            self.assertEqual(wire.inspect_frame(data)[1],b'complete payload')

    def test_binding_forged_metadata_and_both_buffer_releases(self):
        native._profile();engine=backend();free=engine.library.rld_contact_crypto_free
        for valid in (True,False):
            releases=[]
            def release(buffer):releases.append(buffer.len);free(buffer)
            with patch.object(engine.library,'rld_contact_crypto_free',side_effect=release):
                if valid:native.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,b'x')
                else:
                    with self.assertRaises(ValueError):native.inspect_frame(b'wrong')
            self.assertEqual(len(releases),2);self.assertGreater(releases[1],0)
            self.assertEqual(releases[0]==0,not valid)
        with self.assertRaisesRegex(ValueError,'payload binding'):
            native._invoke({'Make':dict(kind='source-finality',source=SOURCE,destination=DESTINATION,export=EXPORT,
                limits=dict(payload=native.MAX_PAYLOAD,frame=native.MAX_FRAME),size_bytes=1,sha256='0'*64)},b'x')
        invoke=native._invoke
        def forged(request,raw=b''):
            value,data=invoke(request,raw);value=dict(value);value['frame_sha256']='0'*64;return value,data
        with patch.object(native,'_invoke',side_effect=forged),self.assertRaises(ValueError):
            native.make_frame('source-finality',SOURCE,DESTINATION,EXPORT,b'x')

    def test_native_pointer_bounds_refuse_without_reading(self):
        native._profile();engine=backend();operation=engine.library.rld_contact_frame
        def refuse(control,size):
            result=operation(control,size,None,native.MAX_FRAME+1)
            try:self.assertEqual(result.payload.len,0)
            finally:engine.library.rld_contact_crypto_free(result.payload)
            return result.receipt
        with self.assertRaisesRegex(ValueError,'ABI bounds differ'):engine.invoke(refuse,'Info')

if __name__=='__main__':unittest.main()
