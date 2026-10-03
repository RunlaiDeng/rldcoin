"""Boundary tests for the non-consensus offline evidence courier."""

import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import interstellar_transfer as transfer


SOURCE = '1' * 64
DESTINATION = '2' * 64
EXPORT = '3' * 64
ANCHOR = '4' * 64
MAX_TARGET = 'f' * 64


class EvidenceTransportTests(unittest.TestCase):
    def test_consensus_v2_exact_binding_and_legacy_refusal_are_carriage_only(self):
        envelope={'format':'RLD-REGIONAL-BFT-NETWORK-V2','currency':SOURCE,'region':SOURCE,
                  'evidence':{'snapshots':[]},'body':{'unauthorized_codec_fixture':True}}
        payload=transfer.canonical(envelope)
        frame=transfer.make_frame('regional-bft',SOURCE,SOURCE,hashlib.sha256(payload).hexdigest(),payload)
        self.assertEqual(transfer.inspect_frame(frame)[1],payload)
        # The courier checks identity/bytes only; Rust must reject this body.
        legacy=dict(envelope,format='RLD-REGIONAL-BFT-NETWORK-V1')
        payload=transfer.canonical(legacy)
        frame=transfer.make_frame('regional-bft',SOURCE,SOURCE,hashlib.sha256(payload).hexdigest(),payload)
        with self.assertRaisesRegex(ValueError,'consensus carriage binding'):
            transfer.inspect_frame(frame)

    def test_exact_payload_route_and_tamper_detection(self):
        payload = b'{"exact": "bytes and spacing"}'
        data = transfer.make_frame('finalized-import', SOURCE, DESTINATION, EXPORT, payload)
        frame, received = transfer.inspect_frame(data, SOURCE, DESTINATION)
        self.assertEqual(received, payload)
        self.assertEqual(transfer.make_frame('finalized-import', SOURCE, DESTINATION, EXPORT, payload), data)
        with self.assertRaisesRegex(ValueError, 'wrong destination'):
            transfer.inspect_frame(data, SOURCE, '5' * 64)
        corrupted = json.loads(data)
        corrupted['payload_b64'] = corrupted['payload_b64'][:-4] + 'AAAA'
        with self.assertRaises(ValueError):
            transfer.inspect_frame(transfer.canonical(corrupted))
        with self.assertRaises(ValueError):
            transfer.inspect_frame(data + b' ')

    def test_durable_receive_repeat_and_exact_carry(self):
        data = transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'{}')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identifier, new = transfer.queue_receive(root / 'queue', data, SOURCE, DESTINATION)
            self.assertTrue(new)
            self.assertEqual(transfer.queue_receive(root / 'queue', data, SOURCE, DESTINATION),
                             (identifier, False))
            transfer.queue_carry(root / 'queue', identifier, root / 'contact.json', SOURCE, DESTINATION)
            self.assertEqual((root / 'contact.json').read_bytes(), data)
            self.assertEqual((root / 'queue' / (identifier + '.json')).read_bytes(), data)
            with self.assertRaisesRegex(ValueError, 'wrong source'):
                transfer.queue_receive(root / 'other', data, '5' * 64, DESTINATION)

    def test_capture_and_apply_source_page_requires_node_replay(self):
        header = {'chain_id': SOURCE, 'parent': ANCHOR, 'height': '1',
                  'timestamp': 1, 'target': MAX_TARGET, 'miner': '5' * 64,
                  'commands_root': '6' * 64, 'state_root': '7' * 64,
                  'nonce': '0'}
        block = {'header': header, 'commands': []}
        tip = transfer.block_id(header, 'source-sync')
        page = {'chain_id': SOURCE, 'v1_tip': ANCHOR,
                'transition_preview_id': '8' * 64, 'common': ANCHOR,
                'tip': tip, 'blocks': [block]}
        status = {'chain_id': SOURCE, 'storage_healthy': True, 'live_rld': True}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = SimpleNamespace(kind='source-sync', source_chain=SOURCE,
                                      destination_chain=DESTINATION, export_id=EXPORT,
                                      anchor=ANCHOR, from_id=ANCHOR, origin='http://127.0.0.1:1',
                                      max_pages=1, output_dir=root)
            with patch.object(transfer, 'node_json', side_effect=[status, page]):
                result = transfer.capture_sync(capture)
            frame_path = root / (result['messages'][0] + '.json')
            apply = SimpleNamespace(input=frame_path, source_chain=SOURCE,
                                    destination_chain=DESTINATION, anchor=ANCHOR,
                                    source_origin='http://127.0.0.1:2', destination_origin=None)
            with patch.object(transfer, 'node_json', return_value=status), \
                 patch.object(transfer, 'node_post_bytes', return_value={'selected': True}) as post:
                self.assertEqual(transfer.apply_frame(apply)['result'], 'NODE_VALIDATED_SYNC')
                self.assertEqual(post.call_count, 1)
                self.assertEqual(post.call_args.args[1], '/v1/earth/blocks')
            with patch.object(transfer, 'node_json', return_value=status), \
                 patch.object(transfer, 'node_post_bytes', side_effect=ValueError('node rejects state root')):
                with self.assertRaisesRegex(ValueError, 'node rejects'):
                    transfer.apply_frame(apply)

    def test_wrong_ancestry_and_receipt_without_replay_fail_closed(self):
        page = {'chain_id': SOURCE, 'v1_tip': ANCHOR, 'common': '9' * 64,
                'tip': '9' * 64, 'blocks': []}
        with self.assertRaisesRegex(ValueError, 'ancestry'):
            transfer.check_sync(page, 'source-sync', SOURCE, DESTINATION, ANCHOR, ANCHOR)
        value = {'bundle': {'source_chain_id': SOURCE, 'destination_chain_id': DESTINATION,
                            'export_id': EXPORT}, 'policy': {},
                 'receipt': {'export_id': EXPORT, 'block_height': '91',
                             'recipient_spendable_height': '97'}}
        data = transfer.make_frame('destination-receipt', SOURCE, DESTINATION, EXPORT,
                                   transfer.canonical(value))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'receipt.json'
            path.write_bytes(data)
            args = SimpleNamespace(input=path, source_chain=SOURCE,
                                   destination_chain=DESTINATION,
                                   source_origin=None, destination_origin='http://127.0.0.1:3')
            with patch.object(transfer, 'node_json', return_value={
                    'valid_on_selected_branches': True, 'live_rld': True,
                    'confirmations': '6'}):
                with self.assertRaisesRegex(ValueError, 'not yet mature'):
                    transfer.apply_frame(args)
            with patch.object(transfer, 'node_json', return_value={
                    'valid_on_selected_branches': True, 'live_rld': True,
                    'confirmations': '7'}):
                self.assertEqual(transfer.apply_frame(args)['result'],
                                 'LOCALLY_VERIFIED_DESTINATION_RECEIPT')
            with patch.object(transfer, 'node_json', side_effect=ValueError('invalid branch')):
                with self.assertRaisesRegex(ValueError, 'invalid branch'):
                    transfer.apply_frame(args)

    def test_queue_frame_limit_retains_data_and_accepts_exact_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(transfer, 'MAX_QUEUE_FILES', 1):
            root=Path(tmp)/'queue'
            first=transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'one')
            second=transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'two')
            ident,_=transfer.queue_receive(root,first,SOURCE,DESTINATION)
            with self.assertRaisesRegex(ValueError,'capacity'):
                transfer.queue_receive(root,second,SOURCE,DESTINATION)
            self.assertEqual((root/(ident+'.json')).read_bytes(),first)
            self.assertEqual(transfer.queue_receive(root,first,SOURCE,DESTINATION),(ident,False))

    def test_queue_byte_limit_exact_boundary(self):
        data=transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'one')
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(transfer,'MAX_QUEUE_BYTES',len(data)-1):
                with self.assertRaisesRegex(ValueError,'capacity'):
                    transfer.queue_receive(Path(tmp)/'queue',data,SOURCE,DESTINATION)
            with patch.object(transfer,'MAX_QUEUE_BYTES',len(data)):
                self.assertTrue(transfer.queue_receive(Path(tmp)/'queue',data,SOURCE,DESTINATION)[1])

    def test_corrupt_retained_frame_is_not_overwritten_by_retry(self):
        data=transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'one')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'queue'
            ident,_=transfer.queue_receive(root,data,SOURCE,DESTINATION)
            target=root/(ident+'.json'); target.write_bytes(data[:10])
            with self.assertRaisesRegex(ValueError,'collision'):
                transfer.queue_receive(root,data,SOURCE,DESTINATION)
            self.assertEqual(target.read_bytes(),data[:10])
            with self.assertRaises(ValueError):
                transfer.queue_carry(root,ident,Path(tmp)/'out',SOURCE,DESTINATION)
            self.assertFalse((Path(tmp)/'out').exists())

    def test_symlink_queue_and_lock_fail_closed(self):
        data=transfer.make_frame('source-finality', SOURCE, DESTINATION, EXPORT, b'one')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); real=root/'real'; real.mkdir(); alias=root/'alias'; alias.symlink_to(real)
            with self.assertRaisesRegex(ValueError,'unsafe directory'):
                transfer.queue_receive(alias,data,SOURCE,DESTINATION)
            target=root/'protected'; target.write_bytes(b'protected')
            (real/'.lock').symlink_to(target)
            with self.assertRaisesRegex(ValueError,'unsafe queue lock'):
                transfer.queue_receive(real,data,SOURCE,DESTINATION)
            self.assertEqual(target.read_bytes(),b'protected')


if __name__ == '__main__':
    unittest.main()
