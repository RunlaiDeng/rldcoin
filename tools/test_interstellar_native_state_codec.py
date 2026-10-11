"""Real native ABI against the independent complete Python state codec."""
import copy
import hashlib
import unittest
from unittest.mock import patch
import interstellar_active_state as reference
import interstellar_state_codec as native
import interstellar_transfer as wire

LIMITS = dict(max_state=64*1024*1024, max_messages=256, max_transit=20*1024*1024)
NETWORK, NODE = 'a'*64, 'b'*64


def sample():
    return dict(active_storage=reference.STORAGE, network=NETWORK, node_id=NODE,
                note=['中文', '🌍', -0.0, 1e-5, 1e16], messages={
        f'{index:064x}': dict(packet=dict(body=dict(frame=frame, ordinal=index)),
                            routing=dict(order=[2, 1, 2]), hops=[index, index])
        for index, frame in enumerate(('AAAA', 'AAAA', 'AB=='))})


def decode(raw, **limits):
    return native.decode(raw, network=NETWORK, node_id=NODE, **(LIMITS | limits))


class NativeStateCodecTests(unittest.TestCase):
    def test_canonical_ascii_del_and_unicode_escape_boundary_matches_python(self):
        for note in ('plain ASCII', ''.join(map(chr, range(128))), '中文🌍'):
            state = sample(); state['note'] = note
            expected = reference.pack(state, **LIMITS)
            image = native.pack(state, **LIMITS)
            self.assertEqual(wire.canonical(image), wire.canonical(expected))
            self.assertEqual(decode(wire.canonical(image)), state)

    def test_exact_bytes_equal_distinct_frames_and_shared_immutable_reconstruction(self):
        state = sample()
        expected = reference.pack(state, **LIMITS)
        image = native.pack(state, **LIMITS)
        self.assertEqual(wire.canonical(image), wire.canonical(expected))
        self.assertEqual(len(image['frames']), 2)
        restored = decode(wire.canonical(image))
        self.assertEqual(restored, state)
        values = list(restored['messages'].values())
        self.assertIs(values[0]['packet']['body']['frame'], values[1]['packet']['body']['frame'])
        self.assertEqual(sample(), state)

    def test_every_record_full_commitment_rejects_later_metadata_change(self):
        image = reference.pack(sample(), **LIMITS)
        ident = next(reversed(image['state']['messages']))
        for field in ('hops', 'routing', 'packet'):
            changed = copy.deepcopy(image)
            transit = changed['state']['messages'][ident]['transit']
            if field == 'hops': transit[field].append(0)
            elif field == 'routing': transit[field]['order'].reverse()
            else: transit[field]['body']['ordinal'] = 99
            # The original vector is a palindrome; change its actual bytes.
            if field == 'routing': transit[field]['order'].append(3)
            with self.subTest(field=field), self.assertRaises(ValueError):
                decode(wire.canonical(changed))

    def test_pool_ownership_missing_corrupt_orphan_and_record_shape_refuse(self):
        image = reference.pack(sample(), **LIMITS)
        ref = next(iter(image['frames']))
        variants = []
        changed = copy.deepcopy(image); del changed['frames'][ref]; variants.append(changed)
        changed = copy.deepcopy(image); changed['frames'][ref]['frame'] = 'AQ=='; variants.append(changed)
        changed = copy.deepcopy(image); changed['frames'][ref]['node_id'] = 'c'*64; variants.append(changed)
        changed = copy.deepcopy(image)
        obj = dict(format=reference.FRAME, network=NETWORK, node_id=NODE, frame='AA==')
        changed['frames'][reference.digest(obj)] = obj; variants.append(changed)
        for value in (True, 1.0, 0, -1, LIMITS['max_transit']+1):
            changed = copy.deepcopy(image)
            next(iter(changed['state']['messages'].values()))['expanded_size_bytes'] = value
            variants.append(changed)
        changed = copy.deepcopy(image)
        next(iter(changed['state']['messages'].values()))['transit']['packet']['body']['frame'] = 'AAAA'
        variants.append(changed)
        for index, changed in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError): decode(wire.canonical(changed))

    def test_noncanonical_duplicate_keys_and_wrong_binding_refuse(self):
        raw = wire.canonical(reference.pack(sample(), **LIMITS))
        for altered in (raw+b' ', b'{"format":"x",'+raw[1:]):
            with self.assertRaises(ValueError): decode(altered)
        for network, node in (('c'*64, NODE), (NETWORK, 'd'*64)):
            with self.assertRaises(ValueError):
                native.decode(raw, network=network, node_id=node, **LIMITS)

    def test_exact_capacity_and_message_limit_without_native_context_leak(self):
        state = sample(); image = reference.pack(state, **LIMITS); size = len(wire.canonical(image))
        self.assertEqual(native.pack(state, **(LIMITS | dict(max_state=size))), image)
        self.assertEqual(decode(wire.canonical(image), max_state=size), state)
        before = native._invoke('Usage')['contexts']
        for limits in (dict(max_state=size-1), dict(max_messages=2), dict(max_transit=1),
                       dict(max_state=LIMITS['max_state']+1), dict(max_messages=True)):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                native.pack(state, **(LIMITS | limits))
        self.assertEqual(native._invoke('Usage')['contexts'], before)

    def test_failed_payload_binding_poisons_context_and_duplicate_begin_retains_original(self):
        token = '1'*32; raw = wire.canonical(dict(sample(), messages={}))
        begin = {'Begin': dict(token=token, limits=LIMITS, **native._payload(raw))}
        try:
            native._invoke(begin, raw)
            with patch.object(native.secrets, 'token_hex', return_value=token), self.assertRaisesRegex(ValueError, 'already exists'):
                native.pack(sample(), **LIMITS)
            malformed = sample(); malformed['active_storage'] = 'legacy'
            with patch.object(native.secrets, 'token_hex', return_value=token), self.assertRaisesRegex(ValueError, 'already exists'):
                native.pack(malformed, **LIMITS)
            # The failed colliding caller did not abort our context.
            transit = wire.canonical(next(iter(sample()['messages'].values())))
            request = dict(token=token, ident='0'*64, size_bytes=len(transit), sha256='0'*64)
            with self.assertRaisesRegex(ValueError, 'payload binding'): native._invoke({'Transit': request}, transit)
            with self.assertRaisesRegex(ValueError, 'failed or closed'): native._invoke({'Finish': dict(token=token)})
        finally: native._invoke({'Abort': dict(token=token)})

    def test_lost_begin_and_finish_replies_close_known_context(self):
        invoke = native._invoke
        before = invoke('Usage')['contexts']
        for phase in ('Begin', 'Finish'):
            def lose(request, raw=b''):
                value = invoke(request, raw)
                if type(request) is dict and phase in request: raise ValueError('lost native reply')
                return value
            with self.subTest(phase=phase), patch.object(native, '_invoke', side_effect=lose):
                with self.assertRaisesRegex(ValueError, 'lost native reply'): native.pack(sample(), **LIMITS)
            self.assertEqual(invoke('Usage')['contexts'], before)

    def test_context_capacity_refuses_ninth_without_replacing_retained_operations(self):
        raw = wire.canonical(dict(sample(), messages={}))
        tokens = [f'{index+16:032x}' for index in range(9)]
        before = native._invoke('Usage')['contexts']; self.assertEqual(before, 0)
        try:
            for token in tokens[:8]: native._invoke({'Begin': dict(token=token, limits=LIMITS, **native._payload(raw))}, raw)
            with self.assertRaisesRegex(ValueError, 'context capacity'):
                native._invoke({'Begin': dict(token=tokens[8], limits=LIMITS, **native._payload(raw))}, raw)
            self.assertEqual(native._invoke('Usage')['contexts'], 8)
            for token in tokens[:8]:
                value = native._invoke({'Finish': dict(token=token)})
                self.assertEqual(value['image']['state'], dict(sample(), messages={}))
        finally:
            for token in tokens: native._invoke({'Abort': dict(token=token)})
        self.assertEqual(native._invoke('Usage')['contexts'], before)

    def test_frame_alphabet_and_legacy_inline_refuse_without_conversion(self):
        for frame in ('AA=A', '中文', 'AA==='):
            state = sample(); next(iter(state['messages'].values()))['packet']['body']['frame'] = frame
            with self.assertRaises(ValueError): native.pack(state, **LIMITS)
        state = sample(); state['active_storage'] = 'legacy'
        with self.assertRaises(ValueError): native.pack(state, **LIMITS)
        with self.assertRaises(ValueError): decode(wire.canonical(sample()))

    def test_ordinary_entry_uses_native_with_python_reference_disabled(self):
        import interstellar_mesh as mesh
        state = sample()
        expected = reference.pack(state, **LIMITS)
        with patch.object(reference, 'pack', side_effect=AssertionError('reference pack called')), \
                patch.object(reference, 'decode', side_effect=AssertionError('reference decode called')), \
                patch.object(reference, 'unpack', side_effect=AssertionError('reference unpack called')):
            image = mesh.pack_state_storage(state)
            self.assertEqual(image, expected)
            self.assertEqual(mesh.unpack_state_storage(image, NETWORK, NODE), state)


if __name__ == '__main__': unittest.main()
