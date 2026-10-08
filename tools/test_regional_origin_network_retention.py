"""Complete-byte retention tests only; these fixtures carry no Native authority."""
import copy
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages, ORIGIN_NETWORK, pack_state, unpack_state


class OriginNetworkRetentionTests(unittest.TestCase):
    def envelope(self, n):
        return dict(format=ORIGIN_NETWORK,currency='1'*64,region='2'*64,
            evidence=dict(snapshots=[dict(unauthenticated_local='same')]),
            body=dict(unauthenticated_fixture=n),origins=[dict(unauthenticated_origin='x'*65536)])

    def test_whole_origin_bytes_share_without_loss_and_remain_immutable(self):
        messages=Messages();originals={}
        for n in range(16):
            envelope=self.envelope(n);ident=mesh.digest(envelope['body'])
            originals[ident]=wire.canonical(envelope)
            messages=messages.append(ident,envelope,None,False)
            envelope['origins'][0]['unauthenticated_origin']='changed'
        packed=pack_state(dict(messages=messages))
        self.assertEqual(len(packed['snapshots']),2)
        self.assertLess(len(wire.canonical(packed)),sum(map(len,originals.values()))//4)
        restored=unpack_state(wire.decode_json(wire.canonical(packed)))['messages']
        for ident,raw in originals.items():
            self.assertEqual(restored.payload(ident),raw)
            restored.envelope(ident)['origins'].clear()
            self.assertEqual(restored.payload(ident),raw)

    def test_missing_changed_or_excess_origin_references_refuse_before_use(self):
        envelope=self.envelope(1);ident=mesh.digest(envelope['body'])
        packed=pack_state(dict(messages=Messages().append(ident,envelope,None,False)))
        for case in ('missing','changed','absent_refs','excess','combined_refs'):
            damaged=copy.deepcopy(packed);record=damaged['runtime']['messages'][ident]
            origin=record['origin_refs'][0]
            if case=='missing':del damaged['snapshots'][origin]
            elif case=='changed':damaged['snapshots'][origin]['unauthenticated_origin']='forged'
            elif case=='absent_refs':del record['origin_refs']
            elif case=='excess':record['origin_refs']*=5
            else:record['refs']*=64
            with self.subTest(case=case),self.assertRaises(ValueError):unpack_state(damaged)
        oversized=copy.deepcopy(packed)
        oversized['runtime']['messages'][ident]['origin_refs']*=4
        with patch.object(wire,'MAX_PAYLOAD',100000):
            with self.assertRaisesRegex(ValueError,'expansion capacity'):unpack_state(oversized)

    def test_complete_frame_version_scope_and_origin_count_are_byte_checks_only(self):
        import hashlib
        envelope=self.envelope(1)
        def frame(value):
            raw=wire.canonical(value)
            return wire.make_frame('regional-bft',value['region'],value['region'],hashlib.sha256(raw).hexdigest(),raw)
        raw=wire.canonical(envelope)
        self.assertEqual(wire.inspect_frame(frame(envelope))[1],raw)
        for case in ('old','missing','excess','wrong_type'):
            changed=copy.deepcopy(envelope)
            if case=='old':changed['format']='RLD-REGIONAL-BFT-NETWORK-V2'
            elif case=='missing':del changed['origins']
            elif case=='excess':changed['origins']*=5
            else:changed['origins']={}
            with self.subTest(case=case),self.assertRaises(ValueError):wire.inspect_frame(frame(changed))

    def test_old_format_cannot_smuggle_origin_payload(self):
        envelope=self.envelope(1);envelope['format']='RLD-REGIONAL-BFT-NETWORK-V2'
        with self.assertRaises(ValueError):Messages().append(mesh.digest(envelope['body']),envelope,None,False)


if __name__=='__main__':unittest.main()
