"""Signed hostile packets still need full frame/route/contact authentication."""
import base64
import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture,NETWORK


class FrameAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.f=Fixture(self.temp.name)
        with mesh._verified_transits_lock:mesh._verified_transits.clear()

    def packet(self,frame):
        with self.f.node('earth') as node:
            signed=mesh.sign(node.key,'packet',dict(format=mesh.VERSION,network=NETWORK,node_id=node.id,
                destination=self.f.identities['proxima']['node_id'],nonce='5'*64,hop_limit=mesh.MAX_HOPS,
                frame=base64.b64encode(frame).decode()))
            header=wire.decode_json(frame)
            route=mesh.sign(node.key,'receipt-route',dict(format=mesh.VERSION,network=NETWORK,node_id=node.id,
                packet_id=mesh.digest(signed),destination=self.f.identities['proxima']['node_id'],frame_id=header['message_id']))
        return dict(packet=signed,routing=route,hops=[])

    def test_correctly_signed_transport_cannot_hide_changed_frame_payload(self):
        header=wire.decode_json(self.f.frame());payload=base64.b64decode(header['payload_b64'])
        header['payload_b64']=base64.b64encode(payload.replace(b'ground',b'Ground',1)).decode()
        transit=self.packet(wire.canonical(header))
        with self.assertRaisesRegex(ValueError,'payload changed'):mesh.transit_check(transit,NETWORK)
        self.assertEqual(len(mesh._verified_transits),0)

    def test_valid_complete_foreign_currency_frame_refuses_without_witness(self):
        envelope=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency='b'*64,region='1'*64,
                      evidence=dict(snapshots=[]),body=dict(Submission=[]))
        payload=wire.canonical(envelope);frame=wire.make_frame('regional-bft','1'*64,'1'*64,
                            hashlib.sha256(payload).hexdigest(),payload)
        transit=self.packet(frame)
        with self.assertRaisesRegex(ValueError,'currency'):mesh.transit_check(transit,NETWORK)
        self.assertEqual(len(mesh._verified_transits),0)

    def test_signed_route_and_hop_tampering_refuse_after_valid_frame(self):
        transit=self.packet(self.f.frame());mesh.transit_check(transit,NETWORK)
        with self.f.node('earth') as node:
            bad=copy.deepcopy(transit);body=dict(bad['routing']['body'],frame_id='f'*64)
            bad['routing']=mesh.sign(node.key,'receipt-route',body)
        with self.assertRaisesRegex(ValueError,'routing'):mesh.transit_check(bad,NETWORK)
        with self.assertRaisesRegex(ValueError,'contact'):mesh.transit_check(transit,NETWORK,
                        recipient=self.f.identities['proxima']['node_id'],sender=self.f.identities['earth']['node_id'])
        bad=copy.deepcopy(transit);bad['hops']=[dict(body={},public_key='0'*64,signature='0'*128)]
        with self.assertRaises(ValueError):mesh.transit_check(bad,NETWORK)

    def test_tighter_frame_limit_refuses_a_previously_authenticated_transit(self):
        frame=self.f.frame();transit=self.packet(frame);mesh.transit_check(transit,NETWORK)
        with patch.object(wire,'MAX_FRAME',len(frame)-1):
            with self.assertRaisesRegex(ValueError,'frame exceeds'):mesh.transit_check(transit,NETWORK)
        packet,raw,visited=mesh.transit_check(transit,NETWORK)
        self.assertEqual(raw,frame);self.assertEqual(visited,[packet['node_id']])
        self.assertTrue(all(isinstance(v,tuple) and all(isinstance(x,str) for x in v)
                            for v in mesh._verified_transits.values()))


if __name__=='__main__':unittest.main()
