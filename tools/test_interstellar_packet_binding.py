"""Storage ownership remains independent of an already authenticated transit."""
import copy
import tempfile
import unittest

import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture, NETWORK


class PacketBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(self.temp.name)
        with self.f.node('earth') as node:
            self.ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            self.state = copy.deepcopy(node.state)
            self.path = node.path

    def test_wrong_map_key_refuses_both_cold_and_exact_warm_transit(self):
        for warm in (False, True):
            with mesh._verified_transits_lock:
                mesh._verified_transits.clear()
            if warm:
                mesh.transit_check(self.state['messages'][self.ident], NETWORK)
            state = copy.deepcopy(self.state)
            state['messages']['f'*64] = state['messages'].pop(self.ident)
            state['recent_transits'] = ['f'*64]
            mesh.atomic(self.path, state)
            raw = self.path.read_bytes()
            with self.subTest(warm=warm), self.assertRaisesRegex(ValueError, 'ownership'):
                self.f.node('earth')
            self.assertEqual(self.path.read_bytes(), raw)

    def test_correctly_signed_wrong_source_route_refuses_after_prior_authentication(self):
        transit = copy.deepcopy(self.state['messages'][self.ident])
        mesh.transit_check(transit, NETWORK)
        # Authenticated transport bytes cannot authorize another packet ID.
        with self.f.node('earth') as node:
            transit['routing'] = mesh.sign(node.key, 'receipt-route',
                dict(transit['routing']['body'], packet_id='f'*64))
        state = copy.deepcopy(self.state)
        state['messages'][self.ident] = transit
        mesh.atomic(self.path, state)
        raw = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'routing'):
            self.f.node('earth')
        self.assertEqual(self.path.read_bytes(), raw)

    def test_valid_hop_to_another_node_cannot_authorize_local_store_ownership(self):
        transit = copy.deepcopy(self.state['messages'][self.ident])
        with self.f.node('earth') as node:
            transit['hops'] = [mesh.sign(node.key, 'hop', dict(format=mesh.VERSION,
                network=NETWORK, node_id=node.id, packet_id=self.ident,
                previous=self.ident, to=self.f.identities['proxima']['node_id']))]
        mesh.transit_check(transit, NETWORK)
        state = copy.deepcopy(self.state)
        state['messages'][self.ident] = transit
        mesh.atomic(self.path, state)
        raw = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'ownership'):
            self.f.node('earth')
        self.assertEqual(self.path.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
