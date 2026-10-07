"""Stop-boundary control-flow model; no Native or real transport authority."""
from contextlib import contextmanager
from types import SimpleNamespace
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp


class StopAfterPrepareTests(unittest.TestCase):
    def exercise(self, retry):
        server = tcp.Server.__new__(tcp.Server)
        server.guard = threading.Lock()
        server.running = True
        server.id, server.network = 'local', 'network'
        server.cursor = 0
        server.peers = {'remote': {'host': '127.0.0.1', 'port': 1,
                                  'tls_cert_sha256': 'pin'}}
        server.insecure = False
        server.contact_trace = None
        server.peer_attempts = {}
        server.accepted_transits = {}
        server.suppressed = lambda _: set()
        server.observation = lambda errors=(): dict(errors=errors)
        marks, forgotten, prepared, connects = [], [], [], []
        server.mark = lambda *args: marks.append(args)
        packets = tuple({'packet': {'complete_model_packet': n}} for n in range(4))
        ids = tuple(mesh.digest(t['packet']) for t in packets)
        retry_ids = ids if retry else ()
        node = SimpleNamespace(id=server.id,
            failed_carriage=lambda _: retry_ids,
            forget_failed_carriage=lambda peer: forgotten.append(peer),
            carriage_position_domain=lambda: ('model-domain',))
        @contextmanager
        def mesh_node(_):
            yield node
        server.mesh_node = mesh_node
        def outgoing(actual_node, peer, suppressed, actual_retry):
            self.assertIs(actual_node, node)
            self.assertEqual(actual_retry, retry_ids)
            value = {'body': {'transits': list(packets)}}
            prepared.append(value)
            # Model the existing received stop flag during full preparation.
            # Completed preparation stays atomic; no protocol timing is changed.
            server.running = False
            return value
        def connect(*args):
            connects.append(args)
            raise OSError('post-stop connection attempted by old source')
        with patch.object(tcp, 'outgoing', side_effect=outgoing), \
             patch.object(tcp, 'client_connect', side_effect=connect), \
             patch.object(mesh, 'remember_carriage_position') as remember:
            report = server._outbound_tick()
            self.assertEqual(len(prepared), 1)
            self.assertEqual(prepared[0]['body']['transits'], list(packets))
            self.assertEqual(forgotten, ['remote'] if retry else [])
            if retry:
                remember.assert_not_called()
            else:
                remember.assert_called_once_with(
                    (('model-domain',), 'remote', 'failed-carriage'), ids)
            self.assertEqual(marks, [('remote', 'outbound', False)])
            self.assertEqual(connects, [], 'stop must prevent a fresh socket attempt after preparation')
            self.assertIn('TCP runtime is stopping; preserve evidence', report['errors'])

    def test_stop_after_ordinary_full_four_keeps_retry_and_refuses_connect(self):
        self.exercise(False)

    def test_stop_after_full_four_retry_keeps_original_retry_rotation(self):
        self.exercise(True)


@unittest.skipUnless(os.environ.get('RLD_STOP_PREPARE_FIXTURE'),
                     'explicit fresh retained ground fixture required')
class RealStopAfterPrepareTests(unittest.TestCase):
    def test_real_signed_full_four_stops_before_connect_and_cold_retains_all(self):
        from test_interstellar_tcp import Fixture
        root = Path(os.environ['RLD_STOP_PREPARE_FIXTURE'])
        self.assertTrue(root.is_absolute())
        self.assertFalse(root.exists())
        root.mkdir(mode=0o700)
        fixture = Fixture(root, names=('earth', 'proxima'))
        self.addCleanup(fixture.close)
        fixture.rounds(1)
        with fixture.node('earth') as node:
            ids = [node.enqueue(fixture.frame(n), fixture.ids['proxima']) for n in range(4)]
            originals = {i: node.transit(i)['packet'] for i in ids}
        destination_before = (root/'proxima'/'mesh-state.json').read_bytes()
        server = fixture.servers['earth']
        original = tcp.outgoing
        prepared = []
        def stopping(node, *args, **kwargs):
            result = original(node, *args, **kwargs)
            prepared.append(result)
            server.running = False
            return result
        with patch.object(tcp, 'outgoing', side_effect=stopping), \
             patch.object(tcp, 'client_connect') as connect:
            report = server.tick()
            connect.assert_not_called()
        self.assertEqual(len(prepared), 1)
        self.assertEqual({mesh.digest(t['packet']) for t in prepared[0]['body']['transits']}, set(ids))
        self.assertIn('TCP runtime is stopping; preserve evidence', report['errors'])
        fixture.close()
        self.assertEqual((root/'proxima'/'mesh-state.json').read_bytes(), destination_before)
        with fixture.node('earth') as node:
            self.assertEqual(set(node.failed_carriage(fixture.ids['proxima'])), set(ids))
            self.assertTrue(set(ids).issubset(node.summaries()))
            for ident in ids:
                transit = node.transit(ident)
                mesh.transit_check(transit, node.network)
                self.assertEqual(transit['packet'], originals[ident])
                self.assertNotIn(ident, node.receipts())
        # This verifies ground custody only; no Native or receipt authority.


if __name__ == '__main__':
    unittest.main()
