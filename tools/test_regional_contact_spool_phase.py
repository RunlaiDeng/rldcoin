"""Same-unit carriage of durably queued bodies; no Native voting authority.

The service-order case models Native release. Mesh cases use actual authenticated
spools and custody with public no-value frame fixtures, never a ledger receipt.
"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture
import test_regional_contact_observation_scope as observation_scope


class SpoolPhaseTests(unittest.TestCase):
    def test_service_sends_newly_released_body_before_next_tick(self):
        fixture = observation_scope.ObservationScopeTests(methodName='runTest')
        service = fixture.service()
        service.config = dict(contacts=[dict(outbox="modeled-spool")])
        phases = []
        def intake(**kwargs):
            phases.append('intake')
            if not kwargs.get('defer_spool_outgoing'):phases.append('outgoing')
            return dict(errors=[])
        node = SimpleNamespace(id='node',state={'adverts':{}},tick=intake,
            summaries=lambda:{},receipts=lambda:{},
            flush_spool_outgoing=lambda:phases.append('outgoing') or [])
        service.selection_node=lambda:nullcontext(node)
        service.tcp.ordinary_mesh_node=lambda:nullcontext(node)
        service.bft.tick=lambda:phases.append('native-release-and-enqueue') or {}
        fixture.tick(service)
        self.assertEqual(phases,['intake','native-release-and-enqueue','outgoing'])

    def test_deferred_intake_does_not_send_until_bounded_flush_and_cold_custody(self):
        temporary=tempfile.TemporaryDirectory()
        fixture=Fixture(temporary.name)
        try:
            fixture.rounds()
            peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as node:
                contact=node.contacts[peer]
                # Existing discovery exchanges may remain; compare exact inventory.
                before=set(Path(contact['outbox']).glob('*.json'))
                node.tick(defer_spool_outgoing=True)
                self.assertEqual(set(Path(contact['outbox']).glob('*.json')),before)
                packet=node.enqueue(fixture.frame(),peer)
                cursor=node.state['cursor']
                self.assertEqual(node.flush_spool_outgoing(),[])
                self.assertEqual(node.state['cursor'],cursor)
                fresh=set(Path(contact['outbox']).glob('*.json'))-before
                carried=[wire.decode_json(p.read_bytes()) for p in fresh]
                self.assertTrue(any(packet==mesh.digest(t['packet']) for b in carried for t in b['body']['transits']))
                self.assertTrue(all(len(b['body']['transits'])<=mesh.MAX_PACKET_BATCH for b in carried))
                self.assertNotIn(packet,node.receipts())
            with fixture.node('proxima') as node:
                self.assertEqual(node.tick()['errors'],[])
                self.assertIn(packet,node.receipts())
            with fixture.node('proxima') as cold:
                self.assertIn(packet,cold.receipts())
        finally:temporary.cleanup()

    def test_failed_deferred_write_retains_queued_bytes_without_receipt(self):
        temporary=tempfile.TemporaryDirectory()
        fixture=Fixture(temporary.name)
        try:
            fixture.rounds()
            peer=fixture.identities['proxima']['node_id']
            with fixture.node('earth') as node:
                node.tick(defer_spool_outgoing=True)
                packet=node.enqueue(fixture.frame(),peer)
                original=wire.canonical(node.state['messages'][packet])
                with patch.object(wire,'write_new',side_effect=OSError('spool write failed')):
                    self.assertEqual(node.flush_spool_outgoing(),['spool write failed'])
                self.assertNotIn(packet,node.receipts())
                self.assertEqual(wire.canonical(node.state['messages'][packet]),original)
            with fixture.node('earth') as cold:
                self.assertNotIn(packet,cold.receipts())
                self.assertEqual(wire.canonical(cold.state['messages'][packet]),original)
                self.assertEqual(cold.flush_spool_outgoing(),[])
            with fixture.node('proxima') as node:
                self.assertEqual(node.tick()['errors'],[])
                self.assertIn(packet,node.receipts())
        finally:temporary.cleanup()


if __name__=='__main__':unittest.main()
