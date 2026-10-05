"""Fresh ground spool counter: churn, suppression, cold fallback, no Native."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
import interstellar_mesh as mesh
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture

class CarriageChurnTests(unittest.TestCase):
    def fixture(self):
        retained=os.environ.get('RLD_GROUND_CHURN_ROOT')
        if retained:
            root=Path(retained)/self._testMethodName
            self.assertFalse(root.exists());root.mkdir(mode=0o700)
        else:
            tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        f=Fixture(root);f.rounds(4)
        return f

    def frame(self, serial):
        return wire.make_frame('source-finality','1'*64,'3'*64,format(serial,'064x'),
                               wire.canonical({'ground_counter':serial,'native_validation_required':True}))

    def run_churn(self, cold):
        f=self.fixture();target={};acks={};coverage=set();delivered_at=None
        with f.node('earth') as node:
            for serial in range(48):node.enqueue(self.frame(1+serial%8),f.identities['andromeda']['node_id'])
            for serial in (100,101):target[node.enqueue(self.frame(serial),f.identities['andromeda']['node_id'])]=self.frame(serial)
        for turn in range(24):
            if cold:
                with mesh._carriage_position_lock:
                    mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with f.node('earth') as node:
                for serial in range(4):node.enqueue(self.frame(200+turn*4+serial),f.identities['andromeda']['node_id'])
            # Every acknowledgment below comes from complete real ground mesh
            # receive/fsync followed by complete local reply receive/fsync.
            for source,destination in (('earth','proxima'),('proxima','andromeda'),
                                       ('andromeda','proxima'),('proxima','earth')):
                peer=f.identities[destination]['node_id'];slot=(source,destination)
                with f.node(source) as node:
                    bundle=node.prepare_exchange(peer,acks.get(slot,set()))
                    self.assertLessEqual(len(bundle['body']['transits']),4)
                    self.assertLessEqual(len(wire.canonical(bundle)),mesh.MAX_BATCH)
                    carried={mesh.digest(t) for t in bundle['body']['transits']}
                with f.node(destination) as node:
                    node.receive(bundle,f.identities[source]['node_id'])
                    reply=node.prepare_exchange(f.identities[source]['node_id'])
                    if destination=='andromeda':
                        coverage.update(node.receipts())
                        for ident,raw in target.items():
                            if ident in node.receipts():
                                transit=node.transit(ident)
                                self.assertEqual(mesh.transit_check(transit,node.network)[1],raw)
                                mesh.receipt_matches(node.receipts()[ident],transit)
                with f.node(source) as node:node.receive(reply,peer)
                acks.setdefault(slot,set()).update(carried)
                if len(acks[slot])>mesh.MAX_MESSAGES:acks[slot].clear()
            if set(target)<=coverage and delivered_at is None:delivered_at=turn+1
        self.assertIsNotNone(delivered_at,'target lost under bounded authenticated historical churn')
        with f.node('earth') as node:
            for ident,raw in target.items():
                self.assertEqual(mesh.transit_check(node.transit(ident),node.network)[1],raw)
            self.assertLessEqual(len(node.state['messages']),mesh.MAX_MESSAGES)
        print('churn-result',self._testMethodName,'delivery_round',delivered_at,flush=True)

    def test_warm_positions_under_authenticated_churn_and_exact_suppression(self):
        self.run_churn(False)

    def test_cold_positions_under_authenticated_churn_and_exact_suppression(self):
        self.run_churn(True)

    def test_later_bad_signature_refuses_after_real_custody_and_warm_position(self):
        f=self.fixture()
        with f.node('earth') as node:
            ident=node.enqueue(self.frame(100),f.identities['andromeda']['node_id'])
            bundle=node.prepare_exchange(f.identities['proxima']['node_id'])
        with f.node('proxima') as node:
            node.receive(bundle,f.identities['earth']['node_id']);before=node.path.read_bytes()
            bad=copy.deepcopy(bundle['body']['transits'][0]);sig=bad['packet']['signature']
            bad['packet']['signature']=('0' if sig[0]!='0' else '1')+sig[1:]
            with self.assertRaisesRegex(ValueError,'signature'):mesh.transit_check(bad,node.network)
            self.assertEqual(node.path.read_bytes(),before)
            self.assertIn(ident,node.state['messages'])

if __name__=='__main__':unittest.main()
