"""Fresh signed carriage analogy; empty proof grants no Native authority."""
import copy
from contextlib import contextmanager
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_bft_retention import Messages
from test_interstellar_mesh import Fixture


class UnpreparedCurrentTests(unittest.TestCase):
    @contextmanager
    def fixture_directory(self):
        parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                    str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
        root=Path(tempfile.mkdtemp(prefix='rld-unprepared-current-',dir=parent))
        # Every generated no-value fixture stays local, including refusals.
        yield root

    def fixture(self,directory):
        return Fixture(directory)

    def signed_data(self,f):
        network=f.configs['earth']['network']
        context=dict(currency=network,region='9'*64,epoch='4'*64,previous='1'*64,
                     parent_height=14,parent_block='2'*64,parent_state='3'*64)
        keys=tuple(mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32).public_key().public_bytes(
            mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex() for n in range(4,8))
        messages=Messages();raws=[]
        for n,phase in ((4,'Prepare'),(5,'Commit'),(6,'Prepare')):
            key=mesh.Ed25519PrivateKey.from_private_bytes(bytes([n])*32);public=keys[n-4]
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps(
                [context,0,'5'*64,phase,public],separators=(',',':'),ensure_ascii=False).encode()
            signature=key.sign(data).hex();key.public_key().verify(bytes.fromhex(signature),data)
            env=dict(format=bft.NETWORK,currency=network,region=context['region'],evidence=dict(snapshots=[]),
                body=dict(Signed=dict(Vote=dict(context=context,round=0,value='5'*64,phase=phase,
                          approval=dict(key=public,signature=signature)))))
            messages=messages.append(mesh.digest(env['body']),env,None,True)
            payload=wire.canonical(env);raws.append(wire.make_frame('regional-bft',context['region'],
                context['region'],messages.content(mesh.digest(env['body'])),payload))
        frames=bft.commit_carriage_frames(messages,context,keys,network,context['region'])
        return context,keys,messages,raws,frames

    def test_newest_pair_offers_unprepared_forwarded_frame_before_prepared_forwarded_frame(self):
        with self.fixture_directory() as directory:
            f=self.fixture(directory);f.rounds()
            source=f.identities['earth']['node_id'];relay=f.identities['proxima']['node_id'];peer=f.identities['andromeda']['node_id']
            network=f.configs['earth']['network']
            context,keys,messages,raws,frames=self.signed_data(f)
            self.assertEqual(len(frames),3)
            with f.node('earth') as node:
                competitor=node.enqueue(raws[0],peer);old=node.prepare_exchange(relay)
                target=node.enqueue(raws[2],peer);incoming=node.prepare_exchange(relay)
                self.assertIn(target,[mesh.digest(t['packet']) for t in incoming['body']['transits']])
                original=copy.deepcopy(node.state['messages'][target])
            with f.node('proxima') as node:
                for _ in range(40):node.enqueue(f.frame(),peer)
                node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
                node.receive(old,source);node.set_carriage_priority(mesh.digest(context),frames)
                offered=node.prepare_exchange(peer)
                self.assertIn(competitor,[mesh.digest(t['packet']) for t in offered['body']['transits']])
                self.assertIn(competitor,node.state['first_carriage'][peer]['prepared'])
                node.receive(incoming,source);node.enqueue(raws[1],peer)
                self.assertNotIn(target,node.state['first_carriage'][peer]['prepared'])
                domain=node.carriage_position_domain();scope=mesh.digest(context)
                bucket=lambda i:(node.state['messages'][i]['packet']['body']['destination'],
                                 node.state['messages'][i]['routing']['body']['frame_id'])
                buckets=sorted(set(bucket(i) for i in node.state['recent_transits']))
                previous=buckets[(buckets.index(bucket(competitor))-1)%len(buckets)]

                def pressure(step):
                    mesh.remember_carriage_position((domain,peer,'recent_transit_cursors','ring'),previous)
                    mesh.forget_carriage_position((domain,peer,'native-current-frame',scope,frames,True))
                    mesh.forget_carriage_position((domain,peer,'native-current-origin',scope))
                    node.state['transit_class_steps'][peer]=step;node.save();node.set_carriage_priority(scope,frames)

                pressure(0);pair=tuple(node.first_carriage_plan(peer)['pending'][:2]);self.assertNotIn(target,pair)
                self.assertTrue({competitor,target}<=set(node.state['recent_transits']))
                state=copy.deepcopy(node.state);durable=node.path.read_bytes()
                node.state['messages'][target]['packet']['signature']='0'*128
                with self.assertRaises(ValueError):node.prepare_exchange(peer)
                self.assertEqual(node.path.read_bytes(),durable);node.state=copy.deepcopy(state)
                with patch.object(mesh,'atomic',side_effect=OSError('unprepared current publication')):
                    with self.assertRaises(OSError):node.prepare_exchange(peer)
                self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),durable)
                selected=node.prepare_exchange(peer);ids=tuple(mesh.digest(t['packet']) for t in selected['body']['transits'])
                self.assertEqual(ids[:2],pair);self.assertEqual(len(ids),4)
                self.assertTrue(set(ids[2:])&(set(node.state['messages'])-set(node.state['recent_transits'])))
                self.assertIn(target,ids[2:],'newest current spare selected already prepared forwarded frame before pending forwarded Prepare')
                self.assertNotIn(competitor,ids[2:]);self.assertFalse(node.receipts())
                self.assertEqual(node.state['messages'][target]['packet'],original['packet'])
                self.assertEqual(node.state['messages'][target]['routing'],original['routing'])
                metadata={k:copy.deepcopy(node.state[k]) for k in ('first_carriage',
                    'recent_transit_cursors','history_transit_cursors','transit_class_steps')}
                retry=node.prepare_exchange(peer,retry_packet_ids=ids)
                self.assertEqual(tuple(mesh.digest(t['packet']) for t in retry['body']['transits']),ids)
                self.assertEqual({k:node.state[k] for k in metadata},metadata)
                pressure(4);old_pair=tuple(node.first_carriage_plan(peer)['pending'][:2])
                fallback=node.prepare_exchange(peer);fallback_ids=tuple(mesh.digest(t['packet']) for t in fallback['body']['transits'])
                self.assertEqual(fallback_ids[:2],old_pair);self.assertIn(competitor,fallback_ids[2:])
                node.validate_state()
            with f.node('andromeda') as node:
                node.receive(selected,relay);receipt=node.receipts()[target]
                self.assertEqual(mesh.receipt_check(receipt,network),target)
                transit=node.transit(target);packet,raw,_=mesh.transit_check(transit,network)
                self.assertEqual(raw,raws[2]);self.assertEqual(transit['packet'],original['packet'])
                self.assertEqual(transit['routing'],original['routing']);mesh.receipt_matches(receipt,transit)
                mesh._verified_transits.clear();self.assertEqual(mesh.transit_check(transit,network)[1],raws[2])
            self.result=dict(ground_signed_analogy=True,Native_Runtime_socket_calls=0,
                complete_transport_packet_and_destination_receipt=True,inner_Native_evidence_qualified=False)


if __name__=='__main__':unittest.main()
