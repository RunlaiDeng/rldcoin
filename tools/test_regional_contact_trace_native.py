"""Real Native full-envelope reception after TLS custody; finite fixture only."""
import copy
import os
from pathlib import Path
import tempfile
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_network_campaign import Campaign
from regional_contact_campaign import public
from regional_contact_node import Native,Service
from regional_contact_trace import ContactTrace

BINARY=Path(os.environ['RLD_CONTACT_BINARY']).resolve()


class NativeTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-trace-')
        self.c=Campaign(BINARY,Path(self.temp.name).resolve()/'fixture')
        self.services={};self.traces={}
        for n in (1,2):
            trace=ContactTrace()
            native=Native(BINARY,self.c.node('earth',n),public(1),self.c.currency)
            cfg=mesh.load(self.c.root/f'mesh-config-{n}.json',65536)
            self.services[n]=Service(native,cfg,None,('127.0.0.1',self.c.ports[n]),
                bft_config=self.c.root/f'bft-config-{n}.json',parallel_carriage=False,contact_trace=trace)
            self.traces[n]=trace

    def tearDown(self):
        for service in self.services.values():service.close()
        self.c.cleanup();self.temp.cleanup()

    def envelope(self):
        context=self.c.cli('earth',0,'bft-context')['context']
        signed=self.c.sign('earth',0,{'Timeout':{'context':context,'round':0}})['message']
        return self.services[1].bft.envelope({'Signed':signed})

    def test_native_checked_exact_envelope_links_source_queue_and_receiver(self):
        source,target=self.services[1],self.services[2];envelope=self.envelope()
        source.bft.retain(envelope,sync=False,local=True);source.bft.broadcast()
        enqueued=[x for x in self.traces[1].snapshot()['events'] if x['stage']=='source_enqueued'
                  and x['peer']==target.tcp.id]
        self.assertEqual(len(enqueued),1);ident=enqueued[0]['packet_id']
        source.tcp.tick();target.tick()
        rows=[x for x in self.traces[2].snapshot()['events'] if x.get('packet_id')==ident]
        self.assertTrue({'destination_receipt_retained','native_envelope_received'}<=set(x['stage'] for x in rows))
        native=[x for x in rows if x['stage']=='native_envelope_received'][0]
        self.assertEqual(native['envelope_id'],mesh.digest(envelope))
        self.assertEqual(enqueued[0]['envelope_id'],native['envelope_id'])
        self.assertIn(mesh.digest(envelope['body']),target.bft.state['messages'])

    def test_transport_receipt_never_becomes_native_reception_of_invalid_envelope(self):
        source,target=self.services[1],self.services[2];bad=copy.deepcopy(self.envelope())
        bad['evidence']['snapshots']=[{}]
        frame=wire.make_frame('regional-bft',source.region,source.region,mesh.digest(bad),wire.canonical(bad))
        with mesh.Node(source.config) as node:ident=node.enqueue(frame,target.tcp.id)
        source.tcp.tick();target.tick()
        stages={x['stage'] for x in self.traces[2].snapshot()['events'] if x.get('packet_id')==ident}
        self.assertIn('destination_receipt_retained',stages)
        self.assertNotIn('native_envelope_received',stages)
        self.assertNotIn(mesh.digest(bad['body']),target.bft.state['messages'])


if __name__=='__main__':unittest.main()
