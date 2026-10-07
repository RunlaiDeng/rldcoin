"""Fresh Native-signed Prepare carriage; no Runtime or consensus qualification.

The same source-only transport counter runs against actual Native envelopes.
All no-value custody remains local; no failed fixture is opened or recovered.
"""
import json
import os
from pathlib import Path
import subprocess
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_campaign import Campaign
from regional_bft_retention import Messages
from regional_contact_campaign import public
from regional_bft_node import commit_carriage_frames
import test_interstellar_unprepared_current as ground


class NativeUnpreparedCurrentTests(ground.UnpreparedCurrentTests):
    def fixture(self,directory):
        value=os.environ.get('RLD_UNPREPARED_NATIVE_BINARY')
        if not value:self.skipTest('reviewed actual Native CLI required')
        binary=Path(value).resolve();project=Path(__file__).resolve().parents[1]
        self.assertTrue(binary.is_file());self.deadline=time.monotonic()+40
        test=self
        class FreshNative(Campaign):
            def invoke(c,command,success=True,helper=False):
                remaining=test.deadline-time.monotonic();test.assertGreater(remaining,0)
                result=subprocess.run(list(map(str,command)),cwd=project,capture_output=True,timeout=remaining)
                test.assertEqual(result.returncode,0 if success else 1,result.stderr.decode(errors='replace'))
                test.assertLessEqual(len(result.stdout),8*1024**2)
                return wire.decode_json(result.stdout)
        c=FreshNative(binary,Path(directory)/'native');self.c=c
        root=Path(directory)/'transport';self.names=['earth','proxima','andromeda']
        self.identities={name:mesh.initialize(root/name,c.currency,c.regions['earth'],name) for name in self.names}
        self.configs={}
        for n,name in enumerate(self.names):
            contacts=[dict(peer=self.identities[other]['node_id'],
                inbox=str(root/'links'/(other+'-'+name)),outbox=str(root/'links'/(name+'-'+other)))
                for j,other in enumerate(self.names) if abs(n-j)==1]
            self.configs[name]=dict(format=mesh.VERSION,state=str(root/name),network=c.currency,contacts=contacts)
        return self

    def node(self,name):
        return mesh.Node(self.configs[name])

    def rounds(self):
        for _ in range(6):
            for name in self.names:
                with self.node(name) as node:self.assertFalse(node.tick()['errors'])

    def frame(self):
        return wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,
                               b'{"ground_fixture":"requires separate ledger validation"}')

    def signed_data(self,f):
        c=self.c;context=c.cli('earth',0,'bft-context');keys=tuple(context['keys']);context=context['context']
        candidate=c.cli('earth',0,'bft-candidate','--miner',public(10),'--commands',c.file('empty-commands',[]))
        proposal=c.sign('earth',0,dict(Propose=dict(round=0,snapshot=candidate,timeout=None)))['message']['Proposal']
        votes=[c.sign('earth',n,dict(Prepare=proposal))['message']['Vote'] for n in (0,1,2)]
        prepared=c.combine('earth',votes)
        committed=c.sign('earth',2,dict(Commit=dict(proposal=proposal,prepared=prepared)))['message']
        bodies=[dict(Signed=dict(Vote=votes[0])),dict(Signed=committed),dict(Signed=dict(Vote=votes[1]))]
        proof=c.cli('earth',0,'proof');messages=Messages();raws=[]
        for n,body in enumerate(bodies):
            envelope=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency=c.currency,region=c.regions['earth'],
                          evidence=proof,body=body)
            packed=c.cli('earth',0,'bft-network-pack','--file',c.file('complete-envelope-'+str(n),envelope))
            checked=c.cli('earth',0,'bft-network-check','--file',c.file('complete-wire-'+str(n),packed))
            ident=mesh.digest(body);messages=messages.append(ident,packed,checked['value'],True)
            payload=messages.payload(ident)
            raws.append(wire.make_frame('regional-bft',c.regions['earth'],c.regions['earth'],messages.content(ident),payload))
        self.target_envelope=messages.envelope(mesh.digest(bodies[2]))
        self.target_body=bodies[2]
        frames=commit_carriage_frames(messages,context,keys,c.currency,c.regions['earth'],0)
        return context,keys,messages,raws,frames

    def test_newest_pair_offers_unprepared_forwarded_frame_before_prepared_forwarded_frame(self):
        super().test_newest_pair_offers_unprepared_forwarded_frame_before_prepared_forwarded_frame()
        # The base fixture's temporary directory is retained by the bounded
        # invocation controller; actual Native performs independent full wire
        # verification on the exact envelope carried to the destination.
        c=self.c;path=c.file('exact-destination-envelope',self.target_envelope)
        result=c.cli('earth',3,'bft-network-check','--file',path)
        self.assertEqual(result['value'],self.target_body['Signed']['Vote']['value'])
        self.assertLess(time.monotonic(),self.deadline)
        print('unprepared-native-result '+json.dumps(dict(completed=True,
            actual_Native_full_envelope_authenticated=True,actual_fixture_voter_signatures=True,
            original_ground_transport_predicate_and_refusals_passed=True,Runtime_socket_calls=0,
            height14_ground_analogy_is_not_maturity=True,full600_qualified=False)),flush=True)
