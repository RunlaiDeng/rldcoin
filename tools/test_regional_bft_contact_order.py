"""Real native phase custody must reach the ordinary outgoing attempt this tick.

The socket attempt is intercepted; native signing, head/outbox persistence,
envelope packing, mesh enqueue and complete frame authentication are real.
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_network_campaign import Campaign
from regional_contact_campaign import public
from regional_contact_node import Native, Service

BINARY = Path(os.environ.get('RLD_CONTACT_BINARY', str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


class ContactOrderTests(unittest.TestCase):
    def test_actual_native_timeout_updates_carriage_round_from_separate_caller_head(self):
        # Retain this tiny fixture on failure as well as success. It contains
        # only fresh public no-value keys, never production custody.
        retained=os.environ.get('RLD_NATIVE_ROUND_FIXTURE')
        if retained is None:
            root=Path(tempfile.mkdtemp(prefix='rld-native-carriage-round-')).resolve()
        else:
            root=Path(retained).resolve();root.mkdir(mode=0o700)
        c=Campaign(BINARY,root/'fixture');service=None
        try:
            native=Native(BINARY,c.node('earth',1),public(1),c.currency)
            service=Service(native,mesh.load(c.root/'mesh-config-1.json',65536),None,
                            bft_config=c.root/'bft-config-1.json',parallel_carriage=False)
            runtime=service.bft
            candidate=c.cli('earth',1,'bft-candidate','--miner',public(10),'--commands',c.file('commands',[]))
            proposal=c.sign('earth',0,{'Propose':dict(round=0,snapshot=candidate,timeout=None)})['message']['Proposal']
            votes=[c.sign('earth',n,{'Prepare':proposal})['message'] for n in (0,2,3)]
            for message in [{'Proposal':proposal},*votes]:
                runtime.retain(runtime.envelope({'Signed':message}),sync=False)
            with patch.object(service.tcp,'tick',return_value=dict(errors=[])):
                service.tick()
                self.assertEqual(runtime._carriage_round,0)
                import time
                runtime.entered_at=time.monotonic()-runtime.round_timeout-1
                service.tick()
            signer=runtime.signer_status()
            self.assertEqual(signer['state']['round'],1)
            self.assertEqual(runtime._carriage_round,1)
            self.assertEqual(signer['head'],runtime.head['head'])
            self.assertIsNone(runtime.head['pending']);self.assertIsNone(runtime.head['outbox'])
            timeouts=[(i,b) for i,b,_,local in runtime.state['messages'].bodies()
                      if local and 'Timeout' in b.get('Signed',{})]
            self.assertEqual(len(timeouts),1)
            self.assertIsNotNone(timeouts[0][1]['Signed']['Timeout']['high'])
            content=runtime.state['messages'].content(timeouts[0][0])
            with mesh.Node(service.config) as node:
                packets=[i for i,t in node.summaries().items() if t['source']==node.id and t['export_id']==content]
                self.assertTrue(packets)
                for ident in packets:
                    _,raw,_=mesh.transit_check(node.transit(ident),node.network)
                    _,payload=wire.inspect_frame(raw)
                    runtime.with_json('bft-network-check',wire.decode_json(payload))
            self.assertEqual(native.call('status')['height'],0)
        finally:
            if service is not None:service.close()
            c.cleanup()

    def test_fresh_commit_is_durable_and_queued_before_the_only_outgoing_attempt(self):
        with tempfile.TemporaryDirectory(prefix='rld-bft-contact-order-') as temporary:
            campaign = Campaign(BINARY, Path(temporary).resolve()/'fixture')
            service = None
            try:
                native = Native(BINARY, campaign.node('earth', 1), public(1), campaign.currency)
                service = Service(native, mesh.load(campaign.root/'mesh-config-1.json', 65536), None,
                                  bft_config=campaign.root/'bft-config-1.json',parallel_carriage=False)
                runtime = service.bft
                candidate = campaign.cli('earth', 1, 'bft-candidate', '--miner', public(10),
                                         '--commands', campaign.file('commands', []))
                proposal = campaign.sign('earth', 0, {'Propose':dict(round=0, snapshot=candidate, timeout=None)})['message']['Proposal']
                votes = [campaign.sign('earth', n, {'Prepare':proposal})['message'] for n in (0, 2, 3)]
                for message in [{'Proposal':proposal}, *votes]:
                    runtime.retain(runtime.envelope({'Signed':message}), sync=False)
                observations = []
                def outgoing():
                    status = runtime.signer_status()
                    commits = [i for i, body, _, local in runtime.state['messages'].bodies()
                               if local and body.get('Signed', {}).get('Vote', {}).get('phase') == 'Commit']
                    self.assertEqual(status['records'], 2)
                    self.assertEqual(len(commits), 1)
                    self.assertIsNone(runtime.head['pending'])
                    self.assertIsNone(runtime.head['outbox'])
                    self.assertEqual(status['head'], runtime.head['head'])
                    content = runtime.state['messages'].content(commits[0])
                    with mesh.Node(service.config) as node:
                        packets = [i for i, summary in node.summaries().items()
                                   if summary['source'] == node.id and summary['export_id'] == content]
                        self.assertTrue(packets)
                        for ident in packets:
                            _, raw, _ = mesh.transit_check(node.transit(ident), node.network)
                            frame, payload = wire.inspect_frame(raw)
                            self.assertEqual(frame['export_id'], content)
                            runtime.with_json('bft-network-check', wire.decode_json(payload))
                    observations.append(status['records'])
                    return dict(errors=[])
                with patch.object(service.tcp, 'tick', side_effect=outgoing):
                    report = service.tick()
                    with patch.object(runtime, 'with_json', wraps=runtime.with_json) as native_calls:
                        service.tick()
                    # The real signer has already committed and only its own
                    # Commit is present. A second Prepare aggregate is unused;
                    # finalization still awaits the complete Commit quorum.
                    self.assertNotIn('bft-quorum', [call.args[0] for call in native_calls.call_args_list])
                self.assertEqual(observations, [2, 2])
                self.assertEqual(report['consensus']['native_records'], 2)
                self.assertEqual(native.call('status')['height'], 0)
                self.assertEqual(report['errors'], [])
            finally:
                if service is not None: service.close()
                campaign.cleanup()


if __name__ == '__main__':
    unittest.main()
