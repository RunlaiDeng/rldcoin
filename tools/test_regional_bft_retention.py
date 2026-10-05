"""Exact retention codec plus real native custody/restart refusal boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages, pack_state, unpack_state, verify_stopped_state, retained_body_present
from regional_bft_node import Runtime
from regional_bft_network_campaign import Campaign
from regional_contact_campaign import public
from regional_contact_node import Native

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()


def envelope(n, snapshots):
    # Codec fixtures have no authorization. Native integration below uses actual
    # admitted keys, certificates and Rust checks instead of these artificial bodies.
    return {'format':'RLD-REGIONAL-BFT-NETWORK-V2','currency':'1'*64,'region':'2'*64,
            'body':{'codec_fixture':n},'evidence':{'snapshots':snapshots}}


def state(messages):
    return {'format':'RLD-REGIONAL-BFT-NODE-V1','binding':{},'messages':messages,
            'height':0,'tip':'2'*64,'snapshot_cache':[],'cursor':0}


class ExactStorageTests(unittest.TestCase):
    def test_complete_bytes_order_and_repeated_references_survive_shared_roundtrip(self):
        a={'statement':{'height':1},'approvals':['a'],'payload':'x'*4000}
        b=dict(a,approvals=['b'])
        messages=Messages();originals={}
        for n in range(32):
            e=envelope(n,[a,b,a]);ident=mesh.digest(e['body']);originals[ident]=wire.canonical(e)
            messages=messages.append(ident,e,None,n%2==0)
        packed=pack_state(state(messages));restored=unpack_state(wire.decode_json(wire.canonical(packed)))['messages']
        self.assertEqual(len(packed['snapshots']),2)
        self.assertLess(len(wire.canonical(packed)),sum(map(len,originals.values()))//4)
        for ident,raw in originals.items():self.assertEqual(restored.payload(ident),raw)
        self.assertEqual(dict(messages),dict(restored))

    def test_mutating_inputs_or_returned_envelopes_cannot_change_retained_bytes(self):
        e=envelope(1,[{'statement':{'height':1},'approvals':['a']}]);ident=mesh.digest(e['body'])
        messages=Messages().append(ident,e,None,False);before=messages.payload(ident)
        e['evidence']['snapshots'][0]['approvals'][0]='forged'
        exposed=messages[ident];exposed['envelope']['evidence']['snapshots'][0]['approvals'][0]='forged'
        exposed['envelope']['body']['codec_fixture']=999
        self.assertEqual(messages.payload(ident),before)
        with self.assertRaises(TypeError):messages._snapshots['0'*64]=b'{}'
        local=messages.with_local(ident)
        self.assertTrue(local[ident]['local']);self.assertFalse(messages[ident]['local'])
        self.assertEqual(local.payload(ident),before)

    def test_index_substitution_missing_bytes_orphan_and_metadata_are_refused(self):
        e=envelope(1,[{'statement':{'height':1},'approvals':['a']}]);ident=mesh.digest(e['body'])
        packed=pack_state(state(Messages().append(ident,e,None,False)))
        mutations={
            'missing':lambda p:p['snapshots'].clear(),
            'altered':lambda p:next(iter(p['snapshots'].values()))['approvals'].append('forged'),
            'orphan':lambda p:p['snapshots'].update({hashlib.sha256(b'{}').hexdigest():{}}),
            'hash':lambda p:p['runtime']['messages'][ident].update(sha256='0'*64),
            'size':lambda p:p['runtime']['messages'][ident].update(size_bytes=wire.MAX_PAYLOAD+1),
            'wrong_order':lambda p:p['runtime']['messages'][ident]['refs'].append(next(iter(p['snapshots']))),
            'oversized_refs':lambda p:p['runtime']['messages'][ident].update(refs=[next(iter(p['snapshots']))]*65),
            'extra_field':lambda p:p['runtime']['messages'][ident].update(authority=True),
            'boolean_size':lambda p:p['runtime']['messages'][ident].update(size_bytes=True),
        }
        for name,alter in mutations.items():
            with self.subTest(name=name):
                damaged=copy.deepcopy(packed);alter(damaged)
                with self.assertRaises(ValueError):unpack_state(damaged)

    def test_expansion_bound_is_checked_before_decoding_shared_snapshot(self):
        a={'payload':'x'*(wire.MAX_PAYLOAD//2)};e=envelope(1,[a]);ident=mesh.digest(e['body'])
        packed=pack_state(state(Messages().append(ident,e,None,False)))
        packed['runtime']['messages'][ident]['refs']*=3
        with patch('regional_bft_retention.wire.decode_json',wraps=wire.decode_json) as decode:
            with self.assertRaisesRegex(ValueError,'expansion capacity'):unpack_state(packed)
            self.assertTrue(all(len(call.args[0])<wire.MAX_PAYLOAD//2 for call in decode.call_args_list))

    def test_512_message_limit_refuses_without_pruning_retained_snapshots(self):
        messages=Messages()
        for n in range(512):
            e=envelope(n,[{'retained':'exact'}]);messages=messages.append(mesh.digest(e['body']),e,None,False)
        before=wire.canonical(pack_state(state(messages)));e=envelope(513,[{'different':'exact'}])
        with self.assertRaisesRegex(ValueError,'capacity'):messages.append(mesh.digest(e['body']),e,None,False)
        self.assertEqual(wire.canonical(pack_state(state(messages))),before)
        self.assertEqual(len(unpack_state(wire.decode_json(before))['messages']),512)

    def test_legacy_inline_format_refuses_without_automatic_conversion(self):
        with self.assertRaisesRegex(ValueError,'preserve old fixture'):unpack_state(state({}))

    def test_campaign_observer_reads_exact_body_from_wrapper_and_refuses_changed_payload(self):
        e=envelope(1,[{'retained':'exact'}]);ident=mesh.digest(e['body'])
        with tempfile.TemporaryDirectory() as scratch:
            path=Path(scratch)/'state.json';packed=pack_state(state(Messages().append(ident,e,None,False)))
            path.write_bytes(wire.canonical(packed))
            self.assertTrue(retained_body_present(path,e['body']))
            self.assertFalse(retained_body_present(path,{'codec_fixture':2}))
            next(iter(packed['snapshots'].values()))['retained']='substituted'
            path.write_bytes(wire.canonical(packed))
            with self.assertRaises(ValueError):retained_body_present(path,e['body'])


class StoppedBatchContractTests(unittest.TestCase):
    """Response/budget plumbing only; these fake rows grant no native authority."""
    def run_codec(self, count=5, padding=0, alter=None):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch).resolve();directory=root/'retention';directory.mkdir()
            messages=Messages()
            for n in range(count):
                e=envelope(n,[]);e['body']['padding']='x'*padding
                messages=messages.append(mesh.digest(e['body']),e,format(n,'064x'),False)
            path=directory/'state.json'
            mesh.atomic(path,pack_state(dict(state(messages),binding={'currency':'1'*64,'region':'2'*64,'key':'3'*64})))
            before=path.read_bytes();calls=[]
            class FakeNative:
                currency='1'*64
                def call(self, action, flag, file):
                    self_outer.assertEqual((action,flag),('bft-network-check-batch','--file'))
                    raw=Path(file).read_bytes();rows=wire.decode_json(raw);calls.append((len(rows),len(raw)))
                    response={'format':'RLD-BFT-COLD-NETWORK-CHECK-V1','currency':self.currency,'region':'2'*64,
                              'request_sha256':hashlib.sha256(raw).hexdigest(),'verified':True,
                              'ledger_changed':False,'signing_authority':False,
                              'results':[{'message_id':'4'*64,'value':format(row['body']['codec_fixture'],'064x')} for row in rows]}
                    if alter:alter(response,len(calls))
                    return response
            self_outer=self
            try:
                result=verify_stopped_state(FakeNative(),{'state':str(directory),'format':'RLD-REGIONAL-BFT-NODE-V1','key':'3'*64},
                                            {'region':'2'*64,'height':0,'tip':'2'*64},root)
                return result,calls
            finally:self.assertEqual(path.read_bytes(),before)

    def test_ordered_four_slot_batches_and_last_remainder(self):
        result,calls=self.run_codec()
        self.assertEqual([n for n,_ in calls],[4,1])
        self.assertEqual(result['messages_authenticated'],5)
        self.assertEqual(result['native_authentication_batches'],2)

    def test_total_byte_limit_splits_before_four_and_keeps_every_complete_envelope(self):
        result,calls=self.run_codec(count=3,padding=3*1024*1024-1024)
        self.assertEqual([n for n,_ in calls],[2,1])
        self.assertTrue(all(size<=8*1024*1024 for _,size in calls))
        self.assertEqual(result['messages_authenticated'],3)

    def test_wrong_request_domain_order_count_or_authority_refuses_unchanged(self):
        changes=[lambda d:d.update(request_sha256='0'*64),lambda d:d.update(currency='0'*64),
                 lambda d:d.update(region='0'*64),lambda d:d.update(verified=1),
                 lambda d:d.update(ledger_changed=True),lambda d:d.update(signing_authority=True),
                 lambda d:d['results'].reverse(),lambda d:d['results'].pop()]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):
                self.run_codec(alter=lambda d,n:change(d))

    def test_later_batch_native_refusal_returns_no_success_and_preserves_state(self):
        def refusal(response,n):
            if n==2:raise ValueError('native rejected later exact envelope')
        with self.assertRaisesRegex(ValueError,'native rejected later'):
            self.run_codec(alter=refusal)


class NativeRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-bft-exact-retention-')
        self.c=Campaign(BINARY,Path(self.temp.name).resolve()/'fixture')
        self.native=Native(BINARY,self.c.node('earth',0),public(1),self.c.currency)
        self.transport=mesh.load(self.c.root/'mesh-config-0.json',65536)
        self.path=self.c.root/'bft-config-0.json';self.runtime=None

    def tearDown(self):
        if self.runtime:self.runtime.close()
        self.c.cleanup();self.temp.cleanup()

    def open(self):
        self.runtime=Runtime(self.native,self.transport,self.path);return self.runtime

    def request(self,n):
        return {'Timeout':{'context':self.native.call('bft-context')['context'],'round':n}}

    def recover_write_failure(self,after_replace):
        runtime=self.open();runtime.sign(self.request(0))
        before=runtime.state_path.read_bytes();native_before=runtime.signer_status()['records'];atomic=mesh.atomic
        def fail(path,value):
            if path==runtime.state_path:
                if after_replace:atomic(path,value)
                raise OSError('injected retention persistence boundary')
            return atomic(path,value)
        with patch.object(mesh,'atomic',side_effect=fail),self.assertRaises(OSError):runtime.sign(self.request(1))
        self.assertTrue(runtime.failed);self.assertIsNotNone(runtime.head['outbox'])
        exact=runtime.head['outbox'];head=runtime.head['head']
        self.assertEqual(runtime.signer_status()['records'],native_before+1)
        if not after_replace:self.assertEqual(runtime.state_path.read_bytes(),before)
        runtime.key_file.unlink();runtime.close();self.runtime=None
        restored=self.open()
        self.assertEqual(restored.head['head'],head);self.assertIsNone(restored.head['outbox'])
        self.assertEqual(restored.signer_status()['records'],native_before+1)
        self.assertEqual(restored.state['messages'][mesh.digest({'Signed':exact})]['envelope']['body'],{'Signed':exact})
        self.assertEqual(len(restored.state['messages']),2)
        restored.tick();self.assertEqual(restored.signer_status()['records'],native_before+1)

    def test_failed_write_before_replace_recovers_exact_outbox_without_first_sign(self):
        self.recover_write_failure(False)

    def test_failed_directory_ack_after_replace_recovers_exact_durable_message(self):
        self.recover_write_failure(True)

    def test_state_byte_refusal_preserves_old_retention_and_pending_native_response(self):
        runtime=self.open();runtime.sign(self.request(0));before=runtime.state_path.read_bytes()
        with patch('regional_bft_node.MAX_STATE',len(before)),self.assertRaisesRegex(ValueError,'capacity'):
            runtime.sign(self.request(1))
        self.assertEqual(runtime.state_path.read_bytes(),before)
        self.assertIsNotNone(runtime.head['outbox']);self.assertEqual(runtime.signer_status()['records'],2)
        runtime.key_file.unlink();runtime.close();self.runtime=None
        restored=self.open();self.assertEqual(restored.signer_status()['records'],2)
        self.assertEqual(len(restored.state['messages']),2);self.assertIsNone(restored.head['outbox'])

    def retain_actual_certificate(self,runtime):
        certificate=self.c.checkpoint('earth')
        proof=self.c.cli('earth',1,'proof')
        runtime.retain(runtime.with_json('bft-network-pack',{'format':'RLD-REGIONAL-BFT-NETWORK-V2','currency':self.c.currency,
                        'region':self.c.regions['earth'],'evidence':proof,'body':{'Finalized':certificate}}),local=True)
        return certificate,proof

    def test_shared_real_certificates_restart_keyless_and_preserve_exact_carriage(self):
        runtime=self.open();_,proof=self.retain_actual_certificate(runtime)
        for n in (1,2,3):
            for message in self.c.cli('earth',n,'bft-retained-messages','--signer-dir',self.c.signer('earth',n)):
                runtime.retain(runtime.with_json('bft-network-pack',{'format':'RLD-REGIONAL-BFT-NETWORK-V2','currency':self.c.currency,
                                'region':runtime.region,'evidence':proof,'body':{'Signed':message}}),local=True)
        payloads={i:runtime.state['messages'].payload(i) for i in runtime.state['messages']}
        disk=runtime.state_path.read_bytes();packed=wire.decode_json(disk)
        self.assertEqual(len(packed['snapshots']),1)
        cold=verify_stopped_state(self.native,mesh.load(self.path,65536),self.native.call('status'),self.c.root)
        self.assertEqual(cold['messages_authenticated'],len(payloads))
        self.assertTrue(cold['full_native_authentication'])
        inline=dict(runtime.state,messages=dict(runtime.state['messages']))
        self.assertGreater(len(wire.canonical(inline)),len(disk)*2)
        head=runtime.head['head'];records=runtime.signer_status()['records']
        runtime.key_file.unlink();runtime.close();self.runtime=None
        restored=self.open()
        for ident,payload in payloads.items():self.assertEqual(restored.state['messages'].payload(ident),payload)
        self.assertEqual(restored.head['head'],head);self.assertEqual(restored.signer_status()['records'],records)
        restored.tick();self.assertEqual(restored.signer_status()['records'],records)
        self.assertEqual(self.native.call('status')['height'],1)

    def test_self_consistent_hashes_do_not_authorize_a_forged_native_certificate(self):
        runtime=self.open();self.retain_actual_certificate(runtime)
        messages=Messages()
        for ident,item in runtime.state['messages'].items():
            e=copy.deepcopy(item['envelope'])
            if e['evidence']['snapshots']:
                approval=e['evidence']['snapshots'][0]['snapshot']['bft']['committed']['votes'][0]['approval']
                approval['signature']=('0' if approval['signature'][0]!='0' else '1')+approval['signature'][1:]
            messages=messages.append(ident,e,item['value'],item['local'])
        mesh.atomic(runtime.state_path,pack_state(dict(runtime.state,messages=messages)))
        paths=(runtime.state_path,runtime.head_path,runtime.signer/'bft.json',self.native.ledger/'journal.json')
        before=[p.read_bytes() for p in paths];runtime.close();self.runtime=None
        with self.assertRaises(ValueError):
            verify_stopped_state(self.native,mesh.load(self.path,65536),self.native.call('status'),self.c.root)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual([p.read_bytes() for p in paths],before)

    def test_legacy_runtime_state_refuses_without_changing_private_custody(self):
        runtime=self.open();runtime.sign(self.request(0))
        mesh.atomic(runtime.state_path,dict(runtime.state,messages=dict(runtime.state['messages'])))
        paths=(runtime.state_path,runtime.head_path,runtime.signer/'bft.json',self.native.ledger/'journal.json')
        before=[p.read_bytes() for p in paths];runtime.close();self.runtime=None
        with self.assertRaisesRegex(ValueError,'preserve old fixture'):self.open()
        self.assertEqual([p.read_bytes() for p in paths],before)


if __name__=='__main__':unittest.main()
