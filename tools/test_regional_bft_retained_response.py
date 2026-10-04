"""Mechanical startup reuse tests; fake boundaries are not Native qualification."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_retained_response as reuse
from regional_bft_retention import Messages


def signed(body):return body.get('Signed',body.get('EpochSigned',{}).get('message',{}))


class ResponseReuseTests(unittest.TestCase):
    def setUp(self):
        self.message={'Timeout':{'fixture_signature':'exact'}}
        self.runtime=SimpleNamespace(_retained_native_authenticated=True,
            state={'binding':{'fixture':True},'messages':Messages()},region='2'*64,
            native=SimpleNamespace(currency='1'*64,authority='3'*64,ledger=Path('/private-fixture')))
        self.saved=[]
        def save(state):self.runtime.state=state;self.saved.append(state)
        self.runtime.save=save;self.index=reuse.RetainedResponses(self.runtime,signed)
    def append(self,message=None,epochs=(),local=True):
        body={'EpochSigned':{'message':message or self.message,'epochs':list(epochs)}}
        e=dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency='1'*64,region='2'*64,body=body,evidence={'snapshots':[]})
        ident=mesh.digest(body);self.runtime.state['messages']=self.runtime.state['messages'].append(ident,e,None,local);return ident
    def test_exact_native_response_reuses_existing_complete_variants_without_rewrapping(self):
        first=self.append();second=self.append(epochs=({'fixture':1},))
        before={i:self.runtime.state['messages'].payload(i) for i in (first,second)}
        self.assertTrue(self.index.reuse(copy.deepcopy(self.message)))
        self.assertEqual({i:self.runtime.state['messages'].payload(i) for i in before},before)
        self.assertFalse(self.saved)
    def test_only_local_carriage_flag_changes_and_immutable_source_rebinds(self):
        ident=self.append(local=False);before=self.runtime.state['messages'].payload(ident)
        self.assertTrue(self.index.reuse(self.message));self.assertEqual(len(self.saved),1)
        self.assertTrue(self.runtime.state['messages'].record(ident)['local'])
        self.assertEqual(self.runtime.state['messages'].payload(ident),before)
        self.assertTrue(self.index.reuse(self.message));self.assertEqual(len(self.saved),1)
        self.assertIs(self.index.source,self.runtime.state['messages'])
    def test_digest_collision_cannot_choose_a_different_native_response(self):
        wrong={'Timeout':{'fixture_signature':'different'}}
        with patch.object(reuse,'_response_id',return_value='0'*64):
            bad=self.append(wrong,local=False);good=self.append(local=False)
            self.assertTrue(self.index.reuse(self.message))
        self.assertFalse(self.runtime.state['messages'].record(bad)['local'])
        self.assertTrue(self.runtime.state['messages'].record(good)['local'])
    def test_existing_local_variant_prevents_promoting_another_complete_variant(self):
        first=self.append(local=False);self.append(epochs=({'fixture':1},),local=True)
        self.assertTrue(self.index.reuse(self.message));self.assertFalse(self.saved)
        self.assertFalse(self.runtime.state['messages'].record(first)['local'])
    def test_missing_response_and_fence_keep_full_existing_construction_path(self):
        self.append();self.assertFalse(self.index.reuse({'Timeout':{'fixture_signature':'changed'}}))
        self.assertFalse(self.index.reuse({'EpochApproval':{'fixture':'fence'}}));self.assertFalse(self.saved)
    def test_unchecked_cold_state_refuses_and_tighter_capacity_falls_back_without_mutation(self):
        self.append(local=False);self.runtime._retained_native_authenticated=False
        with self.assertRaisesRegex(ValueError,'complete Native cold'):self.index.reuse(self.message)
        self.runtime._retained_native_authenticated=True
        self.assertTrue(self.index.reuse(self.message))
        self.saved.clear()
        self.assertTrue(self.index.reuse(self.message))
        with patch.object(reuse,'MAX_INDEX_BYTES',1):self.assertFalse(self.index.reuse(self.message))
        self.assertFalse(self.saved);self.assertIsNone(self.index.index)


if __name__=='__main__':unittest.main()
