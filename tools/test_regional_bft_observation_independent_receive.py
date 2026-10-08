"""Missing optional contact projection cannot substitute for BFT Native checks."""
from contextlib import nullcontext
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import interstellar_transfer as wire
from regional_bft_node import ORIGIN_RUNTIME_FORMAT, FORMAT
from regional_contact_node import NativeRefusal
import test_regional_bft_receive_deferred as deferred_fixture

BUSY=deferred_fixture.BUSY


class IndependentReceiveTests(unittest.TestCase):
    def fixture(self, error=None):
        helper=deferred_fixture.ContactApplyDeferredTests();service,pid,_=helper.service(None)
        payload=wire.canonical(dict(format='RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3',currency='a'*64,
            region=service.region,evidence={'snapshots':[]},origins=[],body={'Signed':{'modeled':True}}))
        raw=wire.make_frame('regional-bft',service.region,service.region,hashlib.sha256(payload).hexdigest(),payload)
        original=service.native.call
        service.native.call=Mock(side_effect=[NativeRefusal('contact-observation',1,BUSY),
                                             original('contact-observation')])
        service.bft=SimpleNamespace(format=ORIGIN_RUNTIME_FORMAT,joint=None,
            state={'messages':{}},receive_many=Mock(side_effect=error),tick=lambda:dict(modeled=True))
        service.contact_trace=SimpleNamespace(native_stage=Mock(),native_received=Mock(),snapshot=lambda:{})
        node=SimpleNamespace(id='c'*64,network='a'*64,state={'adverts':{}},
            tick=lambda **_:dict(errors=[]),summaries=lambda:{pid:dict(destination='c'*64,
            kind='regional-bft',export_id='f'*64)},receipts=lambda:{pid:{}},transit=lambda _: {})
        service.selection_node=lambda:nullcontext(node)
        return helper,service,pid,raw

    def test_selected_complete_bft_attempts_own_native_validation_without_contact_projection(self):
        helper,service,pid,raw=self.fixture();report=helper.tick(service,raw)
        service.bft.receive_many.assert_called_once_with([raw])
        self.assertEqual(service.bft_seen,{'unchanged',pid})
        self.assertEqual(report['applied'],[]);self.assertEqual(report['rejected'],[])
        self.assertEqual(report['errors'],['native rejected: '+BUSY])
        service.native.apply.assert_not_called()
        self.assertEqual(service.native.call.call_count,2)
        service.contact_trace.native_received.assert_called_once_with(pid,raw)

    def test_independent_bft_lock_refusal_grants_no_seen_or_receipt_credit(self):
        helper,service,_,raw=self.fixture(NativeRefusal('bft-origin-network-receive-batch',1,BUSY))
        report=helper.tick(service,raw);service.bft.receive_many.assert_called_once_with([raw])
        self.assertEqual(service.bft_seen,{'unchanged'});self.assertEqual(len(report['deferred']),1)
        self.assertEqual(report['rejected'],[]);service.contact_trace.native_received.assert_not_called()
        self.assertFalse(report['deferred'][0]['ledger_acceptance_known'])
        self.assertFalse(report['deferred'][0]['signing_authority'])

    def test_missing_projection_cannot_hide_later_invalid_complete_native_proof(self):
        helper,service,_,raw=self.fixture(NativeRefusal('bft-origin-network-receive-batch',1,'invalid later proof'))
        report=helper.tick(service,raw);service.bft.receive_many.assert_called_once_with([raw])
        self.assertEqual(service.bft_seen,{'unchanged'});self.assertEqual(len(report['rejected']),1)
        self.assertEqual(report['deferred'],[]);service.contact_trace.native_received.assert_not_called()

    def test_corrupt_frame_still_refuses_before_complete_native_call(self):
        helper,service,_,raw=self.fixture();report=helper.tick(service,raw+b'corrupt')
        service.bft.receive_many.assert_not_called();self.assertEqual(service.bft_seen,{'unchanged'})
        self.assertEqual(len(report['rejected']),1);service.contact_trace.native_received.assert_not_called()

    def test_legacy_and_joint_profiles_do_not_adopt_missing_projection_path(self):
        for legacy,joint in ((FORMAT,None),(ORIGIN_RUNTIME_FORMAT,object())):
            helper,service,_,raw=self.fixture();service.bft.format=legacy;service.bft.joint=joint
            report=helper.tick(service,raw);service.bft.receive_many.assert_not_called()
            self.assertFalse(report['native_observation_available'])
            self.assertEqual(service.bft_seen,{'unchanged'});self.assertEqual(service.native.call.call_count,1)

if __name__=='__main__':unittest.main()
