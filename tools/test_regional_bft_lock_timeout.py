"""Actual Native lock refusal and timeout carriage; no mocked vote authority."""
import copy
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import interstellar_mesh as mesh
import test_regional_bft_node as baseline
from regional_bft_node import Runtime
from regional_contact_node import Native
from regional_contact_campaign import public


LOCK_REFUSAL='native rejected: regional candidate rejected: proposal violates durable prepared lock without a newer valid prepare QC'


class NativeLockTimeoutTests(unittest.TestCase):
    def setUp(self):
        baseline.CallerRecoveryTests.setUp(self)
        self.native=Native(baseline.BINARY,self.c.node('earth',3),public(1),self.c.currency)
        self.transport=mesh.load(self.c.root/'mesh-config-3.json',65536)
        self.path=self.c.root/'bft-config-3.json'

    open=baseline.CallerRecoveryTests.open

    def tearDown(self):
        if self.runtime:self.runtime.close()
        self.c.cleanup()
        result=self._outcome.result
        if any(test is self for test,_ in result.failures+result.errors):self.temp._finalizer.detach()
        else:self.temp.cleanup()

    def retain(self,message):
        self.runtime.retain(self.runtime.envelope({'Signed':message}))

    def locked(self):
        r=self.open();context=self.native.call('bft-context')['context']
        snapshot=self.c.cli('earth',0,'bft-candidate','--miner',public(10),
                            '--commands',self.c.file('lock-empty',[]))
        old=self.c.sign('earth',0,{'Propose':{'round':0,'snapshot':snapshot,'timeout':None}})['message']['Proposal']
        self.retain({'Proposal':old});r.sign({'Prepare':old})
        votes=[self.native.call('bft-retained-messages','--signer-dir',r.signer)[-1]['Vote']]
        for n in (0,1):
            vote=self.c.sign('earth',n,{'Prepare':old})['message'];self.retain(vote);votes.append(vote['Vote'])
        votes.sort(key=lambda v:v['approval']['key']);qc=r.with_json('bft-quorum',votes)
        r.sign({'Commit':{'proposal':old,'prepared':qc}})
        timeouts=[]
        for n in (0,1,2):
            message=self.c.sign('earth',n,{'Timeout':{'context':context,'round':0}})['message']
            self.retain(message);timeouts.append(message['Timeout'])
        tc=r.with_json('bft-timeout-certificate',sorted(timeouts,key=lambda v:v['approval']['key']))
        different=self.c.cli('earth',1,'bft-candidate','--miner',public(11),
                             '--commands',self.c.file('different-empty',[]))
        later=self.c.sign('earth',1,{'Propose':{'round':1,'snapshot':different,'timeout':tc}})['message']['Proposal']
        self.retain({'Proposal':later})
        return r,context,old,later,qc

    def test_rejected_future_prepare_keeps_lock_and_times_out_with_full_four_vote_qc(self):
        r,context,old,later,qc=self.locked()
        self.assertNotEqual(old['snapshot']['statement'],later['snapshot']['statement'])
        # Native signer journal layout is independently observed via its head;
        # the whole private signer inventory is checked around the refusal.
        from verify_regional_bft_sustained import files
        before=files(self.c.signer('earth',3));head=r.head['head'];caller=r.head_path.read_bytes()
        self.assertFalse(r._try_prepare(later))
        self.assertEqual(files(self.c.signer('earth',3)),before)
        self.assertEqual(r.head['head'],head);self.assertEqual(r.head_path.read_bytes(),caller)
        self.assertIsNone(r.head['pending']);self.assertIsNone(r.head['outbox'])
        self.assertEqual(r.signer_status()['state']['round'],0)
        records=r.signer_status()['records'];r.slot=(mesh.digest(context),0);r.entered_at=time.monotonic()-21
        observed=r.tick();self.assertEqual(observed['round'],1)
        self.assertEqual(r.signer_status()['records'],records+1)
        timeout=self.native.call('bft-retained-messages','--signer-dir',r.signer)[-1]['Timeout']
        self.assertEqual(timeout['round'],0);self.assertEqual(timeout['high'],qc)
        full=r.timeout_certificate(context,0)
        self.assertEqual(len(full['votes']),4)
        self.assertEqual([v['approval']['key'] for v in full['votes']],sorted(r.peers))
        self.assertEqual([v['high'] for v in full['votes'] if v['high'] is not None],[qc])
        self.assertEqual(self.native.call('status')['height'],0)

    def test_rejected_current_prepare_can_release_the_original_round_timeout(self):
        r,context,_,later,qc=self.locked();r.sign({'Timeout':{'context':context,'round':0}})
        records=r.signer_status()['records'];r.slot=(mesh.digest(context),1);r.entered_at=time.monotonic()-41
        observed=r.tick();self.assertEqual(observed['round'],2)
        self.assertEqual(r.signer_status()['records'],records+1)
        timeout=self.native.call('bft-retained-messages','--signer-dir',r.signer)[-1]['Timeout']
        self.assertEqual(timeout['round'],1);self.assertEqual(timeout['high'],qc)
        self.assertIsNone(r.head['pending']);self.assertIsNone(r.head['outbox'])
        self.assertEqual(self.native.call('status')['height'],0)


class RefusalBoundaryTests(unittest.TestCase):
    def fixture(self,error=LOCK_REFUSAL):
        request={'Prepare':{'round':1}}
        r=SimpleNamespace(head={'head':'separate-head','pending':copy.deepcopy(request),'outbox':None},
                          sign=Mock(side_effect=ValueError(error)))
        def reconcile():r.head=dict(r.head,pending=None)
        r.reconcile=Mock(side_effect=reconcile)
        return r,request

    def test_other_native_errors_never_clear_pending_or_continue(self):
        for error in ('native rejected: invalid signature',LOCK_REFUSAL+'; altered','local timeout'):
            r,request=self.fixture(error)
            with self.assertRaises(ValueError):Runtime._try_prepare(r,request['Prepare'])
            self.assertEqual(r.head['pending'],request);r.reconcile.assert_not_called()

    def test_wrong_review_and_recovered_response_do_not_grant_timeout_permission(self):
        r,request=self.fixture();r.head['pending']={'Prepare':{'round':2}}
        with self.assertRaises(ValueError):Runtime._try_prepare(r,request['Prepare'])
        r.reconcile.assert_not_called()
        r,request=self.fixture()
        def recovered():r.head=dict(r.head,head='new-head',pending=None,outbox={'Vote':{'retained':True}})
        r.reconcile.side_effect=recovered
        with self.assertRaises(ValueError):Runtime._try_prepare(r,request['Prepare'])
        self.assertEqual(r.head['head'],'new-head');self.assertIsNotNone(r.head['outbox'])


if __name__=='__main__':unittest.main()
