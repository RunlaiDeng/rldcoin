"""Request scheduling model only; Native certificates/signatures are not mocked authority."""
import copy
import unittest
import bft_tick_fixture as baseline

Candidate,_=baseline.methods(baseline.SOURCE,clock_override=baseline.clock)

class Fixture(baseline.Fixture):
    tick=Candidate.tick
    _tick=Candidate._tick
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.key='key-0'
        self.candidate_highs=[]
    def timeouts(self,round_number,count=3,duplicate=False,high=None):
        for n in range(count):
            vote=dict(context=copy.deepcopy(baseline.CONTEXT),round=round_number,high=copy.deepcopy(high),approval=dict(key='key-'+str(0 if duplicate else n)))
            self.messages.add(dict(EpochSigned=dict(message=dict(Timeout=vote),epochs=[])))
    def candidate(self,context,high=None):
        self.candidate_highs.append(high)
        return dict(mock_unsigned_candidate=True,high=high)
    def sign(self,request):
        if 'Propose' not in request:return super().sign(request)
        proposal=request['Propose'];n=proposal['round']
        self.requests.append(dict(kind='Propose',round=n))
        self.counts['bft-sign:Propose']+=1
        self.native_state.update(round=n,prepared=None,committed=None,proposed=True)
        self.native_records+=1;self.entered_at=baseline.clock.now

class CertifiedLeaderTests(unittest.TestCase):
    def test_complete_future_tc_can_request_local_leader_before_own_timer_catches_up(self):
        f=Fixture();f.timeouts(1)
        observed=f.tick()
        self.assertEqual(f.requests,[dict(kind='Propose',round=2)])
        self.assertEqual(observed['round'],2)
        self.assertEqual(f.native_records,1)
        self.assertEqual(f.counts['bft-timeout-certificate'],1)

    def test_two_votes_or_duplicate_signers_cannot_select_a_future_leader_round(self):
        for count,duplicate in ((2,False),(3,True)):
            f=Fixture();f.timeouts(1,count,duplicate)
            f.tick();self.assertEqual(f.requests,[])
            self.assertEqual(f.counts['bft-timeout-certificate'],0)

    def test_foreign_context_or_other_local_key_cannot_select_round(self):
        for foreign in (False,True):
            f=Fixture();f.timeouts(1)
            if foreign:
                for _,body,_,_ in f.messages.rows:body['EpochSigned']['message']['Timeout']['context']['epoch']='other'
            else:f.key='key-1'
            f.tick();self.assertEqual(f.requests,[])

    def test_current_complete_prepare_qc_keeps_two_signature_priority(self):
        f=Fixture();f.proposal(0);f.votes(0,'Prepare',3);f.timeouts(1)
        f.tick()
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Commit',round=0)])
        self.assertEqual(f.counts['bft-timeout-certificate'],0)

    def test_existing_future_proposal_takes_prepare_before_another_future_propose(self):
        f=Fixture();f.proposal(4);f.timeouts(1)
        f.tick();self.assertEqual(f.requests,[dict(kind='Prepare',round=4)])

    def test_highest_eligible_local_round_and_high_qc_value_go_to_native_candidate(self):
        f=Fixture();f.timeouts(1);f.timeouts(5,high=dict(round=2,value='retained-high-value'))
        f.tick();self.assertEqual(f.requests,[dict(kind='Propose',round=6)])
        self.assertEqual(f.candidate_highs,['retained-high-value'])
        self.assertEqual(f.counts['bft-timeout-certificate'],1)

    def test_native_certificate_refusal_or_missing_high_value_cannot_first_sign(self):
        for boundary in ('certificate','candidate'):
            f=Fixture();f.timeouts(1,high=dict(round=0,value='missing-proposal'))
            if boundary=='certificate':
                original=f.with_json
                def refused(action,payload):
                    if action=='bft-timeout-certificate':raise ValueError('mock native refusal')
                    return original(action,payload)
                f.with_json=refused
            else:
                def missing(context,high):raise ValueError('missing high proposal')
                f.candidate=missing
            with self.assertRaises(ValueError):f.tick()
            self.assertEqual(f.requests,[]);self.assertEqual(f.native_records,0)

    def test_keyless_stopped_and_exhausted_rounds_never_first_propose(self):
        for boundary in ('keyless','stopped','exhausted'):
            f=Fixture();f.timeouts(1)
            if boundary=='keyless':f.key_file=None
            elif boundary=='stopped':f.stop_height=10
            else:
                f=Fixture(round_number=31);f.timeouts(31)
            f.tick();self.assertEqual(f.requests,[])

    def test_no_repeat_and_future_certified_proposal_precedes_old_local_leadership(self):
        f=Fixture();f.timeouts(1);f.tick();f.tick()
        self.assertEqual(f.requests,[dict(kind='Propose',round=2)])
        f=Fixture();f.key='key-2';f.proposal(4)
        f.tick();self.assertEqual(f.requests,[dict(kind='Prepare',round=4)])
