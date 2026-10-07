"""Fresh-state same-round Prepare/Commit proposal; mock contract only."""
import json
import unittest
import bft_tick_fixture as baseline

Candidate, _ = baseline.methods(baseline.SOURCE, clock_override=baseline.clock)


class Fixture(baseline.Fixture):
    tick = Candidate.tick
    _tick = Candidate._tick


class CombinedCandidateTests(unittest.TestCase):
    def test_complete_prepare_qc_drives_prepare_commit_same_tick_before_future(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',3); f.proposal(4); f.votes(4,'Prepare',2)
        observations = [f.tick(), f.tick()]
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Commit',round=0),dict(kind='Prepare',round=4)])
        self.assertEqual(observations[0]['round'],0)
        self.assertEqual(observations[0]['native_records'],2)
        self.assertEqual(observations[1]['round'],4)
        self.assertEqual(f.counts['bft-status'],5)
        f.capture(self._testMethodName, observations)

    def test_incomplete_prepare_qc_retains_prepare_then_timeout(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',2)
        first = f.tick()
        baseline.clock.now = 22
        second = f.tick()
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Timeout',round=0)])
        self.assertEqual(f.counts['bft-quorum'],0)
        f.capture(self._testMethodName,[first,second])

    def test_delayed_prepare_qc_can_commit_on_later_tick(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',2)
        first = f.tick()
        vote = dict(context=baseline.copy.deepcopy(baseline.CONTEXT), round=0, phase='Prepare',
                    value=baseline.VALUE, approval=dict(key='key-2'))
        f.messages.add(dict(EpochSigned=dict(message=dict(Vote=vote), epochs=[])), baseline.VALUE)
        second = f.tick()
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Commit',round=0)])
        f.capture(self._testMethodName,[first,second])

    def test_delayed_prepare_qc_does_not_disable_valid_future_path(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',2); f.proposal(4)
        observations = [f.tick(),f.tick()]
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Prepare',round=4)])
        f.capture(self._testMethodName,observations)

    def test_fresh_prepare_mismatch_never_requests_commit(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',3)
        observe = f.signer_status
        def mismatch():
            value = observe()
            if f.counts['bft-status']==2:
                value['state']['prepared'] = None
            return value
        f.signer_status = mismatch
        observations = [f.tick()]
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0)])
        f.capture(self._testMethodName,observations)

    def test_fresh_context_round_or_absent_state_never_authorizes_commit(self):
        for drift in ('context','round','absent'):
            with self.subTest(drift=drift):
                f = Fixture(); f.proposal(0); f.votes(0,'Prepare',3)
                observe = f.signer_status
                def mismatch():
                    value = observe()
                    if f.counts['bft-status']>=2:
                        if drift=='context': value['state']['context']['epoch']='changed-era'
                        elif drift=='round': value['state']['round']=1; value['state']['prepared']=None
                        else: value['state']=None
                    return value
                f.signer_status = mismatch
                observation = f.tick()
                self.assertEqual(f.requests,[dict(kind='Prepare',round=0)])
                if drift in ('context','absent'):
                    self.assertIsNone(observation['round'])
                    self.assertIsNone(f.slot)
                f.capture(self._testMethodName+':'+drift,[observation])

    def test_read_only_role_never_requests_prepare_or_commit(self):
        f = Fixture(); f.proposal(0); f.votes(0,'Prepare',3); f.key_file=None
        observations = [f.tick()]
        self.assertEqual(f.requests,[])
        self.assertFalse(observations[0]['autonomous_signing_enabled'])
        f.capture(self._testMethodName,observations)

    def test_complete_old_round_certificate_still_installs_keyless(self):
        f = Fixture(round_number=4); f.proposal(0); f.votes(0,'Prepare',3); f.votes(0,'Commit',3); f.key_file=None
        call = f.with_json
        def native(action,payload):
            if action=='bft-certify':
                f.counts[action]+=1
                return dict(fake_certified=True)
            if action=='finalize':
                f.counts[action]+=1
                f.state['height']=11
                return dict(fake_finalized=True)
            return call(action,payload)
        f.with_json=native
        f.envelope=lambda body: body
        f.retain=lambda body,**kwargs: f.messages.add(body)
        f.retain_local_body=lambda body: f.retain(f.envelope(body),sync=False,local=True)
        observations = [f.tick()]
        self.assertEqual(f.requests,[])
        self.assertEqual(f.counts['bft-certify'],1)
        self.assertEqual(f.counts['finalize'],1)
        self.assertEqual(observations[0]['height'],11)
        self.assertTrue(observations[0]['explicit_stop_height_reached'])
        f.capture(self._testMethodName,observations)

    def test_distinct_proof_bodies_share_value_without_extra_signers(self):
        f = Fixture(); f.proposal(0,variants=4); f.votes(0,'Prepare',3)
        observations = [f.tick()]
        self.assertEqual(f.requests,[dict(kind='Prepare',round=0),dict(kind='Commit',round=0)])
        # Duplicate proof variants cannot finalize without Commit quorum.
        # Prepare aggregation remains exactly once for the signing request.
        self.assertEqual(f.counts['bft-quorum'],1)
        self.assertTrue(all(q['signers']==3 for q in f.qc_calls))
        f.capture(self._testMethodName,observations)


if __name__ == '__main__':unittest.main()
