"""Actual Runtime phase orchestration; fake Native grants no signing/value rights."""
import unittest
from regional_bft_node import ORIGIN_RUNTIME_FORMAT,FORMAT,carriage_batch
from types import SimpleNamespace
import inspect
import test_regional_bft_finalization_eligibility as baseline

class OwnVoteRuntime(baseline.RecordingRuntime):
    def __init__(self,prepare=2,commit=2,reject=None,keyless=False):
        super().__init__(prepare_count=prepare,commit_count=commit,reject=reject,
                         active_prepared=False,keyless=keyless)
        self.format=ORIGIN_RUNTIME_FORMAT;self.key='d'
        self.prepare_keys=set('abc'[:prepare]);self.commit_keys=set('abc'[:commit])
    def signed(self,context,round_number,kind,phase=None,value=None):
        if kind=='Vote' and round_number==0:
            keys=self.prepare_keys if phase=='Prepare' else self.commit_keys
            return [({'approval':{'key':k},'phase':phase},self.value) for k in sorted(keys)]
        return super().signed(context,round_number,kind,phase,value)
    def _try_prepare(self,proposal):
        self.events.append(('native-prepare',None))
        if self.reject==('native-prepare',None):raise ValueError('Native refused Prepare')
        self.prepare_keys.add(self.key);self.active['prepared']=self.value
        return True
    def sign(self,request):
        super().sign(request)
        if 'Commit' in request:
            self.commit_keys.add(self.key);self.active['committed']=self.value

class OwnQuorumReleaseTests(unittest.TestCase):
    def test_own_third_prepare_and_commit_finish_native_certificate_this_tick(self):
        runtime=OwnVoteRuntime();runtime._tick()
        self.assertIn(('native-sign','Commit'),runtime.events)
        self.assertIn(('bft-certify',None),runtime.events)
        self.assertIn(('finalize',None),runtime.events)
        self.assertEqual(runtime.state['height'],14)
        self.assertEqual(runtime.events.count(('finalize',None)),1)
        self.assertLess(runtime.events.index(('native-prepare',None)),runtime.events.index(('native-sign','Commit')))
        self.assertLess(runtime.events.index(('native-sign','Commit')),runtime.events.index(('bft-certify',None)))
    def test_third_own_commit_requires_both_native_quorums_after_signing(self):
        runtime=OwnVoteRuntime(prepare=3);runtime._tick()
        self.assertIn(('finalize',None),runtime.events)
        start=runtime.events.index(('native-sign','Commit'))
        self.assertEqual(runtime.events[start+1:start+5],
                         [('bft-quorum','Commit'),('bft-quorum','Prepare'),('bft-certify',None),('finalize',None)])
    def test_incomplete_commit_stays_retained_without_finality(self):
        runtime=OwnVoteRuntime(commit=1);runtime._tick()
        self.assertIn(('native-sign','Commit'),runtime.events)
        self.assertNotIn(('bft-certify',None),runtime.events)
        self.assertNotIn(('finalize',None),runtime.events)
    def test_missing_prepare_cannot_commit_or_finalize(self):
        runtime=OwnVoteRuntime(prepare=1);runtime._tick()
        self.assertNotIn(('native-sign','Commit'),runtime.events)
        self.assertNotIn(('finalize',None),runtime.events)
    def test_native_refusals_preserve_signed_phase_without_finality_or_retry(self):
        for refusal in [('native-prepare',None),('bft-quorum','Prepare'),('native-sign','Commit'),
                        ('bft-quorum','Commit'),('bft-certify',None)]:
            with self.subTest(refusal=refusal):
                runtime=OwnVoteRuntime(reject=refusal)
                with self.assertRaises(ValueError):runtime._tick()
                self.assertNotIn(('finalize',None),runtime.events)
                self.assertLessEqual(runtime.events.count(('native-sign','Commit')),1)
    def test_keyless_and_legacy_never_adopt_new_phase_release(self):
        runtime=OwnVoteRuntime(keyless=True);runtime._tick()
        self.assertEqual(runtime.events,[('broadcast',None)])
        runtime=OwnVoteRuntime();runtime.format=FORMAT;runtime._tick()
        self.assertNotIn(('native-sign','Commit'),runtime.events)
        self.assertNotIn(('finalize',None),runtime.events)

class PrepareDependencyCarriageTests(unittest.TestCase):
    def choose(self,messages,pending,height,cursor):
        options={'prepare_first':True} if 'prepare_first' in inspect.signature(carriage_batch).parameters else {}
        return carriage_batch(messages,pending,height,cursor,**options)
    def fixture(self):
        def vote(phase,value='v'):
            return {'Signed':{'Vote':dict(context={'parent_height':0},round=0,value=value,phase=phase,
                approval={'key':'own','signature':'modeled-only'})}}
        rows=[('c',vote('Commit'),'v',True),('p',vote('Prepare'),'v',True)]
        messages=SimpleNamespace(bodies=lambda:iter(rows))
        pending=[(ident,ident,peer) for ident in ('c','p') for peer in ('a','b','c')]
        return messages,pending,rows
    def test_same_unit_commit_cannot_displace_its_waiting_same_peer_prepare(self):
        messages,pending,_=self.fixture()
        selected=self.choose(messages,pending,0,0)
        self.assertEqual(len(selected),4)
        self.assertEqual({p[2] for p in selected if p[1]=='p'},{'a','b','c'})
        self.assertEqual(len([p for p in selected if p[1]=='c']),1)
    def test_history_places_and_unmatched_intents_are_exact(self):
        messages,pending,rows=self.fixture()
        rows.append(('h',{'Finalized':{'statement':{'height':9}}},'history',True))
        pending.extend([('h','h',peer) for peer in ('a','b','c')])
        original=carriage_batch(messages,pending,0,0)
        selected=self.choose(messages,pending,0,0)
        self.assertEqual([p for p in original if p[1]=='h'],[p for p in selected if p[1]=='h'])
        rows[1][1]['Signed']['Vote']['value']='different'
        self.assertEqual(self.choose(messages,pending,0,0),original)
    def test_prepared_or_absent_same_peer_dependency_cannot_suppress_commit(self):
        messages,pending,_=self.fixture();pending=[p for p in pending if p[1]!='p' or p[2]=='a']
        self.assertEqual(self.choose(messages,pending,0,0),
                         carriage_batch(messages,pending,0,0))
