"""Success body, ownership, deadline and private/public terminal counterexamples."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from regional_paged_fault_terminal import execute

PROJECT=Path('/Users/galaxy/GitHub/rldcoin')


def body():
    cold=dict(messages_authenticated=1,full_native_authentication=True,implicit_head_adoption=False,
        retained_state_bytes=1024,state_limit_bytes=32*1024**2)
    transport=dict(node_id='private-node',network='private-network',retained_files=2,retained_bytes=2048,
        all_indexed_transport_archives_authenticated=True)
    rows=[dict(region=r,index=n,height=12,envelopes=cold,transport=transport,separate_caller_head_verified=True)
        for r in ('earth','proxima','andromeda') for n in range(4)]
    return dict(completed=True,full_fault_qualified=True,fixture_only=True,live_rld=False,whole_goal_completed=False,
        stage_seconds=600,round_seconds=60,new_height_limit=24,maturity=2,quorum=3,
        absolute_height_caps=dict(earth=27,proxima=24,andromeda=24),original_owner_first_signs=3,
        owner_requests_replaced=0,custody_copied=False,controller_consensus_or_checkpoints=0,
        all12fixed_head_native_and_complete_envelopes=rows)


class Fake:
    def __init__(self,root,result=None,cleanup_error=False,keep_process=False):
        self.root=root;self.output=root/'driver';self.result=result or body();self.cleanup_error=cleanup_error
        self.keep_process=keep_process;self.processes={1:object()};self.relays=[];self.terminal=[];self.calls=[]
        self.signed_count=3;self.stopped_heads={};self.attempted_owner_signs=3
    def run(self):return self.result
    def cleanup(self):
        if not self.keep_process:self.processes.clear()
        if self.cleanup_error:raise ValueError('retained cleanup failure')


class Tests(unittest.TestCase):
    def run_case(self,factory,now=0):
        with tempfile.TemporaryDirectory(dir=PROJECT/'tmp',prefix='paged-fault-terminal-') as tmp:
            root=Path(tmp);path=root/'raw.json';answer=execute(lambda:factory(root),10,path,now=lambda:now)
            self.assertTrue(path.is_file());raw=path.read_text();return answer,raw
    def test_body_success_cannot_hide_cleanup_failure_or_live_process(self):
        for kwargs in (dict(cleanup_error=True),dict(keep_process=True)):
            answer,raw=self.run_case(lambda r:Fake(r,**kwargs))
            self.assertFalse(answer['completed']);self.assertFalse(answer['full_fault_qualified'])
            self.assertTrue(answer['failed_currency_never_reopen']);self.assertIn('private-node',raw)
    def test_original_deadline_and_missing_cold_slot_refuse(self):
        answer,_=self.run_case(lambda r:Fake(r),now=11);self.assertFalse(answer['completed'])
        incomplete=body();incomplete['all12fixed_head_native_and_complete_envelopes'].pop()
        answer,_=self.run_case(lambda r:Fake(r,incomplete));self.assertFalse(answer['completed'])
        duplicate=body();duplicate['all12fixed_head_native_and_complete_envelopes'][-1]=duplicate['all12fixed_head_native_and_complete_envelopes'][0]
        answer,_=self.run_case(lambda r:Fake(r,duplicate));self.assertFalse(answer['completed'])
    def test_private_identity_stays_raw_and_public_keeps_only_qualified_counts(self):
        answer,raw=self.run_case(lambda r:Fake(r));self.assertTrue(answer['completed'])
        self.assertIn('private-node',raw);self.assertNotIn('private-node',str(answer))
        self.assertNotIn('private-network',str(answer));self.assertEqual(len(answer['stopped_native_envelope_transport_checks']),12)
        self.assertFalse(answer['whole_goal_completed'])
    def test_constructor_failure_is_retained_and_never_claims_cleanup_or_fault(self):
        def fail(_):raise ValueError('source mismatch before any custody writes')
        answer,raw=self.run_case(fail);self.assertFalse(answer['completed']);self.assertFalse(answer['owned_processes_stopped'])
        self.assertEqual(answer['released_owner_responses'],0);self.assertIn('source mismatch',raw)


if __name__=='__main__':unittest.main()
