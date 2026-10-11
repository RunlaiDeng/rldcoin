"""Fresh no-value Native proposal policy versus the independent Python reference."""
import copy
import fcntl
import hashlib
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_proposal_reference import opportunity_reference
from test_regional_bft_retention import NativeRetentionTests


class NativeProposalScheduleTests(unittest.TestCase):
    setUp=NativeRetentionTests.setUp
    tearDown=NativeRetentionTests.tearDown
    open=NativeRetentionTests.open

    def compare(self,runtime):
        context=runtime.native.call('bft-context')['context']
        status=runtime.signer_status()
        active=status['state'] if status['state']['context']==context else {'round':0,'proposed':False}
        paths=[runtime.native.ledger,runtime.signer,runtime.head_path.parent]
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in paths for p in d.rglob('*') if p.is_file()}
        expected=opportunity_reference(runtime,context,active['round'],active)
        result=runtime.proposal_opportunity(context,active['round'])
        self.assertEqual({k:result[k] for k in expected},expected)
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in paths for p in d.rglob('*') if p.is_file()})
        return result

    def foreign(self,runtime,index,request):
        signed=self.c.sign('earth',index,request)
        runtime.retain(runtime.envelope({'Signed':signed['message']}),sync=False)
        return signed['message']

    def test_future_round_current_proposal_and_fourth_high_qc_match_python(self):
        runtime=self.open();context=self.native.call('bft-context')['context']
        self.compare(runtime)
        # Three other admitted signers advance from their actual native heads.
        # The local round remains zero; choose a future own leader opportunity.
        for round_number in range(4):
            for index in (1,2,3):
                self.foreign(runtime,index,{'Timeout':dict(context=context,round=round_number)})
            result=self.compare(runtime)
            if result['proposed_round']>0 and result['can_propose']:break
        self.assertGreater(result['proposed_round'],0);self.assertTrue(result['can_propose'])
        self.assertEqual(len(result['timeout']['votes']),3)
        number=result['proposed_round']
        runtime.sign({'Propose':dict(round=number,snapshot=runtime.candidate(context),timeout=result['timeout'])})
        result=self.compare(runtime);self.assertTrue(result['current_proposals']);self.assertFalse(result['can_propose'])
        proposal=runtime.signed(context,number,'Proposal')[0][0]
        runtime.sign({'Prepare':proposal})
        votes=[runtime.signed(context,number,'Vote','Prepare')[0][0]]
        votes.extend(self.foreign(runtime,index,{'Prepare':proposal})['Vote'] for index in (1,2,3))
        prepared=self.c.combine('earth',votes[:3])
        # Only the fourth signer retains this complete Prepare QC; its Timeout
        # must survive Native's ordered four-voter certificate selection.
        self.foreign(runtime,3,{'Commit':dict(proposal=proposal,prepared=prepared)})
        for index in (1,2,3):
            self.foreign(runtime,index,{'Timeout':dict(context=context,round=number)})
        runtime.sign({'Timeout':dict(context=context,round=number)})
        result=self.compare(runtime)
        self.assertEqual(result['round'],number+1);self.assertEqual(len(result['timeout']['votes']),4)
        self.assertEqual(result['high'],prepared['value'])
        before=runtime.signer_status()['records'];runtime.key_file.unlink();runtime.close();self.runtime=None
        runtime=self.open();self.compare(runtime);self.assertEqual(runtime.signer_status()['records'],before)

    def test_stale_heads_context_round_locks_and_self_consistent_forgery_refuse(self):
        runtime=self.open();context=self.native.call('bft-context')['context']
        before=(runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records'])
        stale=dict(context,parent_height=context['parent_height']+1)
        with self.assertRaises(ValueError):runtime.proposal_opportunity(stale,0)
        with self.assertRaises(ValueError):runtime.proposal_opportunity(context,1)
        old=runtime._archive_head;runtime._archive_head='0'*64
        with self.assertRaises(ValueError):runtime.proposal_opportunity(context,0)
        runtime._archive_head=old
        head=runtime.head;runtime.head=dict(head,head='0'*64)
        with self.assertRaises(ValueError):runtime.proposal_opportunity(context,0)
        runtime.head=head
        with (runtime.root/'.archive.lock').open('r+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(ValueError):runtime.proposal_opportunity(context,0)
        with (runtime.native.ledger/'LOCK').open('r+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(ValueError):runtime.proposal_opportunity(context,0)
        self.assertEqual((runtime.state_path.read_bytes(),runtime.head_path.read_bytes(),runtime.signer_status()['records']),before)
        self.foreign(runtime,1,{'Timeout':dict(context=context,round=0)})
        packed=copy.deepcopy(mesh.load(runtime.state_path,32*1024*1024))
        ident,record=next(iter(packed['runtime']['messages'].items()))
        record['body']['Signed']['Timeout']['approval']['signature']='00'*64
        new_id=mesh.digest(record['body']);packed['runtime']['messages'].pop(ident)
        envelope=dict(record['header'],body=record['body'],evidence={'snapshots':[]})
        record['sha256']=hashlib.sha256(wire.canonical(envelope)).hexdigest();record['size_bytes']=len(wire.canonical(envelope))
        packed['runtime']['messages'][new_id]=record
        mesh.atomic(runtime.state_path,packed);runtime._archive_head=hashlib.sha256(runtime.state_path.read_bytes()).hexdigest()
        damaged=runtime.state_path.read_bytes();caller=runtime.head_path.read_bytes();records=runtime.signer_status()['records']
        with self.assertRaises(ValueError):runtime.proposal_opportunity(context,0)
        self.assertEqual(runtime.state_path.read_bytes(),damaged);self.assertEqual(runtime.head_path.read_bytes(),caller)
        self.assertEqual(runtime.signer_status()['records'],records)

if __name__=='__main__':unittest.main()
