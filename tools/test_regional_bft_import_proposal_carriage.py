"""Extra signed Import carriage checks; no Native ledger or value authority."""
import copy
import hashlib
import inspect
import unittest

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import commit_carriage_frames, NETWORK, ORIGIN_NETWORK
from regional_bft_retention import Messages
from regional_bft_timeout_hint import encoded
import test_regional_bft_timeout_hint as signatures


class ImportProposalCarriageTests(unittest.TestCase):
    setUp=signatures.TimeoutCarriageTests.setUp
    sign=signatures.TimeoutCarriageTests.sign
    proposal=signatures.TimeoutCarriageTests.proposal

    def imported(self, count=1):
        proposal=self.proposal();snapshot=proposal['snapshot'];child=snapshot['blocks'][-1]
        child['commands']=[{'Import':dict(snapshot='1'*64,export=('2' if n%2==0 else '3')*64)} for n in range(count)]
        child['header']['commands']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encoded(child['commands'])).hexdigest()
        snapshot['statement']['block']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encoded(child['header'])).hexdigest()
        key=proposal['leader']['key'];proposal['leader']=self.sign(key,'bft-proposal-v1',[proposal['round'],snapshot,proposal['timeout'],key])
        return proposal

    def frames(self, proposal, enabled=True, format=ORIGIN_NETWORK):
        body={'Signed':{'Proposal':proposal}}
        envelope=dict(format=format,currency=self.context['currency'],region=self.context['region'],evidence={'snapshots':[]},body=body)
        if format==ORIGIN_NETWORK:envelope['origins']=[]
        messages=Messages().append(mesh.digest(body),envelope,None,True)
        options={'import_proposals':enabled} if 'import_proposals' in inspect.signature(commit_carriage_frames).parameters else {}
        return commit_carriage_frames(messages,self.context,self.keys,self.context['currency'],self.context['region'],proposal['round'],**options)

    def test_exact_signed_import_candidate_gets_one_frame_without_changing_bytes(self):
        for count in (1,16):
            proposal=self.imported(count);before=copy.deepcopy(proposal)
            self.assertEqual(len(self.frames(proposal)),1)
            self.assertEqual(proposal,before)

    def test_legacy_or_disabled_path_keeps_original_empty_only_selection(self):
        self.assertEqual(self.frames(self.imported(),enabled=False),())
        self.assertEqual(self.frames(self.imported(),format=NETWORK),())
        self.assertEqual(len(self.frames(self.proposal(),enabled=False)),1)

    def test_changed_command_hash_parent_signature_or_timeout_is_no_hint(self):
        for change in ('command','hash','previous','signature','timeout','leader'):
            proposal=self.imported()
            if change=='command':proposal['snapshot']['blocks'][-1]['commands'][0]['Import']['export']='4'*64
            elif change=='hash':proposal['snapshot']['blocks'][-1]['header']['commands']='5'*64
            elif change=='previous':proposal['snapshot']['statement']['previous']='6'*64
            elif change=='signature':proposal['leader']['signature']='0'*128
            elif change=='timeout':proposal['timeout']['votes'].pop()
            else:proposal['leader']['key']=self.keys[0]
            self.assertEqual(self.frames(proposal),(),change)

    def test_other_commands_and_original_sixteen_command_bound_refuse(self):
        self.assertEqual(self.frames(self.imported(17)),())
        proposal=self.imported();proposal['snapshot']['blocks'][-1]['commands']=[{'Spend':{'modeled':True}}]
        self.assertEqual(self.frames(proposal),())

    def test_original_expansion_bound_and_complete_message_ownership_remain(self):
        from unittest.mock import patch
        import regional_bft_node as bft
        proposal=self.imported()
        with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',1):self.assertEqual(self.frames(proposal),())
        self.assertEqual(len(self.frames(proposal)),1)

    def test_origin_capacity_keeps_exact_proposal_and_all_other_retained_bytes(self):
        from unittest.mock import patch
        import regional_bft_node as bft
        proposal=self.imported();body={'Signed':{'Proposal':proposal}}
        envelope=dict(format=ORIGIN_NETWORK,currency=self.context['currency'],region=self.context['region'],
            evidence={'snapshots':[]},origins=[],body=body)
        p=mesh.digest(body);messages=Messages().append(p,envelope,None,True)
        timeout=proposal['timeout']['votes'][0];other=copy.deepcopy(envelope);other['body']={'Signed':{'Timeout':timeout}}
        t=mesh.digest(other['body']);messages=messages.append(t,other,None,True)
        before={ident:messages.payload(ident) for ident in messages}
        limit=messages.record(p)['size_bytes'];raw=wire.make_frame('regional-bft',self.context['region'],
            self.context['region'],messages.content(p),messages.payload(p));expected=wire.inspect_frame(raw)[0]['message_id']
        options={'import_proposals':True} if 'import_proposals' in inspect.signature(commit_carriage_frames).parameters else {}
        with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',limit):
            frames=commit_carriage_frames(messages,self.context,self.keys,self.context['currency'],self.context['region'],1,**options)
        self.assertEqual(frames,(expected,))
        self.assertEqual({ident:messages.payload(ident) for ident in messages},before)

if __name__=='__main__':unittest.main()
