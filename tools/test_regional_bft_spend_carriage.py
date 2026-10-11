"""Public no-value signature models; empty proofs never authorize Native value."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_node as bft
from regional_bft_retention import Messages
from regional_bft_spend_carriage import ordered_spend
from regional_bft_timeout_hint import encoded
import test_regional_bft_timeout_hint as signatures


class SpendCarriageTests(unittest.TestCase):
    setUp=signatures.TimeoutCarriageTests.setUp
    sign=signatures.TimeoutCarriageTests.sign

    def spend(self,owners=1,remote=False):
        intent=dict(currency=self.context['currency'],region=self.context['region'],
            inputs=[format(n+1,'064x') for n in range(owners)],
            outputs=[dict(owner=self.keys[-1],amount='98')],fee='1',
            destination='9'*64 if remote else None,
            remote=dict(owner=self.keys[-1],amount='100') if remote else None,
            destination_fee='1' if remote else '0',valid_through=21)
        return dict(Spend=dict(intent=intent,approvals=[self.sign(k,'owner-intent',intent)
            for k in self.keys[:owners]]))

    def proposal(self,commands=None,parent=False,round_number=0):
        proposal=copy.deepcopy(self.base) if round_number==0 else signatures.TimeoutCarriageTests.proposal(self,round_number)
        snapshot=proposal['snapshot'];blocks=snapshot['blocks']
        if commands is None:commands=[self.spend()]
        blocks[-1]['commands']=commands
        if parent:
            blocks[0]['commands']=[self.spend()]
            blocks[0]['header']['commands']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encoded(blocks[0]['commands'])).hexdigest()
            self.context['parent_block']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encoded(blocks[0]['header'])).hexdigest()
            blocks[-1]['header']['parent']=self.context['parent_block']
        blocks[-1]['header']['commands']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:commands\0'+encoded(commands)).hexdigest()
        snapshot['statement']['block']=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\0'+encoded(blocks[-1]['header'])).hexdigest()
        key=proposal['leader']['key'];proposal['leader']=self.sign(key,'bft-proposal-v1',[proposal['round'],snapshot,proposal['timeout'],key])
        return proposal

    def frames(self,proposal,enabled=True,format=bft.ORIGIN_NETWORK,imports=True):
        body=dict(Signed=dict(Proposal=proposal));env=dict(format=format,
            currency=self.context['currency'],region=self.context['region'],evidence={'snapshots':[]},body=body)
        if format==bft.ORIGIN_NETWORK:env['origins']=[]
        messages=Messages().append(mesh.digest(body),env,None,True)
        return bft.commit_carriage_frames(messages,self.context,self.keys,self.context['currency'],
            self.context['region'],proposal['round'],import_proposals=imports,spend_proposals=enabled)

    def test_exact_single_group_and_remote_signatures_keep_original_bytes(self):
        for owners,remote in ((1,False),(4,False),(1,True)):
            proposal=self.proposal([self.spend(owners,remote)]);before=copy.deepcopy(proposal)
            self.assertEqual(len(self.frames(proposal)),1);self.assertEqual(proposal,before)

    def test_spend_parent_child_mixed_import_and_original_sixteen_bound(self):
        for count in (1,16):
            proposal=self.proposal([self.spend()]*count);self.assertEqual(len(self.frames(proposal)),1)
        mixed=[self.spend(),dict(Import=dict(snapshot='8'*64,export='9'*64))]
        self.assertEqual(len(self.frames(self.proposal(mixed))),1)
        self.assertEqual(self.frames(self.proposal([self.spend()]*17)),())
        proposal=self.proposal(parent=True);self.assertEqual(len(self.frames(proposal)),1)

    def test_explicit_origin_flag_and_default_empty_import_behavior_remain(self):
        proposal=self.proposal()
        self.assertEqual(self.frames(proposal,enabled=False),())
        self.assertEqual(self.frames(proposal,format=bft.NETWORK),())
        self.assertEqual(self.frames(proposal,imports=False),())
        self.assertEqual(len(self.frames(copy.deepcopy(self.base),enabled=False)),1)

    def test_changed_signed_intent_or_proposal_never_gets_a_hint(self):
        for name in ('amount','fee','input','owner-signature','proposal-signature','command-hash','parent','epoch','leader'):
            proposal=self.proposal();child=proposal['snapshot']['blocks'][-1];spend=child['commands'][0]['Spend']
            if name=='amount':spend['intent']['outputs'][0]['amount']='97'
            elif name=='fee':spend['intent']['fee']='2'
            elif name=='input':spend['intent']['inputs'][0]='3'*64
            elif name=='owner-signature':spend['approvals'][0]['signature']='0'*128
            elif name=='proposal-signature':proposal['leader']['signature']='0'*128
            elif name=='command-hash':child['header']['commands']='5'*64
            elif name=='parent':child['header']['parent']='5'*64
            elif name=='epoch':proposal['snapshot']['statement']['epoch']='5'*64
            else:proposal['leader']['key']=self.keys[0]
            before=copy.deepcopy(proposal);self.assertEqual(self.frames(proposal),(),name);self.assertEqual(proposal,before)

    def test_unknown_fields_types_noncanonical_amounts_and_expiry_refuse(self):
        for value in ('01','-1','1.0','1e2','١','',1,True,str(2**128)):
            command=self.spend();command['Spend']['intent']['fee']=value
            self.assertEqual(self.frames(self.proposal([command])),(),str(value))
        for where in ('intent','approval','signed','payment'):
            command=self.spend();s=command['Spend'];target={'intent':s['intent'],
                'approval':s['approvals'][0],'signed':s,'payment':s['intent']['outputs'][0]}[where]
            target['extra']=True;self.assertEqual(self.frames(self.proposal([command])),(),where)
        for height in (True,-1,2**64,'21'):
            command=self.spend();command['Spend']['intent']['valid_through']=height
            self.assertEqual(self.frames(self.proposal([command])),())

    def test_input_output_approval_bounds_and_order_refuse(self):
        for change in ('no-input','many-input','input-order','duplicate-input','many-output','no-approval','duplicate-approval','approval-order'):
            command=self.spend(4);s=command['Spend'];i=s['intent']
            if change=='no-input':i['inputs']=[]
            elif change=='many-input':i['inputs']=[format(n+1,'064x') for n in range(17)]
            elif change=='input-order':i['inputs'].reverse()
            elif change=='duplicate-input':i['inputs'][-1]=i['inputs'][0]
            elif change=='many-output':i['outputs']*=17
            elif change=='no-approval':s['approvals']=[]
            elif change=='duplicate-approval':s['approvals'][-1]=s['approvals'][0]
            else:s['approvals'].reverse()
            self.assertEqual(self.frames(self.proposal([command])),(),change)

    def test_foreign_currency_region_and_incomplete_remote_pair_refuse(self):
        for change in ('currency','region','destination','remote'):
            command=self.spend();i=command['Spend']['intent']
            if change in ('currency','region','destination'):i[change]='6'*64
            else:i['remote']=dict(owner=self.keys[-1],amount='1')
            self.assertEqual(self.frames(self.proposal([command])),(),change)

    def test_complete_timeout_original_quorum_and_expansion_remain(self):
        proposal=self.proposal(round_number=1);self.assertEqual(len(self.frames(proposal)),1)
        for count in (1,2):
            bad=copy.deepcopy(proposal);bad['timeout']['votes']=bad['timeout']['votes'][:count]
            self.assertEqual(self.frames(bad),())
        with patch.object(bft,'MAX_BROADCAST_HINT_BYTES',1):self.assertEqual(self.frames(proposal),())
        proposal['snapshot']['epochs']=[{}];self.assertEqual(self.frames(proposal),())

    def test_strict_typed_order_is_independent_of_json_map_order(self):
        command=self.spend(4);original=copy.deepcopy(command)
        def reverse(value):
            if type(value) is dict:return {k:reverse(v) for k,v in reversed(list(value.items()))}
            if type(value) is list:return [reverse(v) for v in value]
            return value
        self.assertEqual(encoded(ordered_spend(reverse(command),self.context['currency'],self.context['region'])),encoded(command))
        self.assertEqual(command,original)

    def test_actual_broadcast_requires_current_origin_and_native_observation_for_spend_hint(self):
        # This flag/context is modeled; no Native or value authority follows.
        from test_interstellar_mesh import Fixture
        proposal=self.proposal();body=dict(Signed=dict(Proposal=proposal))
        env=dict(format=bft.ORIGIN_NETWORK,currency=self.context['currency'],region=self.context['region'],
                 body=body,evidence={'snapshots':[]},origins=[])
        messages=Messages().append(mesh.digest(body),env,None,True)
        for profile,authenticated in ((bft.ORIGIN_RUNTIME_FORMAT,True),(bft.ORIGIN_RUNTIME_FORMAT,False),(bft.FORMAT,True)):
            parent=Path(os.environ.get('RLD_RETAINED_GROUND_ROOT',
                str(Path(__file__).resolve().parents[1]/'tmp'))).resolve()
            parent.mkdir(parents=True,exist_ok=True)
            directory=tempfile.mkdtemp(prefix='rld-spend-hint-',dir=parent);fixture=Fixture(directory)
            runtime=bft.Runtime.__new__(bft.Runtime);runtime.format=profile;runtime.joint=None
            runtime.region=self.context['region'];runtime.key=self.keys[1];runtime.node_id=fixture.identities['earth']['node_id']
            runtime.peers=dict(sorted({self.keys[1]:runtime.node_id,self.keys[0]:fixture.identities['proxima']['node_id'],
                self.keys[2]:fixture.identities['andromeda']['node_id'],self.keys[3]:'9'*64}.items()))
            runtime.binding=dict(currency=self.context['currency'],region=runtime.region,key=runtime.key)
            runtime.native=SimpleNamespace(currency=self.context['currency'],authority='public-no-value-signature-model',ledger=Path(directory)/'absent-native')
            runtime.transport=fixture.configs['earth'];runtime._retained_native_authenticated=authenticated
            runtime._carriage_context=wire.canonical(self.context);runtime._carriage_round=0
            runtime.state=dict(messages=messages,height=self.context['parent_height'],cursor=0)
            runtime.save=lambda state:setattr(runtime,'state',state)
            captured=[];original=mesh.Node.set_carriage_priority
            def priority(node,scope,frames,**kwargs):
                captured.append(frames);return original(node,scope,frames,**kwargs)
            with patch.object(mesh.Node,'set_carriage_priority',priority):runtime.broadcast()
            expected=self.frames(proposal) if profile==bft.ORIGIN_RUNTIME_FORMAT else ()
            self.assertEqual(captured,[expected] if authenticated else [])
            self.assertIs(runtime.state['messages'],messages)


if __name__=='__main__':unittest.main()
