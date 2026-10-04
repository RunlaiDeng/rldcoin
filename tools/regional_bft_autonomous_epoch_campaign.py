#!/usr/bin/env python3
"""Ordinary four-carrier TLS lifecycle with an explicitly pinned joint intent.

The controller supplies startup configuration and owner requests, never native
consensus votes, epoch approvals, quorums, activation or checkpoint installation.
Same host/controller and public fixture keys; no independence qualification.
"""
import argparse
import json
from pathlib import Path
import time

import interstellar_mesh as mesh
from regional_bft_network_campaign import Campaign as NetworkCampaign
from regional_contact_campaign import public,save
from regional_bft_joint_epoch import FORMAT


class Campaign(NetworkCampaign):
    def invoke(self,command,success=True,helper=False):
        command=list(command)
        if helper and command[-2:]==['bootstrap','--bft']:
            command[-1]='--bft-joint'
        return super().invoke(command,success,helper)

    def __init__(self,binary,root):
        super().__init__(binary,root)
        self.new_seeds=sorted(range(62,66),key=public)
        for n,seed in enumerate(self.new_seeds):
            key=self.file(f'next-key-{n}',{'secret_key':(bytes([seed])*32).hex()});key.chmod(0o600)
            approval=self.root/f'candidate-{n}'
            initialized=self.cli('earth',n,'signer-init','--signer-dir',approval,'--key',public(seed))
            approval_head_dir=self.root/f'candidate-caller-{n}';approval_head_dir.mkdir(mode=0o700)
            next_head_dir=self.root/f'next-caller-{n}';next_head_dir.mkdir(mode=0o700)
            binding={'currency':self.currency,'region':self.regions['earth'],'key':public(seed)}
            approval_head=approval_head_dir/'head.json'
            mesh.atomic(approval_head,{'format':FORMAT,'binding':binding,'head':initialized['lock_head'],'pending':None,'outbox':None})
            next_head=next_head_dir/'head.json'
            mesh.atomic(next_head,{'format':FORMAT,'binding':binding,'head':None,'pending':None,'outbox':None,'initialization':None})
            original=self.configs[n]
            head=mesh.load(original['head_file'],8*1024*1024)
            mesh.atomic(Path(original['head_file']),dict(head,format=FORMAT))
            joint={'key':public(seed),'key_file':str(key),'signer_dir':str(self.root/f'next-voter-{n}'),
                   'head_file':str(next_head),'approval_dir':str(approval),'approval_head':str(approval_head),
                   'validators':[{'key':public(s),'node_id':self.node_ids[j]} for j,s in enumerate(self.new_seeds)],
                   'select_height':4}
            self.configs[n]=dict(original,format=FORMAT,joint_epoch=joint,stop_height=7)
            if n==0:
                # Explicit keyless late observer; preserve fixture key files,
                # but do not configure them as signing inputs for this carrier.
                self.configs[n]['key_file']=str(self.root/'offline-old-key-input')
                joint['key_file']=str(self.root/'offline-new-key-input')
            self.file(f'bft-config-{n}',self.configs[n]).chmod(0o600)

    def run(self):
        # Keep carrier/signers 0 offline across old selection and new continuation.
        for n in (1,2,3):self.start(n)
        self.wait(lambda:self.reached((1,2,3),7),'autonomous selected-plan handoff and new-set continuation',timeout=420)
        self.same_replicas('earth',(1,2,3))
        native=self.cli('earth',1,'status')
        epoch=native['validator_epoch']
        proof=self.cli('earth',1,'proof')
        selected=[s for s in proof['snapshots'] if s['statement']['height']==4][0]
        mesh.require(any('Reconfigure' in c for c in selected['blocks'][-1]['commands']),'old consensus never selected configured plan')
        mesh.require(all(self.observation(n)['consensus']['joint_active_slot']=='new' for n in (1,2,3)),
                     'online nodes did not switch to explicit new slot')
        # A late uninitialized new key is a native read-only observer; it must
        # not invent its missing boundary signing journal when catching up.
        self.start(0)
        self.wait(lambda:self.reached((0,1,2,3),7),'late replica keyless era catchup',timeout=240)
        self.same_replicas('earth',(0,1,2,3))
        mesh.require(not (self.root/'next-voter-0').exists(),'late new key created a backdated empty journal')
        mesh.require(self.cli('earth',0,'bft-status','--signer-dir',self.signer('earth',0))['records']==0,'offline old signer first-signed')
        mesh.require(self.cli('earth',0,'signer-status','--signer-dir',self.root/'candidate-0')['votes']==0,'offline new candidate first-signed')
        wallet=self.root/'post-epoch-wallet'
        created=self.cli('earth',1,'wallet-init','--wallet-dir',wallet,'--owner',public(10))
        request={'owner':public(10),'inputs':None,'outputs':[{'owner':public(14),'amount':'30'}],
                 'remote':None,'fee':'1','valid_for_blocks':8}
        draft=self.cli('earth',1,'wallet-prepare','--wallet-dir',wallet,'--expected-wallet-head',created['wallet_head'],
                       '--file',self.file('post-epoch-owner-request',request))
        key=self.file('owner-key',{'secret_key':(bytes([10])*32).hex()});key.chmod(0o600)
        signed=self.cli('earth',1,'wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',draft['wallet_head'],
                        '--file',self.file('post-epoch-owner-review',draft),'--review',draft['review_commitment'],'--key-file',key)
        ledger=self.cli('earth',1,'status')['ledger']
        self.cli('earth',1,'bft-submit','--file',self.file('post-epoch-commands',signed['commands']))
        mesh.require(self.cli('earth',1,'status')['ledger']==ledger,'post-era submission debited before inclusion')
        self.wait(lambda:all(any(record[1].get('EpochSubmission',{}).get('commands')==signed['commands']
                                 for record in self.retained(n)) for n in (1,2,3)),
                  'post-era scoped signed owner request gossips while signing paused',timeout=240)
        for n in range(4):self.stop(n)
        heads={n:mesh.load(self.root/f'next-caller-{n}/head.json',8*1024*1024) for n in range(4)}
        for n in range(4):
            self.configs[n]=dict(self.configs[n],stop_height=9)
            self.file(f'bft-config-{n}',self.configs[n]).chmod(0o600)
            self.start(n)
        self.wait(lambda:self.reached((0,1,2,3),9),'restart new-era journals and autonomous payment inclusion',timeout=420)
        self.same_replicas('earth',(0,1,2,3))
        final=self.cli('earth',1,'status')
        amount=sum(int(c['payment']['amount']) for c in final['ledger']['coins'].values() if c['payment']['owner']==public(14))
        mesh.require(amount==30 and final['ledger']['minted']=='300','post-era actual owner payment or issuance differs')
        mesh.require(final['validator_epoch']==epoch,'restart changed activated era')
        view=self.cli('earth',1,'wallet-view','--wallet-dir',wallet,'--expected-wallet-head',signed['wallet_head'])
        mesh.require(view['reserved_owned_outputs']=='0','included owner request remained reserved')
        mesh.require(not (self.root/'next-voter-0').exists(),'restart created late empty voter journal')
        for n in (1,2,3):
            mesh.require(heads[n]['head'] is not None,'new signature caller head was not retained separately')
            old=self.cli('earth',n,'bft-status','--signer-dir',self.signer('earth',n))
            mesh.require(old['state']['epoch_fence']==epoch,'old original signing journal lost fence')
        self.audit('autonomous preconfigured disjoint joint epoch and new-era wallet inclusion')
        return {'format':'RLD-BFT-AUTONOMOUS-JOINT-EPOCH-CAMPAIGN-V1','fixture_only':True,'live_rld':False,
                'currency':self.currency,'native_implementation':self.implementation,'same_host_same_controller':True,
                'ordinary_node_startup':True,'pinned_tls_contact_carriage':True,'old_and_new_signer_zero_offline_through_activation':True,
                'three_old_fences_three_new_approvals':True,'autonomous_selected_plan_height':4,
                'controller_consensus_votes_or_quorums':0,'controller_epoch_approvals_or_activations':0,
                'controller_checkpoint_installations':0,'operator_preconfigured_exact_new_keys_and_carriers':True,
                'late_replica_native_keyless_epoch_catchup':True,'late_new_empty_signer_refused':True,
                'late_carrier_old_and_new_private_key_inputs_absent':True,
                'new_signer_heads_survived_restart':True,'old_original_fences_retained':True,'post_epoch_actual_owner_payment':'30',
                'post_epoch_submission_no_debit':True,'replica_heights':[self.cli('earth',n,'status')['height'] for n in range(4)],
                'minted':'300','observed_ground_phases':self.observations,'conservation':self.checks,
                'arbitrary_dynamic_membership_qualified':False,'full_byzantine_network_fault_profile':False,
                'independent_operators_or_custody_qualified':False,'physical_route_qualified':False,
                'all_state_head_rollback_qualified':False,'generated_private_state_published':False}

    def retained(self,n):
        from regional_bft_retention import unpack_state
        return list(unpack_state(mesh.load(self.root/f'bft-runtime-{n}/state.json',32*1024*1024))['messages'].bodies())


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    c=Campaign(a.binary,a.root)
    try:
        result=c.run();mesh.atomic(a.report,result);print(json.dumps(result))
    finally:c.cleanup()

if __name__=='__main__':main()
