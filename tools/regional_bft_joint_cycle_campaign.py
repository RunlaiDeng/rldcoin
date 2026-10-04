#!/usr/bin/env python3
"""Preconfigured joint handoff followed by the ordinary three-region value cycle.

Only configuration, actual owner requests, process operation and observations
are controller actions. Native votes, activation and value evidence move through
ordinary pinned TLS startup. Same host/public fixtures, not qualification.
"""
import argparse
import json
from pathlib import Path

import interstellar_mesh as mesh
from regional_bft_multiregion_campaign import Campaign as Cycle
from regional_bft_joint_epoch import FORMAT
from regional_bft_retention import unpack_state
from regional_contact_campaign import public


def observe_selected_joint(cli, currency, region, validators, height, epoch):
    """Read-only exact native selection; checkpoint multiplicity is not authority."""
    current=cli('bft-context')
    proof=current['active_epoch_proof']
    mesh.require(current['rules']=='RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1'
                 and current['context']['epoch']==epoch and proof is not None,
                 'ordinary native joint activation is absent or differs')
    statement=proof['statement']
    mesh.require(statement['currency']==currency and statement['region']==region
                 and statement['validators']==validators and current['keys']==validators
                 and statement['closing_height']==height and statement['number']==1,
                 'ordinary native selected joint intent differs')
    scope=cli('bft-epoch-proposal','--checkpoint',statement['closing_checkpoint'])
    mesh.require(scope['proposal'] is not None and scope['proposal']['statement']==statement,
                 'ordinary native closing checkpoint selection differs')
    return proof


def observe_joint_slot(observation):
    """Optional telemetry only, after the independent full Native selection check."""
    consensus=observation.get('consensus')
    mesh.require(isinstance(consensus,dict), 'joint slot telemetry missing its typed observation')
    if 'joint_active_slot' in consensus:
        mesh.require(consensus['joint_active_slot']=='new', 'Earth participant reported a different explicit slot')
        return 'new'
    mesh.require(consensus.get('progress_observation_available') is False
                 and isinstance(consensus.get('diagnostic'),str)
                 and 0<len(consensus['diagnostic'])<=256
                 and 'height' not in consensus and 'round' not in consensus,
                 'joint slot telemetry absent without an explicit bounded unknown observation')
    return None


class Campaign(Cycle):
    def invoke(self,command,success=True,helper=False):
        command=list(command)
        if helper and command[-2:]==['bootstrap','--bft']:command[-1]='--bft-joint'
        return super().invoke(command,success,helper)

    def cli(self,name,n,*args,success=True):
        mesh.require(args and args[0] not in {'bft-epoch-combine','bft-epoch-activate',
                     'bft-epoch-activate-observed','sign-handoff',
                     'install-epoch','propose-epoch','sign-checkpoint','signer-recover-handoff'},
                     'controller attempted epoch approval/activation')
        return super().cli(name,n,*args,success=success)

    def __init__(self,binary,root):
        super().__init__(binary,root)
        self.new_seeds=sorted(range(62,66),key=public)
        self.joint_selected=False
        self.joint_slot_observations=[]
        self.activated_epoch=None
        for n,seed in enumerate(self.new_seeds):
            pair=('earth',n);key=self.file(f'earth-next-key-{n}',{'secret_key':(bytes([seed])*32).hex()});key.chmod(0o600)
            approval=self.root/f'candidate-earth-{n}'
            initialized=self.cli('earth',n,'signer-init','--signer-dir',approval,'--key',public(seed))
            candidate_head_dir=self.root/f'candidate-caller-earth-{n}';candidate_head_dir.mkdir(mode=0o700)
            next_head_dir=self.root/f'next-caller-earth-{n}';next_head_dir.mkdir(mode=0o700)
            binding={'currency':self.currency,'region':self.regions['earth'],'key':public(seed)}
            candidate_head=candidate_head_dir/'head.json'
            mesh.atomic(candidate_head,{'format':FORMAT,'binding':binding,'head':initialized['lock_head'],'pending':None,'outbox':None})
            next_head=next_head_dir/'head.json'
            mesh.atomic(next_head,{'format':FORMAT,'binding':binding,'head':None,'pending':None,'outbox':None,'initialization':None})
            old=self.configs[pair];path=Path(old['head_file'])
            mesh.atomic(path,dict(mesh.load(path,8*1024*1024),format=FORMAT))
            joint={'key':public(seed),'key_file':str(key),'signer_dir':str(self.root/f'next-voter-earth-{n}'),
                   'head_file':str(next_head),'approval_dir':str(approval),'approval_head':str(candidate_head),
                   'validators':[{'key':public(s),'node_id':self.node_ids['earth',j]} for j,s in enumerate(self.new_seeds)],
                   'select_height':4}
            config=dict(old,format=FORMAT,joint_epoch=joint)
            if n==0:
                config['key_file']=str(self.root/'earth-offline-old-key-input')
                joint['key_file']=str(self.root/'earth-offline-new-key-input')
            self.configs[pair]=config
            self.file(f'bft-config-earth-{n}',config).chmod(0o600)

    def audit(self,phase):
        super().audit(phase)
        if phase=='three regions discovered; only Earth has issued fixture value' and not self.joint_selected:
            self.joint_selected=True
            self.resume('earth',7)
            states=[self.cli('earth',n,'status') for n in range(4)]
            mesh.require(len({s['validator_epoch'] for s in states})==1,'joint epoch differs across Earth replicas')
            self.activated_epoch=states[0]['validator_epoch']
            observe_selected_joint(lambda *args:self.cli('earth',1,*args),
                self.currency,self.regions['earth'],[public(s) for s in self.new_seeds],
                4,self.activated_epoch)
            for n in (1,2,3):
                slot=observe_joint_slot(self.observation(('earth',n)))
                self.joint_slot_observations.append(dict(carrier=n,slot=slot,
                    telemetry_available=slot is not None,full_native_selection_previously_verified=True))
                old=self.cli('earth',n,'bft-status','--signer-dir',self.signer('earth',n))
                mesh.require(old['state']['epoch_fence']==self.activated_epoch,'original old fence missing')
            self.assert_keyless_observer()
            self.progress('verified: autonomous selected joint epoch before first cross-region export')

    def assert_keyless_observer(self):
        mesh.require(not (self.root/'next-voter-earth-0').exists(),'nonparticipant observer created new voting custody')
        mesh.require(self.cli('earth',0,'bft-status','--signer-dir',self.signer('earth',0))['records']==0,
                     'keyless old observer first-signed')
        mesh.require(self.cli('earth',0,'signer-status','--signer-dir',self.root/'candidate-earth-0')['votes']==0,
                     'keyless candidate observer first-signed')

    def queued_body_present(self,key,commands):
        state=unpack_state(mesh.load(Path(self.configs[key]['state'])/'state.json',32*1024*1024))
        return any(body.get('EpochSubmission',{}).get('commands',body.get('Submission'))==commands
                   for _,body,_,_ in state['messages'].bodies())

    def submit_export(self,name,owner,destination,recipient,gross,destination_fee):
        wallet=self.root/f'{name}-owner-{owner}'
        initialized=self.cli(name,1,'wallet-init','--wallet-dir',wallet,'--owner',public(owner))
        request={'owner':public(owner),'inputs':None,'outputs':[],'fee':'1','valid_for_blocks':8,
                 'remote':{'destination':self.regions[destination],
                           'recipient':{'owner':public(recipient),'amount':str(gross)},'destination_fee':str(destination_fee)}}
        draft=self.cli(name,1,'wallet-prepare','--wallet-dir',wallet,'--expected-wallet-head',initialized['wallet_head'],
                       '--file',self.file(f'{name}-request',request))
        key=self.file(f'{name}-owner-key',{'secret_key':(bytes([owner])*32).hex()});key.chmod(0o600)
        signed=self.cli(name,1,'wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',draft['wallet_head'],
                        '--file',self.file(f'{name}-review',draft),'--review',draft['review_commitment'],'--key-file',key)
        before=self.cli(name,1,'status')
        result=self.cli(name,1,'bft-submit','--file',self.file(f'{name}-submission',signed['commands']))
        mesh.require(result['queued'] and not result['block_included'] and self.cli(name,1,'status')['ledger']==before['ledger'],
                     'queued actual owner export debited before inclusion')
        self.wait(lambda:all(self.queued_body_present(k,signed['commands']) for k in self.region_keys(name)),
                  f'{name} native era-scoped actual signed export reaches all four carriers')
        self.resume(name,before['height']+1)
        current=self.cli(name,1,'status');eid=draft['draft']['intent_id']
        mesh.require(eid in current['ledger']['exports'],'new-era native export missing')
        view=self.cli(name,1,'wallet-view','--wallet-dir',wallet,'--expected-wallet-head',signed['wallet_head'])
        mesh.require(view['reserved_owned_outputs']=='0','included export remained privately reserved')
        frame=self.cli(name,1,'contact-export','--export',eid)
        return {'currency':self.currency,'source':self.regions[name],'destination':self.regions[destination],
                'export':eid,'recipient':public(recipient),'net_amount':str(gross-destination_fee)},frame

    def run(self):
        result=super().run()
        mesh.require(self.joint_selected and self.activated_epoch is not None,'joint transition was not observed')
        self.assert_keyless_observer()
        mesh.require(result['replica_heights']=={'earth':[11]*4,'proxima':[4]*4,'andromeda':[4]*4},
                     'joint three-region cycle terminal heights differ')
        mesh.require(self.cli('earth',1,'status')['validator_epoch']==self.activated_epoch,'cross-region cycle changed native era')
        result.update(format='RLD-BFT-JOINT-MULTIREGION-GROUND-CAMPAIGN-V1',
            completed=True,preconfigured_autonomous_joint_epoch=True,joint_selection_height=4,
            activated_epoch=self.activated_epoch,old_durable_fences=3,new_durable_approvals=3,
            controller_generated_epoch_approvals=0,controller_installed_epoch_activation=0,
            one_keyless_carrier_never_first_signed=True,late_new_custody_not_created=True,
            first_export_after_native_epoch_activation=True,full_fault_profile_run=False,
            arbitrary_overlapping_membership_qualified=False,BFT_reconfiguration_implemented='one preconfigured disjoint joint transition')
        result['joint_slot_observations']=self.joint_slot_observations
        return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','root','report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    from regional_campaign_terminal import execute
    result=execute(Campaign,a,'RLD-BFT-JOINT-MULTIREGION-GROUND-CAMPAIGN-V1',Path(__file__))
    print(json.dumps({'completed':result['completed'],'failure':result['failure']}),flush=True)

if __name__=='__main__':main()
