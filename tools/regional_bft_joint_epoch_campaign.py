#!/usr/bin/env python3
"""Fresh no-value selected-plan joint CLI epoch ceremony; never autonomous or independent.

Private stores, owner keys, signer journals and separately retained heads stay
under --root. No existing directory is reused. Rust signs/checks every artifact.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import interstellar_mesh as mesh
from regional_contact_node import Native


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed])*32).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()


def campaign(binary, root, report):
    root.mkdir(mode=0o700,parents=False,exist_ok=False)
    count=0
    def file(label,obj):
        path=root/(label+'.json');mesh.atomic(path,obj);return path
    package=json.loads(subprocess.check_output([str(binary.with_name('contact-fixture')),'bootstrap','--bft-joint']))
    currency=package['admissions'][0]['currency'];authority=package['currency']['authority'];bootstrap=file('bootstrap',package)
    natives=[]
    for n in range(4):
        native=Native(binary,root/f'node-{n}',authority,currency)
        native.call('init','--bootstrap',bootstrap,'--region','earth');natives.append(native)
    old=sorted(range(2,6),key=public);new=sorted(range(62,66),key=public)
    for seed in [*old,*new,10]:file(f'key-{seed}',{'secret_key':(bytes([seed])*32).hex()})
    phase='old';heads={};signers={};old_responses=[];view_changes=[]
    def initialize(seeds):
        for n,seed in enumerate(seeds[:3]):
            signers[n]=root/f'{phase}-signer-{seed}';out=natives[n].call('bft-init','--signer-dir',signers[n],'--key',public(seed));heads[n]=out['head'];file(f'{phase}-head-{n}',{'head':heads[n],'pending':None})
    def sign(n,request,seeds):
        nonlocal count
        req=file(f'request-{count}',request);count+=1
        file(f'{phase}-head-{n}',{'head':heads[n],'pending':request})
        out=natives[n].call('bft-sign','--signer-dir',signers[n],'--expected-head',heads[n],'--file',req,'--key-file',root/f'key-{seeds[n]}.json')
        file(f'response-{count}',out);heads[n]=out['head'];file(f'{phase}-head-{n}',{'head':heads[n],'pending':None});return out
    def append(commands,seeds):
        c=natives[0].call('bft-context');leader=[public(s) for s in seeds].index(c['leader_round_zero']);snapshot=natives[0].call('bft-candidate','--miner',public(10),'--commands',file(f'commands-{count}',commands))
        round_number=0;timeout=None
        if leader==3:
            votes=[sign(n,{'Timeout':{'context':c['context'],'round':0}},seeds)['message']['Timeout'] for n in range(3)]
            timeout=natives[0].call('bft-timeout-certificate','--file',file(f'timeout-{count}',votes));round_number=1;leader=0
            view_changes.append({'phase':phase,'parent_height':c['context']['parent_height'],'round':1,'votes':3})
        proposal=sign(leader,{'Propose':{'round':round_number,'snapshot':snapshot,'timeout':timeout}},seeds)['message']['Proposal']
        votes=[sign(n,{'Prepare':proposal},seeds)['message']['Vote'] for n in range(3)]
        prepared=natives[0].call('bft-quorum','--file',file(f'prepare-{count}',votes))
        votes=[sign(n,{'Commit':{'proposal':proposal,'prepared':prepared}},seeds)['message']['Vote'] for n in range(3)]
        committed=natives[0].call('bft-quorum','--file',file(f'commit-{count}',votes))
        certified=natives[0].call('bft-certify','--file',file(f'certificate-{count}',{'proposal':proposal,'prepared':prepared,'committed':committed}))
        cert=file(f'finality-{count}',certified)
        for native in natives:native.call('finalize','--file',cert)
        observations=[native.call('status') for native in natives]
        mesh.require(all(x['ledger']==observations[0]['ledger'] and x['tip']==observations[0]['tip'] and x['validator_epoch']==observations[0]['validator_epoch'] for x in observations),'replica disagreement')
        ledger=observations[0]['ledger'];liquid=sum(int(c['payment']['amount']) for c in ledger['coins'].values());mesh.require(int(ledger['minted'])+int(ledger['received'])==liquid and not ledger['exports'],'native local conservation')
        return observations[0]
    initialize(old)
    for _ in range(3):append([],old)
    wallet=root/'owner-wallet';owner=natives[0].call('wallet-init','--wallet-dir',wallet,'--owner',public(10));wallet_head=owner['wallet_head']
    def payment():
        nonlocal wallet_head
        state=natives[0].call('status');inputs=sorted(k for k,c in state['ledger']['coins'].items() if c['payment']['owner']==public(10) and int(c['payment']['amount'])==100 and c['mature']<=state['height'])[:1]
        mesh.require(len(inputs)==1,'mature actual input missing')
        draft=natives[0].call('wallet-prepare','--wallet-dir',wallet,'--expected-wallet-head',wallet_head,'--file',file(f'owner-intent-{count}',{'owner':public(10),'inputs':inputs,'outputs':[{'owner':public(10),'amount':'100'}],'fee':'0','valid_for_blocks':8,'remote':None}))
        signed=natives[0].call('wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',draft['wallet_head'],'--review',draft['review_commitment'],'--file',file(f'owner-review-{count}',draft),'--key-file',root/'key-10.json');wallet_head=signed['wallet_head'];file('owner-retained-head',{'wallet_head':wallet_head});return signed['commands']
    context=natives[0].call('bft-context')['context']
    selected={'currency':currency,'region':context['region'],'previous_epoch':context['epoch'],'number':1,'validators':[public(s) for s in new]}
    before=append([*payment(),{'Reconfigure':selected}],old);ledger=before['ledger'];context=natives[0].call('bft-context')['context']
    unsigned=natives[0].call('propose-epoch','--validators',file('new-validators',[public(s) for s in new]));proof=copy.deepcopy(unsigned)
    for n in range(3):
        request={'EpochFence':{'context':context,'proposal':unsigned,'previous_epochs':[]}};out=sign(n,request,old);proof['old_approvals'].append(out['message']['EpochApproval']['approval']);old_responses.append((signers[n],heads[n],request,out['message']))
    for n,seed in enumerate(new[:3]):
        directory=root/f'activation-{seed}';head=natives[n].call('signer-init','--signer-dir',directory,'--key',public(seed))['lock_head'];file(f'activation-head-{n}',{'head':head,'pending':unsigned})
        out=natives[n].call('sign-handoff','--signer-dir',directory,'--expected-lock',head,'--file',file('unsigned-handoff',unsigned),'--key-file',root/f'key-{seed}.json');proof['new_approvals'].append(out['approval']);file(f'activation-head-{n}',{'head':out['lock_head'],'pending':None})
    complete=file('complete-epoch',proof)
    for native in natives:native.call('install-epoch','--file',complete);mesh.require(native.call('status')['ledger']==ledger,'epoch changed value')
    for n,(directory,head,request,message) in enumerate(old_responses):
        out=natives[n].call('bft-sign','--signer-dir',directory,'--expected-head',head,'--file',file(f'recover-fence-{n}',request),'--recover-only');mesh.require(out['recovered_exact_retry'] and out['message']==message,'old fence exact recovery')
        mesh.require(natives[n].call('bft-status','--signer-dir',directory)['state']['epoch_fence'] is not None,'old native fence lost')
    phase='new';initialize(new);after=append(payment(),new);append([],new)
    final=[native.call('status') for native in natives];mesh.require(all(x['height']==6 and x['ledger']['minted']=='300' and len(x['ledger']['imports'])==0 for x in final),'terminal native state differs')
    result={'format':'RLD-BFT-JOINT-EPOCH-CLI-CAMPAIGN-V1','fixture_only':True,'live_rld':False,'native_implementation':package['currency']['implementation'],'currency':currency,'same_host_same_controller':True,'native_replicas':4,'old_durable_fences':3,'new_durable_approvals':3,'certified_old_selection':True,'selection_height':4,'one_old_and_one_new_signer_absent':True,'absent_signers_never_first_signed':True,'absence_is_signer_only_four_native_stores_still_receive_certificates':True,'view_changes':view_changes,'owner_signed_payments':2,'replica_heights':[x['height'] for x in final],'minted':'300','native_cli_signing_and_cold_replay':True,'separately_retained_caller_heads':True,'old_exact_fences_recovered_without_keys':True,'regular_prepare_and_commit_quorum':3,'controller_carried_consensus_messages':True,'autonomous_epoch_ceremony':False,'arbitrary_overlapping_membership':False,'formal_joint_reconfiguration_qualification':False,'full_fault_profile_run':False,'fault_tolerant_reconfiguration_qualified':False,'independent_custody_qualified':False,'physical_route_qualified':False,'generated_private_state_published':False}
    mesh.atomic(report,result);return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    mesh.require(a.binary.is_absolute() and a.root.is_absolute() and a.report.is_absolute(),'absolute paths required')
    print(json.dumps(campaign(a.binary,a.root,a.report)))

if __name__=='__main__':main()
