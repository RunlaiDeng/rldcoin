#!/usr/bin/env python3
"""Stopped role fixture: full native prefixes, envelopes, separate heads/custody.

Read only. No signing, initialization recovery, proof application or Runtime
startup; private files and generated identities never enter the report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(ok,reason):
    if not ok:raise ValueError(reason)


def read_native_wallet_metadata(wallet):
    """Read bounded Rust metadata for comparison with a native-validated view.

    This JSON observation is never signing or ledger authority. Rust struct
    field order differs from mesh canonical JSON; duplicates remain forbidden.
    Pending publication must refuse before wallet-view can recover it.
    """
    wallet=Path(wallet)
    require(not (wallet/'wallet.next').exists() and not (wallet/'wallet.next').is_symlink(),
            'pending native wallet publication; preserve stopped custody')
    path=wallet/'wallet.json'
    require(path.is_file() and not path.is_symlink(), 'unsafe native wallet metadata')
    require(path.stat().st_size<=8*1024*1024, 'native wallet metadata byte bound')
    raw=path.read_bytes()
    require(len(raw)<=8*1024*1024, 'native wallet metadata byte bound')
    def pairs(rows):
        value={}
        for key,item in rows:
            require(key not in value, 'duplicate native wallet JSON field')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:require(False,'invalid native wallet JSON constant'))


DRILL_FORMAT='RLD-ROLE-MISSING-LEADER-GROUND-V1'


def run_profile(run):
    """Explicit finite drill scope, separate from a fresh payment/full fault run."""
    require(run.get('format') in (DRILL_FORMAT,'RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1',
                                  'RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1'),
            'explicit role observation profile required')
    drill=run.get('format')==DRILL_FORMAT
    payment=drill or run.get('format')=='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1'
    if drill:
        require(type(run.get('final_height')) is int and 15<=run['final_height']<=18
                and run.get('initial_height')==14
                and type(run.get('absent_carrier')) is int and run['absent_carrier'] in (0,4)
                and run.get('node_process_starts')==9
                and run.get('post_activation_missing_leader_only') is True
                and run.get('offline_carrier_private_files_unchanged') is True
                and run.get('sealed_source_state_unchanged') is True
                and run.get('fresh_full_fault_profile_completed') is False,
                'exact finite post-activation missing-leader drill required')
    return payment,drill,run['final_height'] if drill else (14 if payment else 4)


def verify_ground_config(config,final_height):
    require(type(config.get('round_timeout')) is int and config['round_timeout']==20
            and type(config.get('block_interval')) is int and config['block_interval']==1
            and type(config.get('stop_height')) is int and config['stop_height']==final_height,
            'exact original ground timing and stop-height configuration required')


def verify_role_mapping(config,context,anchors,carrier):
    """Compare configuration with setup anchors and actual native admissions."""
    maps=[config['validators'],*[h['validators'] for h in config['handoffs']]]
    require(maps==anchors['role_validators'],'configured role carriers differ from setup anchors')
    ids={row['node_id'] for row in anchors['nodes'].values()}
    keys=[context['initial_keys'],*[e['statement']['validators'] for e in context['epochs']]]
    require(len(keys)==len(maps)==3,'native role era count differs')
    for number,(mapping,native_keys) in enumerate(zip(maps,keys)):
        require(all(set(row)=={'key','node_id'} for row in mapping)
                and [row['key'] for row in mapping]==native_keys
                and len(set(row['key'] for row in mapping))==len(mapping)==4
                and len(set(row['node_id'] for row in mapping))==4
                and all(row['node_id'] in ids for row in mapping),
                'role mapping differs from complete native certified membership')
        local=next((row['key'] for row in mapping if row['node_id']==carrier),None)
        slot=config['initial_slot'] if number==0 else config['handoffs'][number-1]['slot']
        # This exact fixture intentionally has no initial signer on carrier 0.
        missing_initial=number==0 and carrier==anchors['nodes']['0']['node_id']
        require(slot is None if local is None or missing_initial else
                isinstance(slot,dict) and slot.get('key')==local,'local role slot differs from pinned carrier')


def verify_absent_role_custody(root,config,carrier):
    """Fixture-only absence check; never create, open or recover signing state."""
    require(type(carrier) is int and 0<=carrier<5 and len(config['handoffs'])==2,
            'exact five-carrier two-handoff custody scope required')
    rows=[]
    for number,handoff in enumerate(config['handoffs'],1):
        if handoff['slot'] is not None:continue
        for stem in ('role-voter','role-ready','role-voter-caller','role-ready-caller'):
            path=Path(root)/f'{stem}-{number}-{carrier}'
            require(not path.exists() and not path.is_symlink(),
                    'keyless role slot has unexpected custody or caller state')
        rows.append(dict(carrier=carrier,era=number,paths_checked=4,
                         paths_absent=True,private_slot_initialized=False))
    return rows


def verify(args):
    stage=args.source.resolve();root=args.root.resolve();binary=args.binary.resolve()
    manifest=json.loads(args.manifest.read_text());run=json.loads(args.run_report.read_text())
    require((getattr(args,'verifier_source',None) is None)==(getattr(args,'verifier_manifest',None) is None),
            'corrected verifier source and manifest must be paired')
    payment_profile,drill_profile,final_height=run_profile(run)
    select_heights=[4,8] if payment_profile else [1,3]
    if payment_profile:
        require(run['runtime_source_set_sha256']==manifest['source_set_sha256'] and run['binary_sha256']==sha(binary)
                and run['campaign_source_sha256']==sha(stage/('tools/regional_bft_role_missing_leader_campaign.py'
                                                       if drill_profile else 'tools/regional_bft_role_payment_campaign.py')),
                'executed ordinary payment source/binary differs')
    require(hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==manifest['source_set_sha256'], 'source commitment changed')
    for row in manifest['files']:
        path=stage/row['path']
        require(not any(p.is_symlink() for p in [path,*path.parents]) and path.is_file()
                and path.stat().st_size==row['size_bytes'] and sha(path)==row['sha256'], 'frozen source changed')
    verifier_manifest=None
    if getattr(args,'verifier_source',None) is not None:
        require(args.verifier_manifest is not None, 'exact corrected verifier manifest required')
        corrected=args.verifier_source.resolve()
        verifier_manifest=json.loads(args.verifier_manifest.read_text())
        require(len(verifier_manifest['files'])==verifier_manifest['file_count']
                ==len([p for p in corrected.rglob('*') if p.is_file()]),
                'complete corrected verifier inventory required')
        require(Path(__file__).resolve()==corrected/'tools/verify_regional_bft_role_lifecycle.py',
                'execute exact sealed corrected verifier')
        require(hashlib.sha256(json.dumps(verifier_manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==verifier_manifest['source_set_sha256'],
                'corrected verifier commitment changed')
        from regional_bft_role_fault_scope import protected_paths
        old={r['path']:r for r in manifest['files']};new={r['path']:r for r in verifier_manifest['files']}
        require(all(new.get(name)==old[name] for name in protected_paths(manifest)),
                'corrected verifier changed native or ordinary runtime')
        for row in verifier_manifest['files']:
            path=corrected/row['path']
            require(path.is_file() and not any(p.is_symlink() for p in [path,*path.parents])
                    and path.stat().st_size==row['size_bytes'] and sha(path)==row['sha256'],
                    'corrected verifier frozen source changed')
    else:
        require(Path(__file__).resolve()==stage/'tools/verify_regional_bft_role_lifecycle.py',
                'exact sealed verifier or explicit correction binding required')
    require(run['format'] in ('RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1','RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1',DRILL_FORMAT) and run['completed'] is True
            and run['owned_process_cleanup_verified'] is True and run['fixture_only'] is True and run['live_rld'] is False
            and run['carriers']==5 and run['configured_handoffs']==2 and run['final_height']==final_height
            and type(run['controller_authority_calls']) is int and run['controller_authority_calls']==0
            and run['implementation']==manifest['native_implementation'],
            'completed exact ordinary role fixture required')
    for line in subprocess.check_output(['ps','-A','-o','args='],text=True).splitlines():
        require(not(str(root) in line and (line.startswith(str(binary)) or 'regional_contact_node.py' in line)), 'owned fixture still running')
    sys.path.insert(0,str(stage/'tools'))
    import interstellar_mesh as mesh
    from interstellar_mesh_inspection import MeshInspection
    from regional_bft_retention import unpack_state
    from regional_contact_node import Native
    from verify_regional_bft_sustained import files
    from regional_bft_joint_roles import FORMAT,RULES,APPROVAL
    before=files(root)
    anchor_path=root/'mesh-inspection-anchors.json'
    require(sha(anchor_path)==run['mesh_inspection_anchors_sha256'],'setup inspection anchors changed')
    anchors=mesh.load(anchor_path,65536)
    require(set(anchors)=={'format','network','role_validators','nodes'}
            and anchors['format']=='RLD-ROLE-MESH-INSPECTION-ANCHORS-V1'
            and anchors['network']==run['currency'] and set(anchors['nodes'])==set(map(str,range(5)))
            and len({row['node_id'] for row in anchors['nodes'].values()})==5,'inspection setup domain differs')
    package=json.loads((root/'bootstrap.json').read_text());currency=package['admissions'][0]['currency'];authority=package['currency']['authority']
    require(currency==run['currency'] and package['currency']['implementation']==manifest['native_implementation'], 'native implementation/currency differs')
    native_rows=[];custody_rows=[];retention_rows=[];archive_rows=[];absent_rows=[];states=[]
    with tempfile.TemporaryDirectory(prefix='rld-role-cold-input-') as scratch:
        input_path=Path(scratch)/'envelope.json'
        for n in range(5):
            ledger=root/f'earth-{n}'
            require((ledger/'INCIDENT_GUARD').read_bytes()==bytes(32), 'pending incident needs separate reconciliation')
            native=Native(binary,ledger,authority,currency);state=native.call('status');context=native.call('bft-context')
            require(state['fixture_only'] is True and state['live_rld'] is False and state['height']==final_height and state['currency']==currency
                    and context['rules']==RULES and context['active_epoch_proof']['statement']['number']==2
                    and len(context['epochs'])==2, 'native cold prefix/era differs')
            config=mesh.load(root/f'bft-config-{n}.json',65536)
            verify_ground_config(config,final_height)
            require(config['format']==FORMAT and [h['select_height'] for h in config['handoffs']]==select_heights,
                    'role configuration differs')
            with MeshInspection(mesh.load(root/f'mesh-config-{n}.json',65536),**anchors['nodes'][str(n)]) as node:
                carrier=node.id
                inventory,total=node.archive_inventory()
                archive_rows.append(dict(carrier=n,archived_records=len(node.state['archives']),retained_files=len(inventory),retained_bytes=total,full_cold_authentication=True))
            verify_role_mapping(config,context,anchors,carrier)
            if drill_profile:
                from regional_bft_joint_fault_profile import missing_leader_gate
                absent_id=anchors['nodes'][str(run['absent_carrier'])]['node_id']
                absent_keys=[v['key'] for v in config['handoffs'][1]['validators'] if v['node_id']==absent_id]
                require(len(absent_keys)==1 and missing_leader_gate(14,context['keys'],absent_keys[0])==final_height,
                        'native selected membership/missing-leader gate differs')
                proof=native.call('proof')
                closing=[s for s in proof['snapshots'] if s['statement']['height']==final_height]
                require(any(s['bft']['prepared']['round']>0
                        and len(s['bft']['prepared']['votes'])==3
                        and len(s['bft']['committed']['votes'])==3
                        and all(absent_keys[0] not in [v['approval']['key'] for v in s['bft'][phase]['votes']]
                                for phase in ('prepared','committed'))
                        and hashlib.sha256(mesh.evidence.canonical(s)).hexdigest()==run['missing_leader_checkpoint_sha256']
                        for s in closing),
                        'full native missing-leader certified checkpoint differs')
            absent_rows.extend(verify_absent_role_custody(root,config,n))
            retained=unpack_state(mesh.load(Path(config['state'])/'state.json',32*1024*1024))
            require(set(retained)=={'format','binding','messages','height','tip','snapshot_cache','cursor'}
                    and retained['format']==FORMAT and retained['binding']==dict(currency=currency,region=state['region'],node_id=carrier)
                    and retained['height']==final_height and retained['tip']==state['tip'], 'retained role runtime observation differs')
            mesh.integer(retained['cursor'],0,2**63-1)
            require(isinstance(retained['snapshot_cache'],list) and len(retained['snapshot_cache'])<=64, 'retention snapshot cursor capacity')
            for ident in retained['snapshot_cache']:mesh.hex32(ident)
            count=0
            for ident in retained['messages']:
                raw=retained['messages'].payload(ident);input_path.write_bytes(raw)
                checked=native.call('bft-network-check','--file',input_path)
                require(checked['value']==retained['messages'].record(ident)['value'], 'complete retained envelope native value differs')
                count+=1
            retention_rows.append(dict(carrier=n,complete_envelopes_authenticated=count,full_native_authentication=True))
            local_slots=[config['initial_slot'],*[h['slot'] for h in config['handoffs']]]
            for number,slot in enumerate(local_slots):
                if slot is None:continue
                for field in ('head_file','signer_dir',*(('ready_head','ready_dir') if number else ())):
                    p=Path(slot[field]);require(p.resolve().is_relative_to(root), 'private custody path escapes fixture')
                head=mesh.load(Path(slot['head_file']),8*1024*1024)
                signer=native.call('bft-status','--signer-dir',slot['signer_dir'])
                binding=dict(currency=currency,region=state['region'],key=slot['key'])
                require(head['binding']==signer['binding']==binding and head['head']==signer['head']
                        and head['format']==FORMAT and head['pending'] is None and head['outbox'] is None
                        and (not number or head['initialization'] is None), 'independent native voter/caller head unresolved')
                creation_epoch=[context['epochs'][0]['statement']['previous_epoch'],context['epochs'][1]['statement']['previous_epoch'],context['context']['epoch']][number]
                require(signer['creation']['pin']['epoch']==creation_epoch
                        and signer['creation']['pin']['height']==(0 if not number else config['handoffs'][number-1]['select_height']),
                        'native voter creation differs from configured era boundary')
                if number<2:
                    fence=(context['epochs'][1]['statement']['previous_epoch'] if number==0 else context['context']['epoch'])
                    require(signer['state']['epoch_fence']==fence, 'old voting custody lacks exact native next-era fence')
                if number:
                    ready_head=mesh.load(Path(slot['ready_head']),8*1024*1024)
                    ready=native.call('joint-ready-status','--ready-dir',slot['ready_dir'])
                    require(ready_head['head']==ready['head'] and ready_head['native_binding']==ready['binding']
                            and ready_head['pending'] is None and ready_head['outbox'] is None and ready_head['initialization'] is None
                            and ready['approved'] is True and ready['binding']['key']==slot['key']
                            and ready['scope']==dict(format=APPROVAL,**ready_head['scope'],role='New',approval=dict(key=slot['key'],signature=''))
                            and ready['approval']['proposal']['statement']['number']==number,
                            'purpose-bound readiness/caller head unresolved')
                custody_rows.append(dict(carrier=n,era=number,voter_head_matches=True,readiness_head_matches=bool(number),
                                         native_records=signer['records'],full_native_cold_custody_authentication=True))
            states.append(state);native_rows.append(dict(carrier=n,height=final_height,active_role_era=2,full_genesis_replay=True))
        wallet_rows=[]
        if payment_profile:
            from regional_contact_campaign import public
            from regional_bft_role_payment_campaign import PAYMENTS,FORMAT as PAYMENT_FORMAT
            require(run['owner_signing_eras']==[0,1,2] and run['select_heights']==select_heights
                    and run['node_process_starts']==(9 if drill_profile else 20) and len(run['owner_payments'])==3,
                    'exact three-era ordinary payment profile differs')
            for owner,recipient,amount,height,era in PAYMENTS:
                row=run['owner_payments'][era]
                head=mesh.load(root/f'payment-caller-{era}/head.json',8*1024*1024)
                wallet=root/f'payment-wallet-{era}'
                journal=read_native_wallet_metadata(wallet)
                view=native.call('wallet-view','--wallet-dir',wallet,'--expected-wallet-head',head['head'])
                require(len(journal['records'])==1 and len(view['signed'])==1, 'one exact retained owner signature required')
                record=journal['records'][0];draft=record['draft'];intent=view['signed'][0]['intent']
                binding=dict(currency=currency,region=states[0]['region'],owner=public(owner))
                expected_outputs=[dict(owner=public(recipient),amount=str(amount))]
                change=int(draft['selected_input_total'])-amount-1
                require(change>=0 and draft['change']==str(change), 'exact actual-owner change conservation differs')
                if change:expected_outputs.append(dict(owner=public(owner),amount=str(change)))
                signing_epoch=[context['epochs'][0]['statement']['previous_epoch'],context['epochs'][1]['statement']['previous_epoch'],context['context']['epoch']][era]
                require(head['format']==PAYMENT_FORMAT and head['binding']==journal['binding']==binding and head['pending'] is None
                        and head['head']==view['wallet_head'] and head['intent_id']==draft['intent_id']==row['intent_id']==view['signed'][0]['intent_id']
                        and draft['pin']['height']==height and draft['pin']['epoch']==signing_epoch and draft['intent']==intent
                        and intent['outputs']==expected_outputs and intent['fee']=='1'
                        and intent['destination'] is None and intent['remote'] is None and intent['destination_fee']=='0'
                        and row['era']==era and row['signing_height']==height and row['owner']==public(owner) and row['recipient']==public(recipient)
                        and row['amount']==str(amount) and row['fee']=='1' and row['selected_input_total']==draft['selected_input_total']
                        and row['native_included'] is True and row['signature_and_submission_did_not_debit'] is True
                        and view['signed'][0]['state']=='INCLUDED_IN_LOCAL_LEDGER' and view['signed'][0]['retained_approvals_complete'] is True
                        and view['reserved_owned_outputs']=='0' and not view['local_region_quarantined']
                        and all(i not in states[0]['ledger']['coins'] for i in intent['inputs']),
                        'native owner history/inclusion/external head/current reservation differs')
                wallet_rows.append(dict(era=era,signing_height=height,full_native_owner_replay=True,
                                        native_included=True,old_inputs_consumed=True,reserved_owned_outputs='0'))
            head=mesh.load(root/'payment-recipient-caller/head.json',8*1024*1024)
            read_native_wallet_metadata(root/'payment-recipient-wallet')
            view=native.call('wallet-view','--wallet-dir',root/'payment-recipient-wallet','--expected-wallet-head',head['head'])
            require(head['format']==PAYMENT_FORMAT and head['pending'] is None and view['ledger']['owner']==public(16)
                    and head['binding']==dict(currency=currency,region=states[0]['region'],owner=public(16))
                    and view['wallet_head']==head['head'] and view['available']=='10' and view['ledger']['immature']=='0'
                    and view['reserved_owned_outputs']=='0' and view['signed']==[] and not view['local_region_quarantined'],
                    'final recipient current native spendability differs')
            for owner,amount in ((14,9),(15,9),(16,10)):
                coins=[c for c in states[0]['ledger']['coins'].values() if c['payment']['owner']==public(owner)]
                require(sum(int(c['payment']['amount']) for c in coins)==amount
                        and all(c['mature']<=final_height for c in coins), 'current recipient balances/maturity differ')
    require(all(state==states[0] for state in states), 'five native replicas disagree')
    ledger=states[0]['ledger'];liquid=sum(int(c['payment']['amount']) for c in ledger['coins'].values())
    require(int(ledger['minted'])==300==liquid and ledger['exports']=={} and ledger['imports']=={}, 'canonical native conservation differs')
    require(files(root)==before, 'cold verifier changed private bytes/ownership/permissions/link counts')
    return dict(format='RLD-ROLE-MISSING-LEADER-STOPPED-COLD-V1' if drill_profile else ('RLD-ROLE-PAYMENT-STOPPED-COLD-V1' if payment_profile else 'RLD-ROLE-LIFECYCLE-STOPPED-COLD-V1'),completed=True,fixture_only=True,live_rld=False,
                source_set_sha256=manifest['source_set_sha256'],native_implementation=manifest['native_implementation'],
                binary_sha256=sha(binary),run_report_sha256=sha(args.run_report),verifier_sha256=sha(Path(__file__)),
                verifier_source_set_sha256=verifier_manifest['source_set_sha256'] if verifier_manifest else manifest['source_set_sha256'],
                source_unchanged=True,owned_process_cleanup_verified=True,all_private_fixture_files_unchanged=True,
                mesh_inspection_anchors_sha256=sha(anchor_path),strict_transport_read_only_entry_used=True,
                transport_inspection_private_key_or_signing_used=False,role_carrier_maps_native_and_setup_bound=True,
                native_replays=native_rows,custody_reads=custody_rows,retained_envelopes=retention_rows,transport_archives=archive_rows,
                absent_role_custody=absent_rows,
                minted='300',liquid='300',pending_exports='0',conserved=True,
                ordinary_owner_payments_verified=wallet_rows,final_recipient_native_available='10' if payment_profile else None,
                same_host_three_era_owner_payments_verified=payment_profile,
                finite_post_activation_missing_leader_verified=drill_profile,
                ordinary_owner_payment_qualified=False,fresh_full_fault_profile_completed=False,
                real_process_interruption_qualified=False,independent_or_cross_device_custody_qualified=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','root','source','manifest','run-report','report'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('verifier-source','verifier-manifest'):p.add_argument('--'+name,type=Path)
    args=p.parse_args();result=verify(args);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(completed=True,native_replays=len(result['native_replays']),custody_reads=len(result['custody_reads']),
                         complete_envelopes=sum(r['complete_envelopes_authenticated'] for r in result['retained_envelopes']))))


if __name__=='__main__':main()
