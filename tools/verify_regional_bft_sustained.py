#!/usr/bin/env python3
"""Cold native/custody verification after a completed no-value fault drill.

Read only after owned processes stop. The separate verifier never signs,
constructs a quorum, applies evidence or installs a checkpoint. It reports only
sanitized projections; private journals, keys, configs and backups stay local.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(root):
    result={};total=0
    for p in root.rglob('*'):
        if p.is_symlink():raise ValueError('private fixture symlink refused')
        if p.is_file():
            s=p.stat();total+=s.st_size
            if len(result)>=65536 or s.st_size>64*1024*1024 or total>6*1024**3:
                raise ValueError('private fixture verification capacity exceeded')
            result[str(p.relative_to(root))]=(sha(p),s.st_uid,s.st_mode,s.st_nlink)
    return result


def verify(args, joint=False):
    stage=args.source.resolve();root=args.root.resolve();binary=args.binary.resolve()
    manifest=json.loads(args.manifest.read_text());run=json.loads(args.run_report.read_text())
    commitment=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if commitment!=manifest['source_set_sha256'] or commitment!=run['runtime_source_set_sha256']:
        raise ValueError('named runtime commitment differs')
    for entry in manifest['files']:
        p=stage/entry['path']
        if not p.resolve().is_relative_to(stage) or any(q.is_symlink() for q in [p,*p.parents]) or not p.is_file() or p.stat().st_size!=entry['size_bytes'] or sha(p)!=entry['sha256']:
            raise ValueError('frozen source changed: '+entry['path'])
    if sha(stage/'tools/regional_bft_sustained_campaign.py')!=run['drill_source_sha256']:
        raise ValueError('executed drill source differs')
    expected_format='RLD-JOINT-BFT-SUSTAINED-GROUND-CAMPAIGN-V1' if joint else 'RLD-REGIONAL-BFT-SUSTAINED-GROUND-CAMPAIGN-V3'
    if run['format']!=expected_format:raise ValueError('explicit fault profile differs')
    if not (run['completed'] and run['fixture_only'] and not run['live_rld']
            and run['sealed_source_state_unchanged'] and run['owned_process_cleanup_verified']):
        raise ValueError('completed stopped no-value drill required; preserve failed evidence')
    if run.get('mode','fresh_fault_profile')!='fresh_fault_profile':
        raise ValueError('retained-payment recovery is separately scoped; fresh full-profile verification refused')
    for field in ('controller_generated_consensus_messages','controller_carried_payment_proofs','controller_installed_checkpoints'):
        if type(run[field]) is not int or run[field]!=0:raise ValueError('controller authority/carriage exceeded declared scope')
    for phase in run['observations']:
        elapsed,bound=phase['elapsed_seconds'],phase['observation_bound_seconds']
        if not (type(elapsed) in (int,float) and type(bound) in (int,float)
                and math.isfinite(elapsed) and math.isfinite(bound) and 0<=elapsed<=bound and bound>0):
            raise ValueError('fault observation outside recorded bounds')
    for line in subprocess.check_output(['ps','-A','-o','args='],text=True).splitlines():
        if str(root) in line and (line.startswith(str(binary)) or
                (line.split() and Path(line.split()[0]).name.lower().startswith('python') and 'regional_contact_node.py' in line)):
            raise ValueError('owned fixture process still running; cold verification refused')
    before=files(root)
    sys.path.insert(0,str(stage/'tools'))
    import interstellar_mesh as mesh
    from interstellar_mesh_inspection import MeshInspection
    from verify_regional_bft_cycle import inspection_anchors
    anchors = inspection_anchors(root, run, path_name='fault-mesh-inspection-anchors.json')
    original_anchors = inspection_anchors(root, dict(run,
        mesh_inspection_anchors_sha256=run['source_mesh_inspection_anchors_sha256']))
    if any(any(anchors['nodes'][name][field] != original_anchors['nodes'][name][field]
               for field in ('public_key', 'node_id', 'network')) for name in anchors['nodes']):
        raise ValueError('fault transport public identities differ from retained source anchors')
    from regional_contact_node import Native
    from regional_bft_retention import verify_stopped_state
    if joint:
        from verify_regional_bft_joint_cycle import verify_custody
        from regional_bft_joint_fault_profile import missing_leader_gate
        if not (run['uses_current_new_voter_journals'] is True and run['keyless_carrier_not_initialized'] is True
                and type(run['controller_generated_epoch_approvals']) is int and run['controller_generated_epoch_approvals']==0
                and type(run['controller_installed_epoch_activation']) is int and run['controller_installed_epoch_activation']==0):
            raise ValueError('joint controller scope differs')
        relays=run['ciphertext_fault_relays']
        if not (len(relays)==2 and all(r['refused_connections']>0 and r['ciphertext_bytes_forwarded']>0
                and r['TLS_terminated'] is False for r in relays)):
            raise ValueError('actual cut/restored encrypted contact observations required')
        offers=run['offered_owner_requests']
        if not (len(offers)==3 and {r['region'] for r in offers}=={'earth','proxima','andromeda'}
                and all(r['owner_approval_released'] is True and r['native_queue_accepted'] is True
                        and r['queue_did_not_debit'] is True for r in offers)):
            raise ValueError('three actual owner-approved requests required')
    bootstrap=json.loads((root/'bootstrap.json').read_text())
    currency=bootstrap['admissions'][0]['currency'];authority=bootstrap['currency']['authority']
    if currency != anchors['network']:
        raise ValueError('native currency differs from retained public transport anchors')
    if bootstrap['currency']['implementation']!=manifest['native_implementation'] or run['native_implementation']!=manifest['native_implementation']:
        raise ValueError('native implementation binding differs')
    expected=json.loads((root/'sustained-receipt-expectation.json').read_text())
    if expected['currency']!=currency or expected['net_amount']!='9':raise ValueError('exact retained payment expectation differs')
    ledgers=[];rows=[];archive_rows=[];receipts=[];retention_rows=[];custody_rows=[];joint_view_change=None
    for name in ('earth','proxima','andromeda'):
        states=[]
        for n in range(4):
            native=Native(binary,root/f'{name}-{n}',authority,currency)
            if (root/f'{name}-{n}'/'INCIDENT_GUARD').read_bytes()!=bytes(32):
                raise ValueError('pending incident recovery needs a separate mutating operation')
            state=native.call('status');states.append(state)
            if not state['fixture_only'] or state['live_rld']:raise ValueError('native fixture domain differs')
            config=mesh.load(root/f'bft-config-{name}-{n}.json',65536)
            if any(not Path(config[field]).resolve().is_relative_to(root) for field in ('state','head_file','signer_dir')):
                raise ValueError('BFT custody path escapes private fixture')
            head=mesh.load(Path(config['head_file']),8*1024*1024)
            signer=native.call('bft-status','--signer-dir',config['signer_dir'])
            binding={'currency':currency,'region':state['region'],'key':config['key']}
            if signer['binding']!=binding or head['binding']!=binding or signer['head']!=head['head'] or head['pending'] is not None or head['outbox'] is not None:
                raise ValueError('caller head/outbox unresolved after claimed quiescence')
            if joint and name=='earth':
                custody_rows.append(verify_custody(native,config,state,signer,head,root,n,run))
                if n==0:
                    current=native.call('bft-context')
                    gate=missing_leader_gate(11,current['keys'],config['joint_epoch']['key'])
                    events=[e for e in run['fault_events'] if e['kind']=='validator_offline']
                    if not (len(events)==1 and events[0]['starting_height']==11
                            and events[0]['missing_leader_successor']==gate
                            and events[0]['minimum_online_height']>=gate
                            and events[0]['native_signer_and_external_head_unchanged'] is True):
                        raise ValueError('actual future missing-leader gate observation differs')
                    snapshots=[s for s in native.call('proof')['snapshots']
                               if s['statement']['region']==state['region'] and s['statement']['height']==gate]
                    absent=config['joint_epoch']['key']
                    if not (snapshots and all(s['bft']['prepared']['round']>0
                            and all(v['approval']['key']!=absent for phase in ('prepared','committed')
                                    for v in s['bft'][phase]['votes']) for s in snapshots)):
                        raise ValueError('current-era native missing-leader view-change certificate absent')
                    joint_view_change=dict(successor_height=gate,native_full_proof_verified=True,
                                           absent_key_not_in_prepare_or_commit=True)
            retention_rows.append(dict(verify_stopped_state(native,config,state,root),region=name,replica=n))
            if name=='earth' and expected['export'] not in state['ledger']['exports']:raise ValueError('original export debit missing')
            if name=='proxima':
                receipt=native.call('wallet-receipt','--file',root/'sustained-receipt-expectation.json')
                if not (receipt['expected']==expected and receipt['import_accepted'] and receipt['maturity_reached']
                        and receipt['original_output_spendable_now'] and receipt['local_finality_covers_import']
                        and not receipt['quarantined'] and receipt['original_output_remaining']=='9'):
                    raise ValueError('native recipient debit/import/maturity binding differs')
                receipts.append(receipt)
            rows.append({'region':name,'replica':n,'height':state['height'],'tip':state['tip'],'native_signer_records':signer['records'],'separate_head_matches':True})
            with MeshInspection(mesh.load(root/f'mesh-config-{name}-{n}.json',65536),
                                **anchors['nodes'][f'{name}-{n}']) as node:
                for ident in node.state['archives']:node.archived(ident)
                inventory,total=node.archive_inventory()
                archive_rows.append({'region':name,'replica':n,'archived_records':len(node.state['archives']),
                                     'retained_files':len(inventory),'retained_bytes':total,'full_cold_authentication':True})
        for state in states[1:]:
            if any(state[k]!=states[0][k] for k in ('height','tip','state','ledger','finality','validator_epoch')):
                raise ValueError('cold native replicas disagree')
        if states[0]['height']!=run['result']['final_heights'][name]:raise ValueError('terminal height differs')
        ledgers.append(states[0]['ledger'])
    issued=sum(int(l['minted']) for l in ledgers)
    liquid=sum(int(c['payment']['amount']) for l in ledgers for c in l['coins'].values())
    transit=sum(int(e['recipient']['amount']) for l in ledgers for e in l['exports'].values())-sum(int(l['received']) for l in ledgers)
    if issued!=liquid+transit or transit<0:raise ValueError('native conservation failed')
    if files(root)!=before:raise ValueError('private fixture changed during read-only verification')
    report={'format':'RLD-JOINT-SUSTAINED-COLD-VERIFICATION-V1' if joint else 'RLD-SUSTAINED-COLD-VERIFICATION-V1','fixture_only':True,'live_rld':False,'same_host_same_controller':True,
            'run_report_sha256':sha(args.run_report),'source_set_sha256':commitment,'verifier_sha256':sha(Path(__file__)),
            'native_implementation':manifest['native_implementation'],'binary_sha256':sha(binary),'native_replays':12,
            'replicas':rows,'native_replicas_agree':True,'recipient_checks':len(receipts),'new_export_debit_retained':True,
            'unique_import_and_original_output_maturity_verified':True,'native_conservation':{'issued':str(issued),'liquid':str(liquid),'in_transit':str(transit),'conserved':True},
            'archive_reads':archive_rows,'all_private_fixture_files_unchanged':True,
            'mesh_inspection_anchors_sha256':sha(root/'fault-mesh-inspection-anchors.json'),
            'strict_transport_read_only_entry_used':True,
            'transport_inspection_private_identity_not_loaded':True,
            'bft_retention_reads':retention_rows,
            'joint_custody_reads':custody_rows,
            'joint_missing_leader_certificate':joint_view_change,
            'within_recorded_observation_bounds':all(p['elapsed_seconds']<=p['observation_bound_seconds'] for p in run['observations']),
            'sustained_BFT_liveness_qualified':False,'independent_operators_qualified':False,'cross_host_qualified':False,'power_loss_qualified':False,'physical_route_qualified':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cold_verified':True,'native_replays':12,'authenticated_archive_records':sum(r['archived_records'] for r in archive_rows)}))


def main(joint=False):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','run-report','binary','root','report'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:verify(args,joint=joint)
    except Exception as error:
        raise SystemExit(str(error).replace(str(args.root.resolve()),'<private-fixture>')) from None


if __name__=='__main__':main()
