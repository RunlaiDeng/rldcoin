#!/usr/bin/env python3
"""Supplement an exact successful stopped role/payment cold report with absence.

This ground check never opens Native custody, signs, recovers or starts a node.
The separately named complete Native cold report remains the authority check;
this report establishes only absence of the two configured null-era namespaces.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_regional_bft_role_lifecycle import require, verify_absent_role_custody
from verify_regional_bft_sustained import files
from regional_bft_role_fault_scope import Scope


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(args):
    run=json.loads(args.run_report.read_text())
    cold=json.loads(args.cold_report.read_text())
    # Refuse failed/partial/legacy evidence before inspecting private state.
    require(run.get('format')=='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1'
            and run.get('completed') is True and not run.get('failure')
            and run.get('owned_process_cleanup_verified') is True
            and cold.get('format')=='RLD-ROLE-PAYMENT-STOPPED-COLD-V1'
            and cold.get('completed') is True
            and cold.get('all_private_fixture_files_unchanged') is True
            and cold.get('owned_process_cleanup_verified') is True,
            'exact completed stopped role/payment cold reports required')
    manifest=json.loads(args.manifest.read_text())
    Scope(run,cold,manifest,manifest,sha(args.run_report))
    source=args.source.resolve();root=args.root.resolve();binary=args.binary.resolve()
    commitment=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,
                                         separators=(',',':')).encode()).hexdigest()
    require(commitment==manifest['source_set_sha256']==run['runtime_source_set_sha256']
            ==cold['source_set_sha256'] and cold['run_report_sha256']==sha(args.run_report)
            and run['implementation']==cold['native_implementation']==manifest['native_implementation']
            and sha(binary)==run['binary_sha256']==cold['binary_sha256']
            and cold['verifier_sha256']==sha(source/'tools/verify_regional_bft_role_lifecycle.py')
            and cold['source_unchanged'] is True and run['fixture_only'] is True
            and cold['fixture_only'] is True and run['live_rld'] is False
            and cold['live_rld'] is False,
            'exact source/run/cold/binary verification binding required')
    require(len(manifest['files'])==manifest['file_count'], 'complete source inventory required')
    for row in manifest['files']:
        path=source/row['path']
        require(path.resolve().is_relative_to(source)
                and not any(p.is_symlink() for p in [path,*path.parents])
                and path.is_file() and path.stat().st_size==row['size_bytes']
                and sha(path)==row['sha256'], 'sealed source changed')
    for line in subprocess.check_output(['ps','-A','-o','args='],text=True).splitlines():
        executable=Path(line.split()[0]).name if line.split() else ''
        require(not(str(root) in line and (executable=='rld-regional-ledger-candidate'
                or (executable.lower().startswith('python') and 'regional_contact_node.py' in line))),
                'owned fixture still running')
    before=files(root)
    anchor=root/'mesh-inspection-anchors.json'
    require(sha(anchor)==run['mesh_inspection_anchors_sha256']==cold['mesh_inspection_anchors_sha256'],
            'exact setup anchors required')
    anchors=json.loads(anchor.read_text());rows=[]
    for n in range(5):
        config=json.loads((root/f'bft-config-{n}.json').read_text())
        require(config['format']=='RLD-REGIONAL-BFT-NODE-JOINT-ROLES-V1'
                and [h['select_height'] for h in config['handoffs']]==[4,8]
                and [config['validators'],*[h['validators'] for h in config['handoffs']]]
                    ==anchors['role_validators'], 'exact pinned role mapping required')
        carrier=anchors['nodes'][str(n)]['node_id']
        for handoff in config['handoffs']:
            local=[v for v in handoff['validators'] if v['node_id']==carrier]
            require(len(local)<=1 and (handoff['slot'] is None if not local
                    else isinstance(handoff['slot'],dict) and handoff['slot']['key']==local[0]['key']),
                    'null/current local slot differs from setup role mapping')
        rows.extend(verify_absent_role_custody(root,config,n))
    require({(r['carrier'],r['era']) for r in rows}=={(1,2),(4,1)} and len(rows)==2,
            'exact joining/departing null-era slots required')
    require(files(root)==before, 'absence observer changed private bytes or custody')
    return dict(format='RLD-ROLE-KEYLESS-STOPPED-ABSENCE-V1',completed=True,
        fixture_only=True,live_rld=False,source_set_sha256=commitment,
        run_report_sha256=sha(args.run_report),cold_report_sha256=sha(args.cold_report),
        observer_sha256=sha(Path(__file__)),
        absence_validator_sha256=sha(Path(__file__).with_name('verify_regional_bft_role_lifecycle.py')),
        absent_role_custody=rows,all_private_fixture_files_unchanged=True,
        owned_process_cleanup_verified=True,native_or_signing_or_recovery_calls=0,
        historical_custody_preserved=True,full_native_authentication_repeated=False,
        independent_freshness_or_copied_key_custody_qualified=False,
        fresh_full_fault_profile_completed=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','root','binary','run-report','cold-report','report'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    require(not args.report.exists(), 'retain previous observation; new report path required')
    require(not args.report.resolve().is_relative_to(args.root.resolve())
            and not args.report.resolve().is_relative_to(args.source.resolve()),
            'observation report must be outside private fixture and sealed source')
    result=check(args)
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(completed=True,absent_slots=len(result['absent_role_custody']))))


if __name__=='__main__':main()
