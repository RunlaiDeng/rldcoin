#!/usr/bin/env python3
"""Finite post-activation ground drill from an exact successful stopped cycle.

No controller consensus signing, recovery, epoch installation or message bus.
The stopped source is preserved; a private same-host copy uses the same fixture
keys with the original process absent. This does not qualify independent custody,
copied-key concurrency, missing handoff approvals or a full fault profile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

import interstellar_mesh as mesh
from interstellar_mesh_inspection import config_commitment
from regional_contact_node import Native
from regional_bft_campaign import Campaign as NativeCampaign
from regional_bft_role_lifecycle_campaign import Campaign as Lifecycle
from regional_bft_role_fault_scope import Scope
from regional_bft_joint_fault_profile import commitment
from regional_bft_network_campaign import COLD_START_OBSERVATION_SECONDS
from regional_contact_campaign import public
from verify_regional_bft_role_lifecycle import DRILL_FORMAT, verify_absent_role_custody, verify_ground_config
from verify_regional_bft_sustained import files


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stopped(root):
    for line in subprocess.check_output(['ps','-A','-o','args='],text=True).splitlines():
        fields=line.split();name=Path(fields[0]).name if fields else ''
        mesh.require(not(str(root) in line and (name=='rld-regional-ledger-candidate'
            or (name.lower().startswith('python') and 'regional_contact_node.py' in line))),
            'source or drill still has owned ordinary node processes')


def inventory_digest(inventory):
    return hashlib.sha256(mesh.evidence.canonical(inventory)).hexdigest()


def carrier_inventory(inventory,carrier):
    """All retained local ledger/transport/runtime and every historical slot."""
    prefixes=(f'earth-{carrier}',f'earth-{carrier}-signer',f'mesh-{carrier}',
              f'bft-runtime-{carrier}',f'caller-head-{carrier}',
              *(f'{stem}-{era}-{carrier}' for era in (1,2) for stem in
                ('role-voter','role-ready','role-voter-caller','role-ready-caller')))
    singles={f'earth-{carrier}-key.json',f'node-{carrier}.log',
             f'bft-config-{carrier}.json',f'mesh-config-{carrier}.json',
             'role-key-62.json' if carrier==0 else 'role-key-63.json'}
    return {p:v for p,v in inventory.items()
            if p in singles or any(p==prefix or p.startswith(prefix+'/') for prefix in prefixes)}


def entry(args):
    run=json.loads(args.run_report.read_text());cold=json.loads(args.cold_report.read_text())
    # Failed evidence must refuse before any source, binary or private access.
    mesh.require(run.get('completed') is True and not run.get('failure')
                 and cold.get('completed') is True
                 and run.get('format')=='RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1'
                 and cold.get('format')=='RLD-ROLE-PAYMENT-STOPPED-COLD-V1',
                 'successful ordinary role/payment and full stopped cold evidence required')
    prior=json.loads(args.cycle_manifest.read_text());current=json.loads(args.manifest.read_text())
    verifier=json.loads(args.cold_verifier_manifest.read_text());verifier_stage=args.cold_verifier_source.resolve()
    scope=Scope(run,cold,prior,current,sha(args.run_report))
    source=args.source.resolve();stage=args.runtime_source.resolve();binary=args.binary.resolve()
    mesh.require(Path(__file__).resolve().parent==stage/'tools',
                 'execute the controller from its exact sealed runtime source')
    root=args.root.absolute()
    mesh.require(not root.exists() and not root.is_symlink() and '..' not in root.parts
                 and not any(p.is_symlink() for p in (args.source,*args.source.parents,args.root,*args.root.parents)),
                 'fresh non-symlink drill target required; preserve interrupted targets')
    mesh.require(not root.is_relative_to(source) and not source.is_relative_to(root),
                 'drill cannot overwrite or nest in stopped source')
    for path in (args.report,args.preflight_report):
        mesh.require(not path.exists() and not path.resolve().is_relative_to(source)
                     and not path.resolve().is_relative_to(root)
                     and not path.resolve().is_relative_to(stage),
                     'fresh reports outside private and sealed source directories required')
    for stage_root,manifest in ((args.cycle_source.resolve(),prior),(stage,current),(verifier_stage,verifier)):
        mesh.require(commitment(manifest)==manifest['source_set_sha256'], 'complete source commitment changed')
        mesh.require(len(manifest['files'])==manifest['file_count'], 'complete sealed source inventory required')
        for row in manifest['files']:
            path=stage_root/row['path']
            mesh.require(path.resolve().is_relative_to(stage_root)
                         and not any(p.is_symlink() for p in (path,*path.parents))
                         and path.is_file() and path.stat().st_size==row['size_bytes']
                         and sha(path)==row['sha256'],'sealed cycle or drill source changed')
    mesh.require(sha(binary)==run['binary_sha256']==cold['binary_sha256']
                 and cold['verifier_sha256']==sha(verifier_stage/'tools/verify_regional_bft_role_lifecycle.py')
                 and cold.get('verifier_source_set_sha256')==verifier['source_set_sha256'],
                 'exact original executable and stopped verifier required')
    stopped(source);stopped(root)
    before=files(source)
    # Authenticate the actual source again at this new custody-use boundary.
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(verifier_stage/'tools'))
    command=[sys.executable,'-B',str(verifier_stage/'tools/verify_regional_bft_role_lifecycle.py'),
             '--binary',str(binary),'--root',str(source),'--source',str(args.cycle_source),
             '--manifest',str(args.cycle_manifest),'--run-report',str(args.run_report),
             '--verifier-source',str(verifier_stage),'--verifier-manifest',str(args.cold_verifier_manifest),
             '--report',str(args.preflight_report)]
    checked=subprocess.run(command,env=env,capture_output=True,check=False)
    mesh.require(checked.returncode==0,'actual full source Native/custody/transport recheck refused: '+
                 checked.stderr.decode(errors='replace')[-1024:])
    fresh=json.loads(args.preflight_report.read_text())
    Scope(run,fresh,prior,current,sha(args.run_report))
    mesh.require(files(source)==before,'stopped source changed during full preflight')
    anchor_path=source/'mesh-inspection-anchors.json';anchors=json.loads(anchor_path.read_text())
    mesh.require(sha(anchor_path)==run['mesh_inspection_anchors_sha256'],'original setup anchors changed')
    configs={n:json.loads((source/f'bft-config-{n}.json').read_text()) for n in range(5)}
    absent=[]
    for n,config in configs.items():
        verify_ground_config(config,14)
        absent.extend(verify_absent_role_custody(source,config,n))
    mesh.require({(r['carrier'],r['era']) for r in absent}=={(1,2),(4,1)},'exact null-role namespaces required')
    package=json.loads((source/'bootstrap.json').read_text())
    native=Native(binary,source/'earth-2',package['currency']['authority'],run['currency'])
    gate=scope.gate(native,configs[2],anchors['nodes'][str(args.absent_carrier)]['node_id'])
    status=native.call('status');mesh.require(status['height']==14,'source no longer at exact stopped boundary')
    stopped(source)
    mesh.require(files(source)==before,'source changed before private copy')
    return run,current,source,root,binary,configs,anchors,before,gate,status['region']


class Campaign(Lifecycle):
    def __init__(self,args):
        (self.prior,self.manifest,self.source,self.root,self.binary,configs,anchors,
         self.source_before,self.gate,self.region)=entry(args)
        self.args=args;self.currency=self.prior['currency'];self.implementation=self.prior['implementation']
        self.regions={'earth':self.region};self.processes={};self.logs=[];self.starts=0
        self.observations=[];self.calls=self.helper_calls=self.rejections=0
        self.controller_authority_calls=0;self.earth_forbidden=False;self.absent=args.absent_carrier
        self.root.mkdir(mode=0o700);marker=self.root/'DRILL_PREPARING';marker.write_bytes(b'PRIVATE SAME-HOST COPY\n')
        shutil.copytree(self.source,self.root,dirs_exist_ok=True)
        mesh.require(files(self.source)==self.source_before,'source changed during exact private copy')
        self.configs={n:dict(Scope.rebind(config,self.source,self.root),stop_height=self.gate)
                      for n,config in configs.items()}
        self.ports={};sockets=[]
        try:
            for n in range(5):
                endpoint=socket.socket();endpoint.bind(('127.0.0.1',0));sockets.append(endpoint)
                self.ports[n]=endpoint.getsockname()[1]
        finally:
            for endpoint in sockets:endpoint.close()
        ids={row['node_id']:int(n) for n,row in anchors['nodes'].items()}
        for n in range(5):
            config=json.loads((self.source/f'mesh-config-{n}.json').read_text())
            mesh.require(config['state']==str(self.source/f'mesh-{n}'),'exact original mesh state path required')
            contacts=[]
            for contact in config['contacts']:
                peer=ids[contact['peer']]
                mesh.require(abs(peer-n)==1 and contact['host']=='127.0.0.1','pinned line neighbor required')
                contacts.append(dict(contact,port=self.ports[peer]))
            config=dict(config,state=str(self.root/f'mesh-{n}'),contacts=contacts)
            self.file(f'mesh-config-{n}',config).chmod(0o600)
            self.file(f'bft-config-{n}',self.configs[n]).chmod(0o600)
            anchors['nodes'][str(n)]['config_sha256']=config_commitment(config)
        self.inspection_anchors_path=self.file('mesh-inspection-anchors',anchors)
        self.inspection_anchors_sha256=sha(self.inspection_anchors_path)
        marker.unlink()
        self.offline_before=carrier_inventory(files(self.root),self.absent)
        mesh.require(self.offline_before,'complete offline carrier inventory required')

    def invoke(self,command,success=True,helper=False):
        mesh.require(not helper and success and len(command)>7 and str(command[7]) in
                     {'status','proof','bft-context','bft-status','joint-ready-status','wallet-view'},
                     'controller may only observe existing Native state')
        return NativeCampaign.invoke(self,command,success,helper)

    def cleanup(self):
        errors=[]
        for n,process in list(self.processes.items()):
            try:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill();process.wait(timeout=30)
                mesh.require(process.returncode==0,'owned ordinary node did not exit normally: '+str(n))
            except BaseException as error:errors.append(error)
            finally:
                if process.poll() is not None:self.processes.pop(n,None)
        for log in self.logs:log.close()
        if errors:raise errors[0]

    def start_group(self, carriers):
        """Launch ordinary actors before waiting for each real current-PID cold observation.

        Controller scheduling only. No consensus message, head adoption or
        startup gate is manufactured; launch/readiness failures retain ownership.
        """
        carriers=tuple(carriers)
        mesh.require(len(set(carriers))==len(carriers) and all(type(n) is int and 0<=n<5
                     and n not in self.processes for n in carriers), 'fresh distinct carrier startup required')
        for n in carriers:
            log=(self.root/f'node-{n}.log').open('ab');self.logs.append(log)
            command=[str(self.binary),'--dir',str(self.node('earth',n)),'--authority',public(1),'--currency',self.currency,
                     '--mesh-config',str(self.root/f'mesh-config-{n}.json'),'--bft-config',str(self.root/f'bft-config-{n}.json'),
                     '--mesh-listen','127.0.0.1:'+str(self.ports[n]),'--transport-python',sys.executable,'--interval','0.25']
            self.processes[n]=subprocess.Popen(command,stdout=log,stderr=log)
            self.starts+=1
        for n in carriers:
            self.wait(lambda:self.observation(n)['native_observation_available'],
                      'concurrently launched node startup '+str(n),COLD_START_OBSERVATION_SECONDS)

    def run(self):
        start=time.monotonic();online=tuple(n for n in range(5) if n!=self.absent)
        self.start_group(online)
        self.wait(lambda:self.reached(online,self.gate),'new-era quorum with pinned leader absent',600)
        self.cleanup();self.same_replicas('earth',online)
        mesh.require(carrier_inventory(files(self.root),self.absent)==self.offline_before,
                     'offline carrier ledger/mesh/runtime/historical custody changed')
        proof=self.cli('earth',2,'proof');key=next(v['key'] for v in self.configs[2]['handoffs'][1]['validators']
                                               if v['node_id']==json.loads(self.inspection_anchors_path.read_text())['nodes'][str(self.absent)]['node_id'])
        snapshots=[s for s in proof['snapshots'] if s['statement']['height']==self.gate
                   and s['bft']['prepared']['round']>0 and all(
                       len(s['bft'][phase]['votes'])==3 and key not in [v['approval']['key'] for v in s['bft'][phase]['votes']]
                       for phase in ('prepared','committed'))]
        mesh.require(snapshots,'actual Native certified missing-leader checkpoint required')
        checkpoint_sha=hashlib.sha256(mesh.evidence.canonical(snapshots[0])).hexdigest()
        stopped(self.source);mesh.require(files(self.source)==self.source_before,'original source changed during missing-leader phase')
        self.start_group(range(5))
        self.wait(lambda:self.reached(tuple(range(5)),self.gate),'absent carrier ordinary TLS catchup',600)
        self.cleanup();self.same_replicas('earth',tuple(range(5)))
        mesh.require(self.starts==9,'exact four plus five ordinary process starts required')
        rows=[]
        for n,config in self.configs.items():rows.extend(verify_absent_role_custody(self.root,config,n))
        stopped(self.source);mesh.require(files(self.source)==self.source_before,'sealed original source changed')
        return dict(format=DRILL_FORMAT,completed=True,fixture_only=True,live_rld=False,
            implementation=self.implementation,currency=self.currency,carriers=5,configured_handoffs=2,
            select_heights=[4,8],initial_height=14,final_height=self.gate,absent_carrier=self.absent,
            node_process_starts=self.starts,ordinary_native_startup_used=True,controller_authority_calls=0,
            startup_mode='launch-all-ordinary-processes-before-individual-current-PID-cold-readiness',
            original_cold_start_observation_seconds=COLD_START_OBSERVATION_SECONDS,
            owner_payments=self.prior['owner_payments'],owner_signing_eras=[0,1,2],
            original_payments_preserved_not_reoffered=True,final_recipient_native_available='10',
            post_activation_missing_leader_only=True,fresh_full_fault_profile_completed=False,
            offline_carrier_private_files_unchanged=True,offline_private_inventory_sha256=inventory_digest(self.offline_before),
            sealed_source_state_unchanged=True,sealed_source_inventory_sha256=inventory_digest(self.source_before),
            source_run_report_sha256=sha(self.args.run_report),source_cold_report_sha256=sha(self.args.cold_report),
            fresh_source_preflight_sha256=sha(self.args.preflight_report),
            missing_leader_checkpoint_sha256=checkpoint_sha,absent_role_custody=rows,
            runtime_source_set_sha256=self.manifest['source_set_sha256'],binary_sha256=sha(self.binary),
            campaign_source_sha256=sha(Path(__file__)),mesh_inspection_anchors_sha256=self.inspection_anchors_sha256,
            owned_process_cleanup_verified=True,observations=self.observations,
            duration_seconds=round(time.monotonic()-start,3),same_host=True,
            copied_fixture_keys=True,independent_custody_or_copied_key_concurrency_qualified=False,
            real_process_sigkill_or_power_loss_qualified=False,cross_region_value_qualified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','source','cycle-source','cycle-manifest','runtime-source','manifest',
                 'root','run-report','cold-report','preflight-report','report','cold-verifier-source','cold-verifier-manifest'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--absent-carrier',type=int,choices=(0,4),default=0)
    args=parser.parse_args();campaign=None;result=None
    for path in (args.report,args.preflight_report):
        mesh.require(not path.exists() and not path.is_symlink()
                     and not any(path.resolve().is_relative_to(p.resolve()) for p in
                                 (args.source,args.root,args.cycle_source,args.runtime_source)),
                     'fresh report outside every private and sealed source directory required')
    mesh.require(args.report.resolve()!=args.preflight_report.resolve(),'distinct preflight and result reports required')
    try:
        campaign=Campaign(args);result=campaign.run()
    except BaseException as error:
        result=dict(format=DRILL_FORMAT,completed=False,fixture_only=True,live_rld=False,
                    failure=f'{type(error).__name__}: {error}',fresh_full_fault_profile_completed=False)
        raise
    finally:
        if campaign is not None:
            try:campaign.cleanup()
            except BaseException as error:
                result['completed']=False;result['cleanup_failure']=f'{type(error).__name__}: {error}'
            result['owned_process_cleanup_verified']=not campaign.processes
        if result is not None and not args.report.exists():
            args.report.write_text(json.dumps(result,indent=2)+'\n')
        if result is not None and result.get('cleanup_failure'):
            raise ValueError('ordinary node cleanup failed; retain the reported private target')


if __name__=='__main__':main()
