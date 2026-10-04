#!/usr/bin/env python3
"""Real process SIGKILL at shared archive publication boundaries.

Fresh private opaque/no-value transport fixture only; no native ledger, wallet,
signer, socket or old failed fixture is opened. This is not a full fault profile,
power-loss or independent custody qualification. Generated stores stay private.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


PHASES=('frame-durable','wrapper-durable','index-durable')
NETWORK='a'*64


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def pin(args):
    source=args.source.resolve();manifest=json.loads(args.manifest.read_text())
    if hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()!=manifest['source_set_sha256']:
        raise ValueError('runtime source commitment differs')
    for entry in manifest['files']:
        p=source/entry['path']
        if not p.resolve().is_relative_to(source) or any(q.is_symlink() for q in [p,*p.parents]) or not p.is_file() or p.stat().st_size!=entry['size_bytes'] or sha(p)!=entry['sha256']:
            raise ValueError('runtime source bytes differ')
    sys.path.insert(0,str(source/'tools'))
    import interstellar_mesh as mesh
    if mesh.ARCHIVE_STORAGE!='RLD-CONTACT-ARCHIVE-SHARED-FRAME-V1':raise ValueError('shared fixture runtime required')
    return manifest,mesh


def config(root,mesh):return dict(format=mesh.VERSION,state=str(root),network=NETWORK,contacts=[])


def worker(args):
    _,mesh=pin(args)
    import interstellar_transfer as wire
    root=args.root.resolve();mesh.initialize(root,NETWORK,'1'*64,'process-boundary-fixture')
    with mesh.Node(config(root,mesh)) as node:
        node.enqueue(wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,b'{"opaque_no_value_fixture":true}'),node.id)
        archive_write=mesh.archive_write;atomic=mesh.atomic
        def kill():os.kill(os.getpid(),signal.SIGKILL)
        def write(path,raw):
            archive_write(path,raw)
            kind=wire.decode_json(raw)['format']
            if (args.worker=='frame-durable' and kind==mesh.ARCHIVE_FRAME or
                args.worker=='wrapper-durable' and kind==mesh.ARCHIVE_STORAGE):kill()
        def publish(path,value):
            atomic(path,value)
            if args.worker=='index-durable' and path==node.path and value['archives']:kill()
        mesh.archive_write=write;mesh.atomic=publish;mesh.ARCHIVE_HIGH_WATER=1
        node.archive_completed()
    raise ValueError('SIGKILL boundary was not reached')


def verify(args):
    manifest,mesh=pin(args)
    import interstellar_transfer as wire
    root=args.root.resolve()
    if any(p.is_symlink() for p in [root,*root.parents]):raise ValueError('private fixture symlink refused')
    root.mkdir(mode=0o700) # Fresh only; never resume, merge or overwrite.
    rows=[]
    for phase in PHASES:
        directory=root/phase
        command=[sys.executable,'-B',str(Path(__file__).resolve()),'--worker',phase,
                 '--source',str(args.source.resolve()),'--manifest',str(args.manifest.resolve()),'--root',str(directory)]
        with (root/(phase+'.private.log')).open('xb') as log:
            os.chmod(log.name,0o600)
            result=subprocess.run(command,stdout=log,stderr=log,timeout=30)
        if result.returncode!=-signal.SIGKILL:raise ValueError('actual archive SIGKILL not observed: '+phase)
        files={p:(p.read_bytes(),p.stat().st_ino) for p in (directory/'archive').iterdir()}
        expected=1 if phase=='frame-durable' else 2
        if len(files)!=expected:raise ValueError('exact process boundary residue differs')
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        with mesh.Node(config(directory,mesh)) as node:
            indexed=len(node.state['archives']);active=len(node.state['messages'])
            if (indexed,active)!=((1,0) if phase=='index-durable' else (0,1)):
                raise ValueError('interrupted active/index publication differs')
            # Orphans never authorize adoption. The complete authenticated
            # original active packet/receipt supplies only transport recovery.
            if active:
                original=node.state['messages'][next(iter(node.state['messages']))]
                old_high=mesh.ARCHIVE_HIGH_WATER;mesh.ARCHIVE_HIGH_WATER=1
                try:
                    if node.archive_completed()!=1:raise ValueError('retained active archive recovery failed')
                finally:mesh.ARCHIVE_HIGH_WATER=old_high
            else:original=None
            ident=next(iter(node.state['archives']));blob=node.archived(ident)
            if original is not None and blob['transit']!=original:raise ValueError('recovered complete transit changed')
            if node.state['messages'] or node.state['receipts'] or node.status()['payment_authorized']:
                raise ValueError('transport completion/value separation differs')
            inventory,total=node.archive_inventory()
            if len(inventory)!=2 or len(node.state['archives'])!=1:raise ValueError('retained shared object inventory differs')
            # Every typed retained object has exact canonical, scoped bytes;
            # original blobs are independently reconstructed/authenticated above.
            for p in node.archive_root.iterdir():
                raw=p.read_bytes();obj=wire.decode_json(raw)
                if p.name!=hashlib.sha256(raw).hexdigest()+'.json' or raw!=wire.canonical(obj) or obj['network']!=NETWORK or obj['node_id']!=node.id:
                    raise ValueError('retained object bytes/domain differ')
        if any(p.read_bytes()!=raw or p.stat().st_ino!=ino for p,(raw,ino) in files.items()):
            raise ValueError('interruption recovery rewrote original objects')
        before={p:p.read_bytes() for p in directory.rglob('*') if p.is_file()}
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        with mesh.Node(config(directory,mesh)) as node:node.archived(next(iter(node.state['archives'])))
        if any(p.read_bytes()!=raw for p,raw in before.items()):raise ValueError('post-recovery cold read changed private files')
        rows.append(dict(boundary=phase,actual_process_sigkill=True,exit_code=result.returncode,
                         original_objects_retained=expected,original_objects_bytes_and_inodes_unchanged=True,
                         indexed_before_recovery=indexed,active_before_recovery=active,
                         full_original_transport_authentication=True,cold_read_after_recovery=True,
                         retained_files=2,retained_bytes=total,payment_authorized=False))
    pin(args)
    return dict(format='RLD-SHARED-ARCHIVE-PROCESS-BOUNDARIES-V1',completed=True,runtime_source_set_sha256=manifest['source_set_sha256'],
                verifier_sha256=sha(Path(__file__)),phases=rows,fixture_only=True,live_rld=False,
                selected_storage_boundaries_only=True,native_ledger_or_wallet_used=False,socket_or_full_runtime_used=False,
                default_completion_high_water_tested=False,fresh_full_fault_profile_completed=False,
                independent_custody_qualified=False,power_loss_qualified=False,old_failed_fixtures_opened=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',choices=PHASES)
    for field in ('source','manifest','root'):parser.add_argument('--'+field,type=Path,required=True)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if args.worker:worker(args)
    else:
        if args.report is None:parser.error('--report is required')
        result=verify(args);args.report.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(completed=True,actual_sigkill_boundaries=len(result['phases']),native_value_authorized=False)))


if __name__=='__main__':main()
