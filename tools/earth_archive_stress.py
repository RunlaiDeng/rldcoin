#!/usr/bin/env python3
"""Synthetic archive load. Does not mine or validate monetary history."""
import argparse
import json
import resource
import sys
import time
from pathlib import Path
import earth_history_archive as a


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--records',type=int,default=210001)
    args=parser.parse_args()
    a.require(200001 <= args.records <= 1000000, 'stress record bound')
    identity=dict(role='source',chain_id='1'*64,anchor='1'*64,source_commitment='2'*64)
    parent=identity['anchor']; batch=[]; started=time.monotonic(); forks=0
    with a.Archive(args.output,identity) as archive:
        for height in range(1,args.records+1):
            def record(nonce):
                return a.canonical({'header':dict(chain_id=identity['chain_id'],parent=parent,
                    height=str(height),timestamp=1000+height,target='f'*64,miner='3'*64,
                    commands_root='4'*64,state_root='5'*64,nonce=str(nonce)), 'commands':[]})
            main=record(0)
            if height % 1000 == 0:
                for nonce in range(1,11): batch.append(record(nonce)); forks+=1
            batch.append(main)
            parent=a.block_metadata(main,'source',identity['chain_id'])[0]
            if len(batch)>=256:
                archive.append(batch); batch=[]
            if height % 50000 == 0: print(json.dumps({'synthetic_height':height}),flush=True)
        archive.append(batch)
        archive.artifact('HEAD',parent.encode())
        loaded=time.monotonic(); report=archive.verify(); verified=time.monotonic()
    with a.Archive(args.output) as archive:
        reopened=archive.verify(report['commitment'])
    elapsed=time.monotonic()-started
    assert reopened==report and report['records']==args.records+forks
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_bytes=rss if sys.platform=='darwin' else rss*1024
    report.update(result='SYNTHETIC_ARCHIVE_CAPACITY_PASS', selected_records=args.records,
        side_branch_records=forks, load_seconds=round(loaded-started,3),
        initial_verify_seconds=round(verified-loaded,3), total_seconds=round(elapsed,3),
        peak_process_rss_bytes=rss_bytes, disk_bytes=sum(p.stat().st_size for p in args.output.iterdir() if p.is_file()),
        scope='synthetic byte/ancestry records, bounded SQLite cache; not PoW, node restart, UTXO replay or a live capacity upgrade')
    path=args.output.parent/(args.output.name+'-report.json')
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
