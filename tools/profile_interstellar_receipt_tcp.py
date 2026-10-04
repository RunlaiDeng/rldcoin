#!/usr/bin/env python3
"""Fresh no-value ground TLS workload; no native or failed stores are opened.

Fixture setup selects one already authenticated receipt per packet. Measured
exchanges use the ordinary TCP server/tick and complete selected custody checks.
This component measurement is not ordinary consensus or a full fault profile.
"""
import argparse
import hashlib
import json
from pathlib import Path
import threading
import time
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from test_interstellar_tcp import Fixture


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    root=args.root.resolve()
    root.mkdir(mode=0o700)  # Never merge, resume or overwrite a private fixture.
    paths=[Path(module.__file__).resolve() for module in (mesh,tcp,wire)]
    sources={p.name:sha(p) for p in paths}
    fixture=Fixture(root,names=('earth','proxima'))
    try:
        fixture.rounds(2)
        with fixture.node('earth') as source,fixture.node('proxima') as destination:
            for serial in range(args.count):
                raw=wire.make_frame('source-finality','1'*64,'3'*64,'4'*64,
                    wire.canonical(dict(opaque_no_value_fixture='x'*args.payload_bytes,serial=serial)))
                ident=source.enqueue(raw,destination.id)
                destination.receive(source.exchange(destination.id),source.id)
                outgoing=destination.exchange(source.id)
                receipt=destination.receipts()[ident]
                setup=mesh.sign(destination.key,'exchange',{**outgoing['body'],'receipts':[receipt]})
                source.receive(setup,destination.id)
                with patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
                    source.archive_completed();destination.archive_completed()
            mesh.require(len(source.state['archives'])==args.count
                         and len(destination.state['archives'])==args.count,'fixture archives incomplete')
            ident=source.enqueue(fixture.frame(9001),destination.id)
        rows=[];guard=threading.Lock()
        original_receive=mesh.Node.receive;original_outgoing=tcp.outgoing
        original_archive=mesh.Node.archived;original_sync=mesh.sync_retained
        def observed_receive(node,bundle,peer):
            started=time.monotonic()
            try:return original_receive(node,bundle,peer)
            finally:
                with guard:rows.append(dict(operation='receive',receipts=len(bundle['body']['receipts']),
                    transits=len(bundle['body']['transits']),seconds=round(time.monotonic()-started,6)))
        def observed_outgoing(node,peer,accepted_transits=None):
            started=time.monotonic();bundle=original_outgoing(node,peer,accepted_transits)
            with guard:rows.append(dict(operation='prepare',receipts=len(bundle['body']['receipts']),
                transits=len(bundle['body']['transits']),seconds=round(time.monotonic()-started,6)))
            return bundle
        counts=dict(complete_archive_reconstructions=0,retained_file_fsyncs=0)
        def observed_archive(node,ident):
            with guard:counts['complete_archive_reconstructions']+=1
            return original_archive(node,ident)
        def observed_sync(path):
            with guard:counts['retained_file_fsyncs']+=1
            return original_sync(path)
        started=time.monotonic()
        with patch.object(mesh.Node,'receive',observed_receive),patch.object(tcp,'outgoing',observed_outgoing),\
             patch.object(mesh.Node,'archived',observed_archive),patch.object(mesh,'sync_retained',observed_sync):
            result=fixture.servers['earth'].tick()
        elapsed=time.monotonic()-started
        # Servers are closed before inspecting the complete selected custody.
        fixture.close()
        with fixture.node('proxima') as destination:
            delivered=ident in destination.receipts()
            if delivered:destination.transit(ident)
        with fixture.node('earth') as source:
            source_receipted=ident in source.receipts()
        mesh.require({p.name:sha(p) for p in paths}==sources,'profile source changed')
        return dict(format='RLD-RECEIPT-TLS-COMPONENT-PROFILE-V1',source_sha256=sources,
            archived_receipts_per_node=args.count,opaque_payload_bytes=args.payload_bytes,
            tick_seconds=round(elapsed,6),tick_errors=result['errors'],operations=rows,**counts,
            new_transit_destination_custody=delivered,new_transit_source_receipt=source_receipted,
            selected_receipts_fully_authenticated_and_fsynced=True,
            fixture_setup_selected_one_receipt_per_packet=True,actual_loopback_tls13=True,
            fixture_only=True,live_rld=False,failed_private_stores_opened=False,
            native_ledger_or_wallet_used=False,ordinary_consensus_or_full_fault_profile_completed=False,
            independent_or_physical_qualification=False)
    finally:fixture.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--count',type=int,default=128)
    parser.add_argument('--payload-bytes',type=int,default=65536)
    args=parser.parse_args()
    mesh.require(1<=args.count<=mesh.MAX_MESSAGES and 1<=args.payload_bytes<=512*1024,'profile input bound')
    mesh.require(not args.report.exists(),'report already exists')
    result=run(args);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('tick_seconds','tick_errors','complete_archive_reconstructions',
        'retained_file_fsyncs','new_transit_destination_custody','new_transit_source_receipt')}))


if __name__=='__main__':main()
