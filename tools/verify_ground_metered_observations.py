"""Bind completed finite measurements to exact sources, run and stopped cold.

Never opens a node or converts a measurement into ledger/signing authority.
The private sample log is read only for bounded anonymous observations.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from regional_ground_resources import MAX_LINE, MAX_LOG, MAX_RECORDS, canonical, digest, require, source_binding


def edges():
    pairs=[]
    for name in ('earth','proxima','andromeda'):
        pairs.extend(((name,n),(name,n+1)) for n in range(3))
    pairs += [(('earth',1),('proxima',1)),(('proxima',1),('andromeda',1))]
    return {f'{a[0]}_{a[1]}_to_{b[0]}_{b[1]}' for first,second in pairs
            for a,b in ((first,second),(second,first))}


def check_meters(rows):
    require(type(rows) is list and len(rows)==22 and {row['label'] for row in rows}==edges(),
            'complete exact 22 directed meter edges required')
    counters=('attempts','refused_connections','forwarded_connections','failed_connections','active_connections',
              'client_to_target_received','client_to_target_sent','target_to_client_received','target_to_client_sent')
    for row in rows:
        require(row['metric_counters_available'] is True and all(type(row[key]) is int and 0<=row[key]<2**63 for key in counters),
                'complete available bounded stream counters required')
        require(row['active_connections']==0 and row['forwarded_connections']+row['refused_connections']==row['attempts']
                and row['failed_connections']<=row['forwarded_connections'], 'terminal connection accounting differs')
        received=row['client_to_target_received']+row['target_to_client_received']
        sent=row['client_to_target_sent']+row['target_to_client_sent']
        require(row['client_to_target_received']>=row['client_to_target_sent']
                and row['target_to_client_received']>=row['target_to_client_sent']
                and row['ciphertext_bytes_forwarded']==sent
                and row['observed_bytes_not_yet_forwarded']==received-sent, 'stream byte accounting differs')
        require(row['max_workers']==2 and row['max_connection_seconds']==4
                and row['max_connection_bytes']==64*1024*1024
                and all(row[key] is False for key in ('TLS_terminated','physical_wire_bytes_measured',
                    'payload_authenticated','custody_acknowledged','ledger_accepted')),
                'meter scope or bounds differ')


def check_log(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size<=MAX_LOG
            and path.stat().st_mode&0o777==0o600,'bounded private resource log required')
    rows=[];previous=None
    with path.open('rb') as stream:
        while True:
            line=stream.readline(MAX_LINE+1)
            if not line:break
            require(len(line)<=MAX_LINE and line.endswith(b'\n') and len(rows)<MAX_RECORDS,
                    'resource log line/record bound or interrupted tail')
            row=json.loads(line)
            require(row['sequence']==len(rows) and row['predecessor_sha256']==previous
                    and canonical(row)+b'\n'==line,'exact canonical resource log chain differs')
            rows.append(row);previous=hashlib.sha256(line).hexdigest()
    require(rows and rows[0]['kind']=='header' and rows[-1]['kind']=='terminal'
            and rows[-1]['observation_completed'] is True and rows[-1]['controller_exit_code']==0
            and rows[-1]['qualification'] is False,'complete observation terminal required')
    samples=[row for row in rows if row['kind']=='sample']
    require(samples,'actual resource samples required')
    prior=None
    for row in samples:
        start,end=row['monotonic_start'],row['monotonic_end']
        require(type(start) in (int,float) and type(end) in (int,float) and math.isfinite(start)
                and math.isfinite(end) and end>=start and (prior is None or start>=prior),
                'resource sample time order differs')
        prior=end
    return rows,samples


def sample_summary(samples):
    return dict(samples=len(samples),
        sampled_max_process_rss_bytes=max((p['rss_bytes'] for row in samples for p in row['processes'] if p['available']),default=None),
        sampled_max_single_process_one_core_cpu_percent=max((p['cpu_one_core_percent'] for row in samples for p in row['processes']
            if p['available'] and p['cpu_one_core_percent'] is not None),default=None),
        unknown_process_samples=sum(not p['available'] for row in samples for p in row['processes']),
        unknown_storage_samples=sum(not p['available'] for row in samples for p in row['storage']),
        interval_overruns=sum(row['interval_overrun'] for row in samples))


def verify(args):
    run=json.loads(args.run_report.read_bytes());cold=json.loads(args.cold_report.read_bytes())
    resources=json.loads(args.resource_report.read_bytes());supplement=json.loads(args.controller_manifest.read_bytes())
    node=json.loads(args.node_manifest.read_bytes())
    require(run['completed'] is True and run['failure'] is None and run['fresh_fault_profile_completed'] is True
            and run['mode']=='fresh_fault_profile' and run['owned_process_cleanup_verified'] is True
            and run['sealed_source_state_unchanged'] is True and run['all_explicit_contact_streams_metered'] is True
            and run['maximum_local_stop_height']==24 and run['phase_observation_bound_seconds']==600,
            'completed exact newly metered finite fault scope required')
    binding=source_binding(args.node_manifest,args.node_source,args.binary,node['source_set_sha256'],supplement['node_binary_sha256'])
    require(hashlib.sha256(canonical(supplement['files'])).hexdigest()==supplement['source_set_sha256'],
            'controller source inventory commitment differs')
    for entry in supplement['files']:
        relative=Path(entry['path'])
        require(not relative.is_absolute() and '..' not in relative.parts,'bounded controller relative source required')
        require(digest(args.controller_source/relative)==(entry['sha256'],entry['size_bytes']),
                'controller source bytes differ')
    sources={Path(row['path']).name:row['sha256'] for row in supplement['files']}
    require(run['drill_source_sha256']==sources['regional_bft_sustained_campaign.py']
            and run['value_auditor_sha256']==sources['regional_ground_value.py']
            and run['contact_meter_sha256']==sources['regional_ground_relay.py'], 'executed controller/helper binding differs')
    require(cold['format']=='RLD-JOINT-SUSTAINED-COLD-VERIFICATION-V1'
            and cold['run_report_sha256']==digest(args.run_report)[0]
            and cold['source_set_sha256']==run['runtime_source_set_sha256']==binding['source_set_sha256']
            and cold['binary_sha256']==binding['binary_sha256'] and len(cold['native_replays'])==12
            and len(cold['recipient_checks'])==4 and len(cold['joint_custody_reads'])==4
            and all(cold[key] is True for key in ('native_replicas_agree','new_export_debit_retained',
                'unique_import_and_original_output_maturity_verified','all_private_fixture_files_unchanged',
                'strict_transport_read_only_entry_used','transport_inspection_private_identity_not_loaded',
                'within_recorded_observation_bounds')), 'exact complete stopped cold evidence required')
    check_meters(run['explicit_contact_stream_meters'])
    checks=run['conservation_checks']
    require(checks and all(row['conserved'] is True and row['compatible_prefixes_verified'] is True
            and int(row['issued'])==int(row['liquid'])+int(row['pending_exports'])
            and len(row['native_read_transcript'])==15
            and hashlib.sha256(canonical(row['native_read_transcript'])).hexdigest()==row['native_read_transcript_sha256']
            for row in checks),'bound Native value observation transcript required')
    rows,samples=check_log(args.private_log)
    require(all(resources[key]==value for key,value in sample_summary(samples).items()),
            'resource summary differs from complete retained samples')
    require(rows[0]['binding']['source_set_sha256']==binding['source_set_sha256']
            and rows[0]['binding']['binary_sha256']==binding['binary_sha256']
            and rows[0]['binding']['sampler_sha256']==sources['regional_ground_resources.py']
            and resources['source_set_sha256']==binding['source_set_sha256']
            and resources['controller_source_set_sha256']==supplement['source_set_sha256']
            and resources['run_report_sha256']==digest(args.run_report)[0]
            and resources['private_log_sha256']==digest(args.private_log)[0] and resources['samples']==len(samples),
            'exact resource log/source/run bindings required')
    return dict(format='RLD-GROUND-METERED-EVIDENCE-BINDING-V1',fixture_only=True,live_rld=False,
                completed_finite_metered_scope_and_stopped_cold_bound=True,
                source_set_sha256=binding['source_set_sha256'],controller_source_set_sha256=supplement['source_set_sha256'],
                run_report_sha256=digest(args.run_report)[0],cold_report_sha256=digest(args.cold_report)[0],
                resource_report_sha256=digest(args.resource_report)[0],directed_contact_meters=22,
                phase_native_value_observations=len(checks),resource_samples=len(samples),
                total_hop_ciphertext_bytes_forwarded=sum(row['ciphertext_bytes_forwarded'] for row in run['explicit_contact_stream_meters']),
                transport_bytes_do_not_prove_ledger_delivery=True,continuous_resource_peaks_measured=False,
                short_lived_native_children_complete=False,sustained_BFT_liveness_qualified=False,
                independent_operators_qualified=False,physical_route_qualified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('run_report','cold_report','resource_report','private_log','controller_manifest','controller_source',
                 'node_manifest','node_source','binary','report'):
        parser.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    args=parser.parse_args()
    require(not args.report.exists() and not args.report.is_symlink(),'retain existing measurement verification report')
    value=verify(args)
    with args.report.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')


if __name__=='__main__':main()
