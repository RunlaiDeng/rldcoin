"""Evidence association refuses incomplete/fabricated measurement summaries."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from regional_ground_resources import CHILD_CPU_FORMAT,canonical
from verify_ground_metered_observations import check_log,check_meters,edges,sample_summary,storage_summary,child_cpu_summary


class MeteredEvidenceTests(unittest.TestCase):
    def meters(self):
        return [dict(label=label,metric_counters_available=True,attempts=3,refused_connections=1,
                     forwarded_connections=2,failed_connections=1,active_connections=0,
                     client_to_target_received=13,client_to_target_sent=10,target_to_client_received=7,
                     target_to_client_sent=7,ciphertext_bytes_forwarded=17,observed_bytes_not_yet_forwarded=3,
                     max_workers=2,max_connection_seconds=4,max_connection_bytes=64*1024*1024,
                     TLS_terminated=False,physical_wire_bytes_measured=False,payload_authenticated=False,
                     custody_acknowledged=False,ledger_accepted=False) for label in sorted(edges())]

    def test_every_original_configured_direction_and_partial_forwarding_required(self):
        check_meters(self.meters())
        self.assertEqual(len(edges()),22)

    def test_missing_duplicate_extra_and_later_changed_byte_counter_refuse(self):
        original=self.meters()
        for rows in (original[:-1],original+[original[0]],original[:-1]+[original[0]]):
            with self.assertRaises(ValueError):check_meters(rows)
        changed=copy.deepcopy(original);changed[0]['ciphertext_bytes_forwarded']=20
        with self.assertRaisesRegex(ValueError,'byte accounting'):check_meters(changed)

    def test_active_socket_failed_counter_and_ledger_claim_refuse(self):
        for change in ({'active_connections':1},{'metric_counters_available':False},
                       {'client_to_target_sent':True},{'ledger_accepted':True},{'max_workers':3}):
            rows=self.meters();rows[0].update(change)
            with self.assertRaises(ValueError):check_meters(rows)

    def log(self, root, changes=None, truncate=False,exit_code=0):
        rows=[dict(kind='header'),dict(kind='sample',monotonic_start=1,monotonic_end=2),
              dict(kind='terminal',observation_completed=True,controller_exit_code=exit_code,qualification=False)]
        if changes:rows[1].update(changes)
        lines=[];previous=None
        for index,row in enumerate(rows):
            line=canonical(dict(row,sequence=index,predecessor_sha256=previous))+b'\n'
            lines.append(line);previous=hashlib.sha256(line).hexdigest()
        path=root/'log';path.write_bytes(b''.join(lines)[:-1] if truncate else b''.join(lines));path.chmod(0o600)
        return path

    def test_exact_private_chained_log_passes_without_native_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows,samples=check_log(self.log(Path(temporary)))
            self.assertEqual(len(samples),1)
            self.assertFalse(rows[-1]['qualification'])

    def test_failed_terminal_requires_explicit_failed_scope_and_cannot_count_as_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=self.log(Path(temporary),exit_code=1)
            with self.assertRaisesRegex(ValueError,'complete observation terminal'):check_log(path)
            rows,samples=check_log(path,expected_exit=1)
            self.assertEqual(rows[-1]['controller_exit_code'],1)
            self.assertFalse(rows[-1]['qualification'])

    def test_truncated_replaced_chain_and_reversed_times_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with self.assertRaises(ValueError):check_log(self.log(root,truncate=True))
            path=self.log(root);path.write_bytes(path.read_bytes().replace(b'"monotonic_start":1',b'"monotonic_start":0'))
            with self.assertRaisesRegex(ValueError,'chain differs'):check_log(path)
            with self.assertRaisesRegex(ValueError,'time order'):check_log(self.log(root,{'monotonic_start':3}))

    def test_partial_unknowns_are_counted_and_not_invented_as_zero_maxima(self):
        unknown=dict(available=False,rss_bytes=None,cpu_one_core_percent=None)
        row=dict(processes=[unknown],storage=[dict(available=False)],interval_overrun=True)
        result=sample_summary([row])
        self.assertIsNone(result['sampled_max_process_rss_bytes'])
        self.assertIsNone(result['sampled_max_single_process_one_core_cpu_percent'])
        self.assertEqual(result['unknown_process_samples'],1)
        self.assertEqual(result['unknown_storage_samples'],1)

    def test_per_directory_maxima_preserve_unknown_and_non_atomic_scope(self):
        unknown=dict(label='mesh_earth_0',available=False,files=None,logical_file_bytes=None,atomic_snapshot=False)
        first=dict(label='mesh_proxima_0',available=True,files=4,logical_file_bytes=100,atomic_snapshot=False)
        later=dict(first,files=5,logical_file_bytes=90)
        result=storage_summary([dict(storage=[unknown,first]),dict(storage=[unknown,later])])
        self.assertIsNone(result['mesh_earth_0']['sampled_max_files'])
        self.assertEqual(result['mesh_earth_0']['unknown_samples'],2)
        self.assertEqual(result['mesh_proxima_0']['sampled_max_files'],5)
        self.assertEqual(result['mesh_proxima_0']['sampled_max_logical_file_bytes'],100)
        for change in ({'available':1},{'files':True},{'atomic_snapshot':True}):
            with self.assertRaises(ValueError):storage_summary([dict(storage=[dict(first,**change)])])

    def child_samples(self):
        header=dict(format=CHILD_CPU_FORMAT,observer_binding={'exited_child_cpu_sha256':'a'*64},
                    measured=dict(own_plus_exited_child_cpu_requested=True,child_process_tree=False))
        base=dict(label='owned_parent',available=True,monotonic_start=1,monotonic_end=2,
                  own_cpu_lifetime_seconds=1,own_plus_exited_children_cpu_lifetime_seconds=3,
                  own_plus_exited_children_one_core_percent=None,non_atomic_exited_children_estimate_seconds=2,
                  observation_includes_all_live_child_cpu=False,live_child_rss_measured=False,
                  Native_command_census_verified=False,atomic_snapshot=False)
        later=dict(base,monotonic_start=3,monotonic_end=4,own_plus_exited_children_cpu_lifetime_seconds=5,
                   own_plus_exited_children_one_core_percent=100,non_atomic_exited_children_estimate_seconds=4)
        def sample(row):return dict(monotonic_start=row['monotonic_start']-0.1,
                                   monotonic_end=row['monotonic_end']+0.1,
                                   processes=[dict(label='owned_parent')],own_plus_exited_child_cpu=[row])
        return header,[sample(base),sample(later)]

    def test_child_cpu_summary_recomputes_delta_and_never_adds_overlapping_totals(self):
        header,samples=self.child_samples();result=child_cpu_summary(header,samples)
        self.assertEqual(result['processes']['owned_parent']['sampled_max_own_plus_exited_one_core_percent'],100)
        self.assertEqual(result['processes']['owned_parent']['available_samples'],2)
        self.assertFalse(result['overlapping_parent_child_totals_added'])
        self.assertFalse(result['full_live_child_CPU_RSS_covered'])

    def test_child_unknowns_cannot_be_filled_and_gap_cannot_reuse_previous_delta(self):
        header,samples=self.child_samples();unknown=copy.deepcopy(samples[-1])
        row=unknown['own_plus_exited_child_cpu'][0];row['available']=False
        for k in ('own_cpu_lifetime_seconds','own_plus_exited_children_cpu_lifetime_seconds',
                  'own_plus_exited_children_one_core_percent','non_atomic_exited_children_estimate_seconds'):row[k]=None
        result=child_cpu_summary(header,[unknown]);entry=result['processes']['owned_parent']
        self.assertIsNone(entry['sampled_max_own_plus_exited_one_core_percent'])
        self.assertIsNone(entry['sampled_max_exited_children_lifetime_seconds'])
        self.assertEqual(entry['unknown_samples'],1)
        row['own_cpu_lifetime_seconds']=0
        with self.assertRaisesRegex(ValueError,'invented'):child_cpu_summary(header,[unknown])
        row['own_cpu_lifetime_seconds']=None
        with self.assertRaisesRegex(ValueError,'discontinuous'):child_cpu_summary(header,[samples[0],unknown,samples[1]])

    def test_child_scope_labels_bounds_times_and_changed_cpu_refuse(self):
        header,samples=self.child_samples()
        with self.assertRaisesRegex(ValueError,'explicit V2'):child_cpu_summary({},samples)
        for change in ({'label':'private/path'},{'available':1},{'live_child_rss_measured':True},
                       {'monotonic_end':10},{'own_plus_exited_children_one_core_percent':99},
                       {'own_plus_exited_children_cpu_lifetime_seconds':float('nan')},
                       {'non_atomic_exited_children_estimate_seconds':1}):
            altered=copy.deepcopy(samples);altered[1]['own_plus_exited_child_cpu'][0].update(change)
            with self.assertRaises(ValueError):child_cpu_summary(header,altered)
        altered=copy.deepcopy(samples);altered[0]['own_plus_exited_child_cpu']*=33
        with self.assertRaisesRegex(ValueError,'process labels'):child_cpu_summary(header,altered)


if __name__=='__main__':unittest.main()
