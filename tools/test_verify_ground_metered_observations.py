"""Evidence association refuses incomplete/fabricated measurement summaries."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from regional_ground_resources import canonical
from verify_ground_metered_observations import check_log,check_meters,edges,sample_summary


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

    def log(self, root, changes=None, truncate=False):
        rows=[dict(kind='header'),dict(kind='sample',monotonic_start=1,monotonic_end=2),
              dict(kind='terminal',observation_completed=True,controller_exit_code=0,qualification=False)]
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


if __name__=='__main__':unittest.main()
