"""Executed controller evidence must bind complete, safe source inventories."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_regional_bft_sustained as verifier


class ControllerBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stage = self.root / 'node'
        self.controller = self.root / 'controller'
        self.manifest_path = self.root / 'controller-manifest.json'
        self.drill = 'tools/regional_bft_sustained_campaign.py'
        self.sources = {
            'drill_source_sha256': self.drill,
            'value_auditor_sha256': 'tools/regional_ground_value.py',
            'contact_meter_sha256': 'tools/regional_ground_relay.py',
        }
        node_drill = self.stage / self.drill
        node_drill.parent.mkdir(parents=True)
        node_drill.write_bytes(b'original node-stage controller\n')
        for name in self.sources.values():
            path = self.controller / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('separate executed controller: ' + name + '\n').encode())
        (self.controller / 'SCOPE.md').write_bytes(b'Complete supplemental inventory.\n')
        self.manifest = self.inventory()
        self.save_manifest()
        self.run = {field: self.digest(self.controller / name)
                    for field, name in self.sources.items()}

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def commitment(rows):
        return hashlib.sha256(json.dumps(rows, sort_keys=True,
                                        separators=(',', ':')).encode()).hexdigest()

    def inventory(self):
        rows = [dict(path=str(path.relative_to(self.controller)),
                     size_bytes=path.stat().st_size, sha256=self.digest(path))
                for path in sorted(self.controller.rglob('*')) if path.is_file()]
        return dict(files=rows, file_count=len(rows), fixture_only=True, live_rld=False,
                    source_set_sha256=self.commitment(rows), node_binary_sha256='1' * 64)

    def save_manifest(self, recommit=False):
        if recommit:
            self.manifest['source_set_sha256'] = self.commitment(self.manifest['files'])
            self.manifest['file_count'] = len(self.manifest['files'])
        self.manifest_path.write_text(json.dumps(self.manifest))

    def bind(self, run=None, source=None, manifest=None):
        return verifier.executed_controller_binding(
            self.stage, self.run if run is None else run,
            self.controller if source is None else source,
            self.manifest_path if manifest is None else manifest)

    def test_complete_separate_controller_passes_without_native_or_process_calls(self):
        node_before = (self.stage / self.drill).read_bytes()
        with patch.object(verifier.subprocess, 'run', side_effect=AssertionError('process call')), \
             patch.object(verifier.subprocess, 'check_output', side_effect=AssertionError('process call')), \
             patch.object(verifier.subprocess, 'Popen', side_effect=AssertionError('process call')):
            result = self.bind()
        self.assertIsInstance(result, dict)
        self.assertEqual(result['source_set_sha256'], self.manifest['source_set_sha256'])
        self.assertEqual(result['manifest_sha256'], self.digest(self.manifest_path))
        self.assertEqual(result['executed_components'], self.sources)
        self.assertTrue(result['complete_inventory_verified'])
        self.assertTrue(result['controller_manifest_node_pin_not_used_as_native_authority'])
        self.assertEqual((self.stage / self.drill).read_bytes(), node_before)
        self.assertNotEqual(self.digest(self.stage / self.drill), self.run['drill_source_sha256'])

    def test_original_manifest_without_declared_count_passes(self):
        del self.manifest['file_count']
        self.save_manifest()
        self.assertTrue(self.bind()['complete_inventory_verified'])

    def test_rotating_probe_requires_exact_policy_and_complete_executed_source(self):
        name='tools/regional_native_receipt_probe.py'
        path=self.controller/name;path.write_bytes(b'fresh rotating native read selection\n')
        self.manifest=self.inventory();self.save_manifest()
        run=dict(self.run,receipt_probe_source_sha256=self.digest(path),
                 controller_native_receipt_observation_policy='fresh_native_replica_rotation_1_2_3_0')
        result=self.bind(run)
        self.assertEqual(result['executed_components']['receipt_probe_source_sha256'],name)
        for field,value in [('receipt_probe_source_sha256','0'*64),
                            ('controller_native_receipt_observation_policy','unknown')]:
            with self.subTest(field=field),self.assertRaises(ValueError):self.bind(dict(run,**{field:value}))
        for field in ('receipt_probe_source_sha256','controller_native_receipt_observation_policy'):
            changed=dict(run);del changed[field]
            with self.subTest(missing=field),self.assertRaises(ValueError):self.bind(changed)
        self.manifest['files']=[row for row in self.manifest['files'] if row['path']!=name]
        self.manifest['file_count']-=1;self.save_manifest(recommit=True)
        with self.assertRaises(ValueError):self.bind(run)

    def test_default_binding_requires_exact_node_stage_drill(self):
        original = dict(drill_source_sha256=self.digest(self.stage / self.drill))
        self.assertIsNone(verifier.executed_controller_binding(self.stage, original))
        with self.assertRaises(ValueError):
            verifier.executed_controller_binding(self.stage, self.run)

    def test_each_executed_component_hash_must_match_separate_inventory(self):
        for field in self.sources:
            with self.subTest(field=field):
                changed = dict(self.run, **{field: '0' * 64})
                with self.assertRaises(ValueError):
                    self.bind(changed)

    def test_each_execution_binding_is_required(self):
        for field in self.sources:
            with self.subTest(field=field):
                changed = dict(self.run)
                del changed[field]
                with self.assertRaises(ValueError):
                    self.bind(changed)

    def test_partial_separate_controller_arguments_refuse(self):
        for source, manifest in ((self.controller, None), (None, self.manifest_path)):
            with self.subTest(source=source, manifest=manifest):
                with self.assertRaises(ValueError):
                    verifier.executed_controller_binding(self.stage, self.run, source, manifest)

    def test_changed_inventory_commitment_refuses(self):
        self.manifest['source_set_sha256'] = '0' * 64
        self.save_manifest()
        with self.assertRaises(ValueError):
            self.bind()

    def test_fixture_domain_and_declared_count_cannot_be_relaxed(self):
        original = copy.deepcopy(self.manifest)
        for changes in ({'fixture_only': False}, {'fixture_only': 1},
                        {'live_rld': True}, {'live_rld': 0}, {'file_count': 3}):
            with self.subTest(changes=changes):
                self.manifest = dict(original, **changes)
                self.save_manifest()
                with self.assertRaises(ValueError):
                    self.bind()

    def test_recommitted_wrong_file_digest_and_size_refuse(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (('sha256', '0' * 64), ('size_bytes', 9999)):
            with self.subTest(field=field):
                self.manifest = copy.deepcopy(original)
                self.manifest['files'][0][field] = value
                self.save_manifest(recommit=True)
                with self.assertRaises(ValueError):
                    self.bind()

    def test_changed_nonexecuted_inventory_file_refuses(self):
        (self.controller / 'SCOPE.md').write_bytes(b'Altered nonexecuted scope.\n')
        with self.assertRaises(ValueError):
            self.bind()

    def test_extra_unlisted_file_and_missing_listed_file_refuse(self):
        extra = self.controller / 'unlisted.py'
        extra.write_bytes(b'unreviewed controller code\n')
        with self.assertRaises(ValueError):
            self.bind()
        extra.unlink()
        (self.controller / 'SCOPE.md').unlink()
        with self.assertRaises(ValueError):
            self.bind()

    def test_recommitted_duplicate_and_omitted_inventory_entries_refuse(self):
        original = copy.deepcopy(self.manifest)
        for rows in (original['files'] + [original['files'][0]], original['files'][1:]):
            with self.subTest(entries=len(rows)):
                self.manifest = dict(original, files=rows)
                self.save_manifest(recommit=True)
                with self.assertRaises(ValueError):
                    self.bind()

    def test_listed_file_symlink_with_exact_target_bytes_refuses(self):
        path = self.controller / 'SCOPE.md'
        target = self.root / 'outside-scope.md'
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.bind()

    def test_source_directory_symlink_refuses(self):
        alias = self.root / 'controller-alias'
        alias.symlink_to(self.controller, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.bind(source=alias)

    def test_source_parent_symlink_refuses(self):
        alias = self.root / 'node-and-controller-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.bind(source=alias / 'controller')

    def test_manifest_symlink_refuses(self):
        alias = self.root / 'manifest-alias.json'
        alias.symlink_to(self.manifest_path)
        with self.assertRaises(ValueError):
            self.bind(manifest=alias)

    def test_manifest_parent_symlink_refuses(self):
        alias = self.root / 'manifest-directory-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.bind(manifest=alias / self.manifest_path.name)

    def test_recommitted_escape_and_absolute_inventory_paths_refuse(self):
        original = copy.deepcopy(self.manifest)
        local = self.controller / 'SCOPE.md'
        outside = self.root / 'outside-scope.md'
        outside.write_bytes(local.read_bytes())
        local.unlink()
        for path in ('../outside-scope.md', str(outside)):
            with self.subTest(path=path):
                self.manifest = copy.deepcopy(original)
                row = next(row for row in self.manifest['files'] if row['path'] == 'SCOPE.md')
                row['path'] = path
                self.save_manifest(recommit=True)
                with self.assertRaises(ValueError):
                    self.bind()


if __name__ == '__main__':
    unittest.main()
