"""Finite retention/semantic discriminators, never native qualification."""
import copy
import hashlib
import json
import unittest

import bft_paged_history_model as m


def put_manifest(archive, stream, manifest):
    archive.manifests[stream] = m.canonical(manifest).hex()


def manifest(archive, stream='ledger'):
    return m.decode(bytes.fromhex(archive.manifests[stream]))


def certificate(block, auth, voters=(0, 1, 2), round_number=0):
    payload = m.vote_payload(block, round_number)
    return {'block': block, 'round': round_number,
            'prepare': [auth.issue('prepare', s, payload) for s in voters],
            'commit': [auth.issue('commit', s, payload) for s in voters]}


class PagedHistory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.small = m.build_trace(80)

    def refused_unchanged(self, archive, heads, issued, auth, expected):
        before = archive.inventory()
        with self.assertRaisesRegex(m.Refusal, expected):
            m.replay(archive, heads, issued, auth)
        self.assertEqual(archive.inventory(), before)

    def test_complete_2016_window_and_signer_retention(self):
        archive, heads, issued, auth, counts, old = m.build_trace()
        ledger, signers = m.replay(archive, heads, issued, auth)
        self.assertEqual(ledger.height, 2018)
        self.assertEqual(ledger.channel['close'], 1)
        self.assertEqual(ledger.channel['deadline'], 2017)
        self.assertTrue(ledger.channel['settled'])
        self.assertEqual(ledger.channel['spent'], 2)
        self.assertEqual(ledger.channel['sequence'], 2)
        self.assertEqual(ledger.liquid, issued)
        self.assertEqual(ledger.permanent_imports, {'permanent-export-1'})
        self.assertEqual(ledger.transit, {})
        self.assertEqual(len(ledger.active), 64)
        self.assertTrue(all(len(s.active) == 128 for s in signers))
        self.assertTrue(all(n > 128 for n in counts))
        self.assertEqual(sum(counts), 2018 * 6)
        self.assertEqual(sum(len(list(archive.events(f'voter-{i}', heads[f'voter-{i}'])))
                             for i in m.KEYS), sum(counts))
        self.assertLessEqual(len(archive.objects) + len(archive.manifests), m.FILES)
        raw_bytes = sum(len(v) // 2 for v in archive.objects.values()) + \
            sum(len(v) // 2 for v in archive.manifests.values())
        self.assertLessEqual(raw_bytes, m.ARCHIVE_BYTES)
        self.refused_unchanged(archive, old, issued, auth, 'latest head')
        self.__class__.long_result = {
            'heights': ledger.height, 'close': ledger.channel['close'],
            'deadline': ledger.channel['deadline'], 'last_challenge': 2017,
            'settlement': 2018, 'cumulative_fee': ledger.channel['spent'],
            'retained_signer_records': counts, 'active_ledger_observations': len(ledger.active),
            'active_signer_records': [len(s.active) for s in signers],
            'files': len(archive.objects) + len(archive.manifests), 'retained_bytes': raw_bytes,
            'qualified': 'ideal-authentication retention model only'}

    def test_missing_reordered_corrupt_forward_pages(self):
        base, heads, issued, auth, _, _ = self.small
        for case in ('missing', 'reordered', 'corrupt', 'forward'):
            with self.subTest(case=case):
                archive = copy.deepcopy(base)
                doc = manifest(archive)
                if case == 'missing':
                    del archive.objects[doc['pages'][0]['digest']]
                    expected = 'missing page'
                elif case == 'reordered':
                    doc['pages'][0], doc['pages'][1] = doc['pages'][1], doc['pages'][0]
                    put_manifest(archive, 'ledger', doc)
                    expected = 'ordered page predecessor'
                elif case == 'corrupt':
                    key = doc['pages'][0]['digest']
                    raw = bytearray.fromhex(archive.objects[key])
                    raw[0] ^= 1
                    archive.objects[key] = bytes(raw).hex()
                    expected = 'digest/length'
                else:
                    key = doc['pages'][0]['digest']
                    page = m.decode(bytes.fromhex(archive.objects[key]))
                    page['previous'] = doc['pages'][1]['digest']
                    raw = m.canonical(page)
                    new_key = hashlib.sha256(raw).hexdigest()
                    archive.objects[new_key] = raw.hex()
                    doc['pages'][0] = {'digest': new_key, 'size': len(raw)}
                    put_manifest(archive, 'ledger', doc)
                    expected = 'ordered page predecessor'
                self.refused_unchanged(archive, heads, issued, auth, expected)

    def test_self_consistent_hashes_do_not_authenticate_or_roll_back(self):
        base, heads, issued, auth, _, old = self.small
        # Attack rewrites the entire model archive/head chain consistently, but
        # the separately retained current heads still detect all-file rollback.
        rollback, rollback_heads, _, rollback_auth, _, _ = m.build_trace(64)
        self.refused_unchanged(rollback, heads, issued, rollback_auth, 'latest head')
        self.refused_unchanged(base, old, issued, auth, 'latest head')
        # An invented complete certificate with correct page/head digests has
        # no oracle-authenticated commit statement. Hashes do not authorize it.
        archive = copy.deepcopy(base)
        ledger, _ = m.replay(base, heads, issued, auth)
        operation = {'kind': 'export', 'id': 'never-authenticated-certificate', 'amount': 1}
        block = {'domain': m.DOMAIN, 'genesis': ledger.genesis, 'era': 0,
                 'height': 81, 'parent': ledger.tip,
                 'actions': [{'operation': operation,
                              'authorization': auth.issue('owner', 'model-owner', operation)}]}
        forged = certificate(block, m.IdealAuthentication())
        self.assertNotIn(m.canonical(forged['commit'][0]), auth.statements)
        changed_heads = dict(heads)
        changed_heads['ledger'] = archive.append('ledger', forged)
        self.refused_unchanged(archive, changed_heads, issued, auth, 'authentication absent')
        # Registering this exact statement in the trusted ideal oracle changes
        # the authentication premise. Identical formerly-authenticated bytes
        # must not be mislabeled as a forgery (the initial test fixture did so).
        certificate(block, auth)
        accepted, _ = m.replay(archive, changed_heads, issued, auth)
        self.assertEqual(accepted.height, 81)
        self.assertEqual(accepted.transit['never-authenticated-certificate'], 1)

    def test_complete_invalid_value_tail_is_atomic(self):
        base, heads, issued, auth, _, _ = self.small
        ledger, _ = m.replay(base, heads, issued, auth)
        attacks = [
            {'kind': 'import', 'id': 'permanent-export-1'},
            {'kind': 'challenge', 'sequence': 3, 'generation': 0, 'fee': 1},
            {'kind': 'settle'},
            {'kind': 'challenge', 'sequence': 2, 'generation': 1, 'fee': 2},
        ]
        for op in attacks:
            with self.subTest(operation=op):
                before = copy.deepcopy(ledger.__dict__)
                block = {'domain': m.DOMAIN, 'genesis': ledger.genesis, 'era': 0,
                         'height': 81, 'parent': ledger.tip,
                         'actions': [{'operation': op,
                                      'authorization': auth.issue('owner', 'model-owner', op)}]}
                with self.assertRaises(m.Refusal):
                    ledger.execute(certificate(block, auth), auth)
                self.assertEqual(ledger.__dict__, before)

    def test_old_admission_unknown_era_and_quorum_roles_refuse(self):
        base, heads, issued, auth, _, _ = self.small
        ledger, _ = m.replay(base, heads, issued, auth)
        block = {'domain': m.DOMAIN, 'genesis': ledger.genesis, 'era': 0,
                 'height': 81, 'parent': ledger.tip, 'actions': []}
        for case in ('domain', 'era', 'quorum', 'role', 'duplicate'):
            b = copy.deepcopy(block)
            if case == 'domain':
                b['domain'] = 'RLD-REGIONAL-BFT-FIXTURE-V1'
            elif case == 'era':
                b['era'] = 1
            cert = certificate(b, auth)
            if case == 'quorum':
                cert['commit'] = cert['commit'][:2]
            elif case == 'role':
                cert['commit'] = cert['prepare']
            elif case == 'duplicate':
                cert['commit'][2] = cert['commit'][1]
            before = copy.deepcopy(ledger.__dict__)
            with self.assertRaises(m.Refusal):
                ledger.execute(cert, auth)
            self.assertEqual(ledger.__dict__, before)

    def test_signer_lock_survives_valid_view_change(self):
        base, heads, issued, auth, _, _ = self.small
        ledger, _ = m.replay(base, heads, issued, auth)
        signer = m.Signer(0)
        block = {'domain': m.DOMAIN, 'genesis': ledger.genesis, 'era': 0,
                 'height': 81, 'parent': ledger.tip, 'actions': []}
        previous = 'separately-retained-caller-head'

        def record(b, role, round_number, prev):
            p = m.vote_payload(b, round_number)
            timeout = {k: p[k] for k in ('genesis', 'height', 'parent')}
            timeout['round'] = round_number - 1
            return {'previous': prev, 'request': {
                'role': role, 'payload': p, 'observed': ledger.tip, 'block': b,
                'prepare': [auth.issue('prepare', i, p) for i in (0, 1, 2)] if role == 'commit' else [],
                'timeout': [auth.issue('timeout', i, timeout) for i in (0, 1, 2)] if round_number else []},
                'response': auth.issue(role, 0, p)}

        commit = record(block, 'commit', 0, previous)
        signer.execute(commit, previous, ledger, auth)
        previous = m.digest({'previous': previous, 'event': commit})
        conflict = copy.deepcopy(block)
        op = {'kind': 'export', 'id': 'conflicting-proposal', 'amount': 1}
        conflict['actions'] = [{'operation': op, 'authorization': auth.issue('owner', 'model-owner', op)}]
        before = copy.deepcopy(signer.__dict__)
        with self.assertRaisesRegex(m.Refusal, 'prepare-QC lock'):
            signer.execute(record(conflict, 'prepare', 1, previous), previous, ledger, auth)
        self.assertEqual(signer.__dict__, before)
        # A certified next round on the SAME complete block may continue.
        same = record(block, 'prepare', 1, previous)
        signer.execute(same, previous, ledger, auth)
        self.assertEqual(signer.lock, m.digest(block))
        before = copy.deepcopy(signer.__dict__)
        with self.assertRaisesRegex(m.Refusal, 'previous caller head'):
            signer.execute(same, 'old-caller-head', ledger, auth)
        self.assertEqual(signer.__dict__, before)

    def test_publication_failure_retains_residue_and_refuses(self):
        archive = m.Archive('pinned-model-genesis')
        head = archive.initial_head('ledger')
        for i in range(15):
            head = archive.append('ledger', {'ordered': i})
        old_manifest = dict(archive.manifests)
        with self.assertRaisesRegex(m.Refusal, 'publication interrupted'):
            archive.append('ledger', {'ordered': 15}, interrupt=True)
        self.assertEqual(archive.manifests, old_manifest)
        self.assertEqual(len(archive.objects), 1)
        self.assertIsNotNone(archive.pending)
        before = archive.inventory()
        with self.assertRaisesRegex(m.Refusal, 'incomplete publication'):
            list(archive.events('ledger', head))
        with self.assertRaisesRegex(m.Refusal, 'incomplete publication'):
            archive.append('ledger', {'ordered': 16})
        self.assertEqual(archive.inventory(), before)

    def test_capacity_refusal_and_orphans_count_without_deletion(self):
        for limits, event, expected in [
            (m.Limits(object_bytes=300), {'oversized': 'x' * 500}, 'object capacity'),
            (m.Limits(files=1), {'value': 1}, 'file capacity'),
            (m.Limits(archive_bytes=100), {'value': 1}, 'archive capacity'),
        ]:
            archive = m.Archive('pinned-model-genesis', limits)
            if limits.files == 1:
                archive.objects['retained-orphan'] = m.canonical({'residue': 1}).hex()
            before = archive.inventory()
            with self.assertRaisesRegex(m.Refusal, expected):
                archive.append('ledger', event)
            self.assertEqual(archive.inventory(), before)
        with self.assertRaisesRegex(m.Refusal, 'cannot increase'):
            m.Archive('pinned', m.Limits(files=m.FILES + 1))


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(PagedHistory))
    if hasattr(PagedHistory, 'long_result'):
        print(json.dumps(PagedHistory.long_result, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
