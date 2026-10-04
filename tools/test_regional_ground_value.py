"""Structural observation counterexamples; fake reads grant no Native authority."""
import copy
import hashlib
import unittest

from regional_ground_value import audit_certified_prefixes


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


class ValueObservationTests(unittest.TestCase):
    def setUp(self):
        self.currency = h('currency')
        self.regions = {name:h(name) for name in ('earth','proxima','andromeda')}
        self.states, self.proofs, self.calls = {}, {}, []
        self.export = h('export')
        for name in self.regions:
            for replica in range(4):
                height = 2 if name != 'earth' or replica == 2 else 1
                ledger = dict(minted='100',received='0',coins={h(name+'coin'):dict(payment=dict(amount='100'))},
                              exports={},imports={})
                if name == 'earth' and height == 2:
                    ledger['coins'][h(name+'coin')]['payment']['amount'] = '90'
                    ledger['exports'][self.export] = dict(id=self.export,source=self.regions['earth'],
                        destination=self.regions['proxima'],recipient=dict(amount='10'),destination_fee='1')
                state = dict(currency=self.currency,region=self.regions[name],height=height,
                    tip=h(name+str(height)),state=h(name+'state'+str(height)),ledger=ledger,
                    fixture_only=True,live_rld=False)
                self.states[name,replica] = state
                statement = dict(currency=self.currency,region=self.regions[name],height=height,
                                 block=state['tip'],state=state['state'])
                self.proofs[name,replica] = dict(snapshots=[dict(statement=statement,
                    blocks=[dict(header=dict(parent=h(name+str(i)))) for i in range(height)])])

    def read(self, name, replica, command):
        self.calls.append((name, replica, command))
        return copy.deepcopy((self.states if command == 'status' else self.proofs)[name,replica])

    def audit(self):
        return audit_certified_prefixes(self.read, self.regions, self.currency)

    def test_leading_replica_included_debit_is_counted_with_gross_and_net(self):
        row = self.audit()
        self.assertEqual((row['issued'],row['liquid'],row['pending_exports'],row['pending_export_net_amount']),
                         ('300','290','10','9'))
        self.assertEqual(row['selected_native_checkpoints'][0]['replica'], 2)
        self.assertEqual(len(self.calls), 15)
        self.assertEqual(len(row['native_read_transcript']), 15)
        self.assertTrue(all(call[2] in {'status','proof'} for call in self.calls))
        self.assertFalse(row['custody_or_signing_authority'])
        self.assertFalse(row['request_queue_or_oldest_wait_measured'])

    def test_unique_import_clears_pending_without_releasing_export(self):
        for replica in range(4):
            ledger = self.states['proxima',replica]['ledger']
            ledger['received'] = '10'
            ledger['coins'][h('proximacoin')]['payment']['amount'] = '110'
            ledger['imports'][self.export] = h('certified source checkpoint')
        row = self.audit()
        self.assertEqual((row['liquid'],row['pending_exports'],row['unresolved_export_count']),('300','0',0))
        self.assertEqual(row['observed_export_count'], 1)

    def test_incompatible_equal_height_state_and_lagging_tip_refuse(self):
        for field in ('state','tip'):
            with self.subTest(field=field):
                original = self.states['proxima',3][field]
                self.states['proxima',3][field] = h('different')
                with self.assertRaisesRegex(ValueError,'compatible certified prefix'):
                    self.audit()
                self.states['proxima',3][field] = original

    def test_certificate_state_or_currency_and_segment_base_refuse(self):
        snapshot = self.proofs['earth',2]['snapshots'][0]
        for field in ('state','currency'):
            original = snapshot['statement'][field]
            snapshot['statement'][field] = h('wrong')
            with self.assertRaisesRegex(ValueError,'exact complete certified checkpoint'):
                self.audit()
            snapshot['statement'][field] = original
        snapshot['base'] = h('omitted predecessor')
        with self.assertRaisesRegex(ValueError,'complete genesis-derived prefix'):
            self.audit()

    def test_wrong_native_domain_missing_and_unbounded_height_do_not_become_zero(self):
        state = self.states['earth',0]
        for change in ({'currency':h('other')},{'height':25},{'height':True},{'live_rld':True}):
            saved = dict(state)
            state.update(change)
            with self.assertRaises(ValueError):
                self.audit()
            state.clear();state.update(saved)
        del state['height']
        with self.assertRaises(KeyError):self.audit()

    def test_native_lock_refusal_and_later_invalid_response_do_not_reuse_prior_value(self):
        self.audit()
        def refused(*args):raise ValueError('native rejected: lock acquisition failed')
        with self.assertRaisesRegex(ValueError,'lock acquisition failed'):
            audit_certified_prefixes(refused,self.regions,self.currency)
        self.states['earth',2]['ledger']['coins'][h('earthcoin')]['payment']['amount']='100'
        with self.assertRaisesRegex(ValueError,'conservation failed'):
            self.audit()

    def test_import_without_source_wrong_destination_and_received_counter_refuse(self):
        ledger = self.states['andromeda',0]['ledger']
        for ident, received in ((h('unknown export'),'10'),(self.export,'10')):
            ledger['imports']={ident:h('checkpoint')};ledger['received']=received
            with self.assertRaisesRegex(ValueError,'exact destination export'):
                self.audit()
        ledger['imports']={};ledger['received']='1'
        with self.assertRaisesRegex(ValueError,'received counters'):
            self.audit()

    def test_multiple_valid_checkpoint_variants_are_not_counted_twice(self):
        self.proofs['earth',2]['snapshots'].append(copy.deepcopy(self.proofs['earth',2]['snapshots'][0]))
        self.assertEqual(self.audit()['observed_export_count'], 1)


if __name__ == '__main__':unittest.main()
