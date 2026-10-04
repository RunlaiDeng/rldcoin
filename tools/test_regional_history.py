"""Real native CLI paging, caller-held storage roots and permanent import replay."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from regional_contact_campaign import Campaign, public, save

BINARY=Path(os.environ.get('RLD_CONTACT_BINARY',str(Path(__file__).parent/'regional-ledger/target/debug/rld-regional-ledger-candidate'))).resolve()

class NativeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rld-native-history-cli-')
        self.root=Path(self.temp.name).resolve()/'fixture'
        self.c=Campaign(BINARY,self.root)
    def tearDown(self):
        self.c.cleanup();self.temp.cleanup()
    def files(self):
        return {str(p.relative_to(self.root)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob('*') if p.is_file()}
    def head(self,name='earth'):
        return self.c.cli(name,'history-head')
    def test_current_native_storage_root_replays_and_is_not_independent_freshness(self):
        h=self.head();self.assertTrue(h['logical_native_replay_complete'])
        self.assertFalse(h['independent_latest_state_anchor_qualified'])
        self.assertFalse(h['long_history_qualified']);self.assertFalse(h['live_rld'])
        self.c.mine('earth');h=self.head();before=self.files()
        self.assertEqual(self.c.cli('earth','history-check','--expected-head',h['history_head']),h)
        self.assertEqual(self.files(),before)
    def test_valid_old_manifest_refused_with_latest_external_head_without_mutation(self):
        path=self.root/'earth/journal.json';old=path.read_bytes();self.c.mine('earth');latest=self.head()
        path.write_bytes(old);before=self.files()
        rejected=self.c.cli('earth','history-check','--expected-head',latest['history_head'],success=False)
        self.assertIn('external retained head',rejected['reason']);self.assertEqual(self.files(),before)
        self.assertEqual(self.c.cli('earth','status')['height'],0)
    def test_head_cannot_cross_region_and_pending_incident_refuses_without_reconcile(self):
        h=self.head();before=self.files()
        self.c.cli('proxima','history-check','--expected-head',h['history_head'],success=False)
        self.assertEqual(self.files(),before)
        guard=self.root/'earth/INCIDENT_GUARD';guard.write_bytes(bytes([1])*32);before=self.files()
        failure=self.c.cli('earth','history-check','--expected-head',h['history_head'],success=False)
        self.assertIn('pending incident',failure['reason']);self.assertEqual(self.files(),before)
    def test_missing_referenced_native_page_never_opens_or_repairs_value(self):
        self.c.mine('earth');h=self.head();manifest=json.loads((self.root/'earth/journal.json').read_bytes())
        page=self.root/'earth/history'/(manifest['pages'][0]['hash']+'.json');page.unlink();before=self.files()
        self.c.cli('earth','history-check','--expected-head',h['history_head'],success=False)
        self.assertEqual(self.files(),before)
    def test_original_import_identity_survives_spent_output_and_cold_paged_replay(self):
        for _ in range(4):self.c.mine('earth')
        self.c.certify('earth')
        source=self.c.cli('earth','status')['ledger']
        chosen=sorted(key for key,coin in source['coins'].items() if coin['payment']['owner']==public(10) and int(coin['mature'])<=5)[0]
        self.assertEqual(source['coins'][chosen]['payment']['amount'],'100')
        intent=self.c.intent('earth',[10],remote=('proxima',11,99,1),fee=1,inputs=[chosen])
        self.c.mine('earth',[intent['command']]);self.c.certify('earth')
        eid=intent['export_or_transaction_id'];frame=self.c.cli('earth','contact-export','--export',eid)
        path=self.root/'actual-frame.json';save(path,frame)
        imported=self.c.cli('proxima','contact-apply','--file',path,'--miner',public(10))
        self.assertTrue(imported['import_accepted']);self.c.mine('proxima');self.c.mine('proxima');self.c.certify('proxima')
        spend=self.c.intent('proxima',[11],outputs=[(12,98)])
        self.c.mine('proxima',[spend['command']]);head=self.head('proxima')
        self.assertEqual(head['permanent_import_entries'],1)
        current=self.c.cli('proxima','status');self.assertIn(eid,current['ledger']['imports'])
        self.assertFalse(any(c['payment']['owner']==public(11) for c in current['ledger']['coins'].values()))
        before=self.files();self.c.cli('proxima','history-check','--expected-head',head['history_head'])
        self.assertEqual(self.files(),before)
        duplicate={'Import':{'snapshot':current['ledger']['imports'][eid],'export':eid}}
        failed=self.c.mine('proxima',[duplicate],success=False)
        self.assertIn('permanent import tombstone',failed['reason'])
        self.assertEqual(self.head('proxima'),head);self.c.audit('spent original output retains native permanent import identity')

if __name__=='__main__':unittest.main()
