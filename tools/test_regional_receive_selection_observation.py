"""Real selector with modeled custody; watched metadata grants no Native rights."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from regional_contact_node import Service
from regional_contact_trace import ContactTrace,TraceCursor,MAX_EVENT_BYTES


def ident(n):return format(n,'064x')


class SelectionObservationTests(unittest.TestCase):
    def service(self,watch=None):
        service=Service.__new__(Service)
        class Messages:
            def __iter__(self):return iter(['retained'])
            def content(self,key):return ident(900)
        service.bft=SimpleNamespace(state={'messages':Messages()})
        service.bft_seen=set();service.progress={'cursor':0}
        service.receive_after={'novel':ident(3),'background':None}
        service.contact_trace=ContactTrace(watch_envelope_id=watch)
        service.contact_trace.bind(ident(700),ident(777))
        rows={ident(n):dict(destination=ident(777),kind='regional-bft',
                           export_id=ident(600+n) if n<10 else ident(900))
              for n in range(1,14)}
        receipts={i:{} for i in rows}
        quota=dict(attempted=set(),novel=0,background=0)
        return service,rows,receipts,quota

    def events(self,service):
        value=service.contact_trace.snapshot()
        delta=TraceCursor(ident(700),ident(777)).drain(value)
        self.assertTrue(delta['this_interval_complete'])
        self.assertTrue(all(len(str(row).encode())<=MAX_EVENT_BYTES for row in delta['events']))
        self.assertFalse(value['authority'])
        return delta['events']

    def test_watched_novel_rank_before_cursor_and_quota_changes(self):
        service,rows,receipts,quota=self.service(ident(606))
        chosen=service.receive_candidates(rows,receipts,ident(777),quota)
        self.assertEqual(chosen,[ident(4),ident(5),ident(10),ident(11)])
        row=self.events(service)[0]
        self.assertEqual((row['novel_watch_rank'],row['background_watch_rank']),(3,0))
        self.assertEqual((row['watched_eligible_count'],row['watched_selected_count']),(1,0))
        self.assertEqual((row['novel_count'],row['background_count'],row['remaining_count']),(9,4,4))
        self.assertEqual((quota['novel'],quota['background']),(2,2))
        self.assertEqual(service.receive_after,{'novel':ident(5),'background':ident(11)})
        self.assertEqual(service.bft_seen,set())

    def test_each_missing_receipt_seen_attempted_or_wrong_destination_is_separate(self):
        for reason in ('receipt','seen','attempted','destination'):
            with self.subTest(reason=reason):
                service,rows,receipts,quota=self.service(ident(606))
                if reason=='receipt':receipts.pop(ident(6))
                elif reason=='seen':service.bft_seen.add(ident(6))
                elif reason=='attempted':quota['attempted'].add(ident(6))
                else:rows[ident(6)]['destination']=ident(888)
                service.receive_candidates(rows,receipts,ident(777),quota)
                row=self.events(service)[0]
                self.assertEqual(row['watched_summary_count'],1)
                self.assertEqual(row['watched_eligible_count'],0)
                self.assertEqual(row['watched_selected_count'],0)
                self.assertEqual(row['watched_receipt_count'],0 if reason in ('receipt','destination') else 1)
                self.assertEqual(row['watched_seen_count'],int(reason=='seen'))
                self.assertEqual(row['watched_attempted_count'],int(reason=='attempted'))

    def test_classifier_call_order_quota_and_cursor_identical_when_enabled_or_refused(self):
        results=[]
        for mode in ('disabled','watched','refused'):
            service,rows,receipts,quota=self.service(None if mode=='disabled' else ident(608))
            calls=[]
            def classifier(packet):
                calls.append(packet)
                return 'same-complete-frame' if int(packet,16)<10 else packet
            if mode=='refused':
                with patch.object(service.contact_trace,'event',side_effect=OSError('diagnostic only')):
                    selected=service.receive_candidates(rows,receipts,ident(777),quota,classifier)
                self.assertEqual(service.contact_trace.rejected,1)
            else:selected=service.receive_candidates(rows,receipts,ident(777),quota,classifier)
            results.append((selected,calls,copy.deepcopy(quota),dict(service.receive_after)))
            if mode=='disabled':self.assertEqual(service.contact_trace.sequence,0)
            else:
                if mode=='watched':
                    row=self.events(service)[0]
                    self.assertEqual(row['inspected_count'],4)
                    self.assertEqual(row['selected'],1)
                    self.assertEqual(row['watched_selected_count'],0)
        self.assertEqual(results[0],results[1]);self.assertEqual(results[0],results[2])

    def test_background_copies_selected_without_any_extra_frame_read(self):
        service,rows,receipts,quota=self.service(ident(900))
        chosen=service.receive_candidates(rows,receipts,ident(777),quota)
        row=self.events(service)[0]
        self.assertEqual(row['watched_summary_count'],4)
        self.assertEqual((row['background_watch_rank'],row['watched_selected_count']),(1,2))
        self.assertEqual(row['inspected_count'],0)
        self.assertEqual(len(chosen),4)

    def test_pending_recheck_and_empty_quota_keep_original_selection(self):
        service,rows,receipts,quota=self.service(ident(606))
        service.bft_intake_pending=SimpleNamespace(packets={ident(6)})
        self.assertEqual(service.receive_candidates(rows,receipts,ident(777),quota),[ident(6)])
        row=self.events(service)[0]
        self.assertEqual((row['selection_mode'],row['watched_selected_count']),('pending',1))
        quota['attempted']={ident(n) for n in range(1,5)}
        self.assertEqual(service.receive_candidates(rows,receipts,ident(777),quota),[])
        self.assertEqual(self.events(service)[-1]['selection_mode'],'empty')

    def test_legacy_and_no_quota_preserve_original_returns(self):
        for legacy in (False,True):
            service,rows,receipts,_=self.service(ident(604))
            if legacy:service.bft=None
            chosen=service.receive_candidates(rows,receipts,ident(777))
            self.assertEqual(chosen,[ident(n) for n in ((1,2,3,4) if legacy else (4,5,10,11))])
            row=self.events(service)[0]
            self.assertEqual(row['selection_mode'],'legacy' if legacy else 'classified')

    def test_bad_observer_inputs_refuse_diagnostic_without_changing_selector(self):
        service,rows,receipts,quota=self.service(ident(606))
        rows[ident(14)]=dict(destination=ident(888),kind='regional-bft')
        chosen=service.receive_candidates(rows,receipts,ident(777),quota)
        self.assertEqual(chosen,[ident(4),ident(5),ident(10),ident(11)])
        self.assertEqual(service.contact_trace.sequence,0)
        self.assertEqual(service.contact_trace.rejected,1)
        for bad in ('bad',{},'A'*64):
            with self.assertRaises(ValueError):ContactTrace(watch_envelope_id=bad)


if __name__=='__main__':unittest.main()
