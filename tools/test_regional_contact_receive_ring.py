"""Packet ordering only; simulated metadata grants no Native authority."""
from types import SimpleNamespace
import unittest

from regional_contact_node import Service, MAX_PER_TICK


def ident(number):return f'{number:064x}'


class Contents:
    def __init__(self,contents):self.contents=list(contents)
    def __iter__(self):return iter(range(len(self.contents)))
    def content(self,key):return self.contents[key]


class ReceiveRingTests(unittest.TestCase):
    def setup_ring(self,novel=range(1,33),background=(100,101)):
        service=Service.__new__(Service)
        service.bft_seen=set();service.progress={'cursor':0}
        service.receive_after={'novel':None,'background':None}
        service.bft=SimpleNamespace(state={'messages':Contents([ident(999)])})
        rows={ident(n):dict(destination=ident(777),kind='regional-bft',export_id=ident(n)) for n in novel}
        rows.update({ident(n):dict(destination=ident(777),kind='regional-bft',export_id=ident(999)) for n in background})
        receipts={key:True for key in rows}
        return service,rows,receipts

    def select(self,service,rows,receipts):
        selected=service.receive_candidates(rows,receipts,ident(777))
        self.assertLessEqual(len(selected),MAX_PER_TICK)
        service.progress['cursor']+=MAX_PER_TICK
        return selected

    def test_successful_removal_does_not_skip_next_waiting_novel_packet(self):
        service,rows,receipts=self.setup_ring()
        first=self.select(service,rows,receipts)
        self.assertEqual(first[:2],[ident(1),ident(2)])
        service.bft_seen.update(first[:2])
        second=self.select(service,rows,receipts)
        self.assertEqual(second[:2],[ident(3),ident(4)])
        # Previous numeric rank stepping skips 3/4 after removing 1/2;
        # keep the concrete rank reference as a regression counterexample.
        remaining=sorted(ident(n) for n in range(3,33))
        old_start=(MAX_PER_TICK//MAX_PER_TICK)*(MAX_PER_TICK//2)%len(remaining)
        self.assertEqual((remaining[old_start:]+remaining[:old_start])[:2],[ident(5),ident(6)])

    def test_inserted_lower_id_waits_for_wrap_without_shifting_the_next_packet(self):
        service,rows,receipts=self.setup_ring(novel=range(1,7))
        first=self.select(service,rows,receipts);service.bft_seen.update(first[:2])
        rows[ident(0)]=dict(rows[ident(3)],export_id=ident(0));receipts[ident(0)]=True
        self.assertEqual(self.select(service,rows,receipts)[:2],[ident(3),ident(4)])
        service.bft_seen.update((ident(3),ident(4)))
        self.assertEqual(self.select(service,rows,receipts)[:2],[ident(5),ident(6)])
        service.bft_seen.update((ident(5),ident(6)))
        self.assertIn(ident(0),self.select(service,rows,receipts))

    def test_independent_nonempty_classes_complete_bounded_static_rotations(self):
        service,rows,receipts=self.setup_ring(novel=range(1,18),background=range(100,119))
        seen_novel=set();seen_background=set()
        for _ in range(10):
            selected=self.select(service,rows,receipts)
            self.assertEqual(len(selected),4)
            seen_novel.update(selected[:2]);seen_background.update(selected[2:])
        self.assertEqual(seen_novel,{ident(n) for n in range(1,18)})
        self.assertEqual(seen_background,{ident(n) for n in range(100,119)})
        self.assertEqual(set(service.receive_after),{'novel','background'})
        self.assertTrue(all(type(value) is str and len(value)==64 for value in service.receive_after.values()))

    def test_changed_complete_proof_stays_novel_and_ordinary_traffic_keeps_slots(self):
        service,rows,receipts=self.setup_ring(novel=(1,2),background=(100,101))
        rows[ident(100)]['kind']='source-sync'
        selected=self.select(service,rows,receipts)
        self.assertEqual(selected[:2],[ident(1),ident(2)])
        self.assertEqual(set(selected[2:]),{ident(100),ident(101)})
        self.assertEqual(service.bft.state['messages'].contents,[ident(999)])
        self.assertEqual(service.bft_seen,set()) # selection cannot grant reception.

    def test_single_class_uses_all_slots_and_restart_resets_only_scheduling(self):
        for novel,background in ((range(1,11),()),((),range(100,110))):
            service,rows,receipts=self.setup_ring(novel,background)
            ordered=sorted(rows)
            self.assertEqual(self.select(service,rows,receipts),ordered[:4])
            self.assertEqual(self.select(service,rows,receipts),ordered[4:8])
            restarted,_,_=self.setup_ring(novel,background)
            self.assertEqual(self.select(restarted,rows,receipts),ordered[:4])

    def test_non_bft_selection_and_missing_destination_receipts_are_unchanged(self):
        service,rows,receipts=self.setup_ring(novel=range(1,11),background=())
        service.bft=None;service.progress['cursor']=4
        rows[ident(1)]['destination']=ident(888);del receipts[ident(2)]
        before=dict(service.receive_after)
        eligible=sorted(ident(n) for n in range(3,11))
        self.assertEqual(self.select(service,rows,receipts),eligible[4:8])
        self.assertEqual(service.receive_after,before)

    def test_current_native_exact_origin_frame_completion_frees_slots_without_hiding_changed_proof(self):
        service,rows,receipts=self.setup_ring(novel=(1,2),background=(100,101))
        rows[ident(100)].update(kind='source-finality',frame_id=ident(900))
        rows[ident(101)].update(kind='source-finality',frame_id=ident(901))
        service._native_origin_messages=frozenset({ident(900)})
        selected=self.select(service,rows,receipts)
        self.assertNotIn(ident(100),selected)
        self.assertIn(ident(101),selected)
        self.assertEqual(service.bft_seen,set())
        service._native_origin_messages=frozenset()
        self.assertIn(ident(100),self.select(service,rows,receipts))


if __name__=='__main__':unittest.main()
