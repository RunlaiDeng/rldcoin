"""Bounded scheduler opportunities; real TLS/custody has a separate component."""
from contextlib import contextmanager
import errno
import threading
import time
import unittest

import interstellar_mesh as mesh
import interstellar_tcp as tcp


class OutboundPeerPhaseTests(unittest.TestCase):
    def refusing_scheduler(self, count):
        server=tcp.Server.__new__(tcp.Server)
        server.guard=threading.Lock();server.running=True;server.cursor=0
        server.peers={format(n+1,'064x'):{'host':'127.0.0.1','port':20000+n}
                      for n in range(count)}
        server.peer_attempts={};server.accepted_transits={};server.contact_trace=None
        server.outbound_owner=None;server.outbound_guard=threading.Lock()
        calls=[]
        @contextmanager
        def unavailable(deadline):
            self.assertGreater(deadline,time.monotonic())
            raise BlockingIOError(errno.EAGAIN,'controlled scheduler-only refusal')
            yield
        server.mesh_node=unavailable
        server.mark=lambda peer,direction,success:calls.append((peer,direction,success))
        server.observation=lambda errors:dict(errors=errors)
        return server,calls

    def test_every_pinned_peer_visits_every_attempt_position_under_periodic_contention(self):
        # No accepted Node/request is fabricated: all attempts are refused.
        # The opportunities are observed through the actual outbound entry.
        for count in range(1,mesh.MAX_CONTACTS+1):
            with self.subTest(contacts=count):
                server,calls=self.refusing_scheduler(count)
                positions={peer:set() for peer in server.peers}
                width=min(count,tcp.MAX_OUTBOUND_PER_TICK)
                for _ in range(count):
                    before=len(calls);server.tick();batch=calls[before:]
                    self.assertEqual(len(batch),width)
                    self.assertEqual(len({x[0] for x in batch}),width)
                    for position,(peer,direction,success) in enumerate(batch):
                        self.assertIn(peer,server.peers)
                        self.assertEqual(direction,'outbound');self.assertFalse(success)
                        positions[peer].add(position)
                # Each peer encounters every one of the available phase slots;
                # a permanently unavailable whole batch still cannot progress.
                self.assertTrue(all(value==set(range(width)) for value in positions.values()))
                self.assertEqual(sum(server.peer_attempts.values()),count*width)

    def test_contact_change_uses_only_current_pinned_endpoints_without_state_adoption(self):
        server,calls=self.refusing_scheduler(8)
        server.tick();removed=sorted(server.peers)[3]
        server.peers.pop(removed)
        new='f'*64;server.peers[new]={'host':'127.0.0.1','port':21000}
        before=len(calls)
        for _ in range(8):server.tick()
        seen={peer for peer,_,_ in calls[before:]}
        self.assertEqual(seen,set(server.peers));self.assertNotIn(removed,seen)
        self.assertIn(new,seen)
        self.assertEqual(server.accepted_transits,{})

    def test_empty_or_stopped_scheduler_creates_no_attempt_or_success(self):
        server,calls=self.refusing_scheduler(0);server.tick()
        self.assertEqual(calls,[]);self.assertEqual(server.cursor,0)
        server,calls=self.refusing_scheduler(4);server.running=False;server.tick()
        self.assertEqual(calls,[]);self.assertEqual(server.peer_attempts,{})


if __name__=='__main__':unittest.main()
