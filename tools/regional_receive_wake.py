"""Coalesced ordinary intake scheduling after complete transport custody."""
import math
import threading
import time

import interstellar_mesh as mesh

MIN_IDLE_INTERVAL = 0.1


class Wait:
    def __init__(self, server, interval):
        mesh.require(type(interval) in (int, float) and math.isfinite(interval)
                     and MIN_IDLE_INTERVAL <= interval <= 3600,
                     'ordinary receive wait interval outside bound')
        self.server, self.interval = server, interval
        self.condition = threading.Condition()
        self.pending = self.stopped = self.released = False
        self.callback = self.notify
        server.claim_receive_wake(self.callback)

    def notify(self):
        with self.condition:
            if not self.stopped and not self.pending:
                self.pending = True
                self.condition.notify_all()

    def wait(self, running):
        # Preserve at least the original minimum idle time after each complete
        # service unit, even for a notice retained during that unit. No timer
        # or quorum/maturity clock is reset by a later notification.
        started = time.monotonic()
        earliest, periodic = started + MIN_IDLE_INTERVAL, started + self.interval
        with self.condition:
            while not self.stopped and running():
                now = time.monotonic()
                if self.pending and now >= earliest:
                    self.pending = False
                    return True
                if now >= periodic:
                    return False
                due = earliest if self.pending else periodic
                self.condition.wait(min(MIN_IDLE_INTERVAL, max(0, due-now)))
        return False

    def stop(self):
        with self.condition:
            self.stopped = True
            self.condition.notify_all()

    def close(self):
        self.stop()
        if not self.released:
            self.server.release_receive_wake(self.callback)
            self.released = True
