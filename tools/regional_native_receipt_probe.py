"""Bounded fresh Native receipt observations across explicitly pinned replicas.

The caller must invoke its pinned Native CLI with normal full replay. This
selects an observation point; it never installs evidence, signs or remembers a
receipt. All-replica agreement and stopped verification remain separate gates.
"""
import time


class NativeReplicaReceiptProbe:
    interval_seconds = 2

    def __init__(self):
        self.next_read = 0.0
        self.attempts = 0
        self.next_replica = 1

    def attempt(self, read, accepts):
        now = time.monotonic()
        if now < self.next_read:
            return False
        self.next_read = now + self.interval_seconds
        replica = self.next_replica
        self.next_replica = (replica + 1) % 4
        self.attempts += 1
        # Advance even on a Native refusal: a busy replica cannot pin the
        # observer. No earlier result can satisfy this or a skipped attempt.
        value = read(replica)
        return value if accepts(value) else False
