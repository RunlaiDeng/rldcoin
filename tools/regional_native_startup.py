"""Bounded contention waiting for native-authenticated startup observations.

This wrapper exists only during construction. It does not retry mutations,
recover responses, initialize custody, adopt heads or synthesize observations.
Successful native replay retains its own existing CPU/output bounds; the three
seconds below bound accumulated failed lock attempts and delay, not replay CPU.
"""
import time

LOCK_REFUSAL = ('native rejected: regional candidate rejected: '
                'lock acquisition failed because the operation would block')
MAX_CONTENTION_SECONDS = 3.0
MAX_LOCK_REFUSALS = 128
RETRY_DELAY_SECONDS = 0.025
OBSERVATIONS = frozenset({
    'contact-status', 'bft-context', 'bft-status', 'bft-retained-messages',
    'proof', 'bft-network-pack', 'bft-network-check', 'bft-network-check-batch',
    'bft-installed-epochs', 'bft-network-check-plan', 'history-check',
})


class Inspection:
    """One constructor's shared contention budget; native remains authoritative."""
    def __init__(self, native, clock=time):
        self.native = native
        self.clock = clock
        self.contention_seconds = 0.0
        self.lock_refusals = 0

    def __getattr__(self, name):
        return getattr(self.native, name)

    def call(self, *args, **kwargs):
        if not args or args[0] not in OBSERVATIONS:
            return self.native.call(*args, **kwargs)
        while True:
            started = self.clock.monotonic()
            try:
                return self.native.call(*args, **kwargs)
            except ValueError as error:
                if str(error) != LOCK_REFUSAL:
                    raise
                self.lock_refusals += 1
                self.contention_seconds += self.clock.monotonic() - started
                if (self.lock_refusals >= MAX_LOCK_REFUSALS
                        or self.contention_seconds >= MAX_CONTENTION_SECONDS):
                    raise
                remaining = MAX_CONTENTION_SECONDS - self.contention_seconds
                started = self.clock.monotonic()
                self.clock.sleep(min(RETRY_DELAY_SECONDS, remaining))
                self.contention_seconds += self.clock.monotonic() - started
                if self.contention_seconds >= MAX_CONTENTION_SECONDS:
                    raise
