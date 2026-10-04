"""Optional process-local ground fsync timing, never custody or power-loss proof.

Calls the original syscall exactly once even if telemetry fails. No descriptor,
path, payload or exception text survives. Install only in a fresh diagnostic
process; this does not attach to or change an existing node process.
"""
from contextlib import contextmanager
import math
import os
import threading
import time

from regional_ground_resources import require

MAX_CALLS=1_000_000
_installation=threading.Lock()


class FsyncMeter:
    def __init__(self,*,max_calls=MAX_CALLS):
        require(type(max_calls) is int and 1<=max_calls<=MAX_CALLS,'bounded fsync counter required')
        self.original=os.fsync
        self.max_calls=max_calls
        self.lock=threading.Lock()
        self.available=True
        self.calls=self.failures=0
        self.total_seconds=self.max_seconds=0.0
        self.hook_restored=True
        self.wrapper=lambda fd:self.call(fd)

    def call(self,fd):
        started=None
        try:started=time.monotonic()
        except Exception:self.available=False
        succeeded=False
        try:
            result=self.original(fd)
            succeeded=True
            return result
        finally:
            # Telemetry must neither replace a syscall exception nor suppress
            # an actual successful syscall. Lost/overflowed metrics stay unknown.
            try:
                ended=time.monotonic()
                duration=None if started is None else ended-started
                if not self.lock.acquire(blocking=False):
                    self.available=False
                else:
                    try:
                        if (duration is None or not math.isfinite(duration) or duration<0
                                or self.calls>=self.max_calls):
                            self.available=False
                        else:
                            self.calls+=1
                            self.failures+=int(not succeeded)
                            self.total_seconds+=duration
                            self.max_seconds=max(self.max_seconds,duration)
                    finally:self.lock.release()
            except Exception:self.available=False

    @contextmanager
    def installed(self):
        require(_installation.acquire(blocking=False),'another fsync observation hook is installed')
        try:
            require(os.fsync is self.original,'fsync implementation changed before observation')
            os.fsync=self.wrapper
            self.hook_restored=False
            try:yield self
            finally:
                if os.fsync is self.wrapper:
                    os.fsync=self.original
                    self.hook_restored=True
                else:self.available=False
        finally:_installation.release()

    def snapshot(self):
        locked=self.lock.acquire(blocking=False)
        try:
            available=locked and self.available
            return dict(format='RLD-GROUND-PROCESS-FSYNC-OBSERVATION-V1',available=available,
                        calls=self.calls if available else None,failed_calls=self.failures if available else None,
                        summed_syscall_wall_seconds=self.total_seconds if available else None,
                        max_syscall_wall_seconds=self.max_seconds if available else None,
                        counter_bound=self.max_calls,original_hook_restored=self.hook_restored,
                        process_local_only=True,parallel_wall_durations_may_overlap=True,
                        all_native_or_node_fsync_covered=False,CPU_cost_measured=False,
                        power_loss_qualified=False,custody_or_ledger_authority=False)
        finally:
            if locked:self.lock.release()
