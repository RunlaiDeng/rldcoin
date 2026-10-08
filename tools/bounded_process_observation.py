"""Bounded process observations; no test, Native or value qualification.

Use the caller's existing command and budget unchanged. Observe the child's
actual exit and resource usage directly, without a time wrapper's separate exit
or privileged host queries. Preserve complete output in a new private log.
"""
from dataclasses import dataclass
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


@dataclass(frozen=True)
class Observation:
    returncode: int
    timed_out: bool
    descendant_residue: bool
    owned_group_empty: bool
    seconds: float
    user_cpu_seconds: float
    system_cpu_seconds: float
    maximum_resident_bytes: int
    major_faults: int
    swaps: int
    involuntary_context_switches: int


def group_exists(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    return True


def signal_group(pid, signum):
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass  # An already exited owned group needs no replacement signal.


def observe(command, *, output, budget_seconds, env=None):
    """One original child command, one exact progress budget, no shell.

    Cleanup is separate from progress. A timeout or descendant residue remains
    a failed observation even if cleanup succeeds or the child exits zero.
    Resource fields describe this child, including its reaped descendants;
    they cannot establish historical host pressure or individual phase costs.
    """
    if (type(budget_seconds) not in (int, float)
            or not math.isfinite(budget_seconds) or budget_seconds <= 0):
        raise ValueError('finite positive existing budget required')
    if not hasattr(os, 'wait4'):
        raise RuntimeError('direct child resource observation unavailable')
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError('explicit nonempty command required')
    started = time.monotonic()
    timed_out = False
    fd = os.open(Path(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    timed_out = time.monotonic()-started > budget_seconds
                    break
                if time.monotonic() - started >= budget_seconds:
                    timed_out = True
                    signal_group(process.pid, signal.SIGTERM)
                    cleanup_deadline = time.monotonic() + 1
                    while True:
                        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                        if pid:
                            process.returncode = os.waitstatus_to_exitcode(status)
                            break
                        if time.monotonic() >= cleanup_deadline:
                            signal_group(process.pid, signal.SIGKILL)
                            _, status, usage = os.wait4(process.pid, 0)
                            process.returncode = os.waitstatus_to_exitcode(status)
                            break
                        time.sleep(.01)
                    break
                time.sleep(min(.01, max(.001, budget_seconds-(time.monotonic()-started))))
        finally:
            if process.returncode is None:
                signal_group(process.pid, signal.SIGKILL)
                _, status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
        residue = group_exists(process.pid)
        if residue:
            signal_group(process.pid, signal.SIGTERM)
            deadline = time.monotonic() + 1
            while group_exists(process.pid) and time.monotonic() < deadline:
                time.sleep(.01)
            if group_exists(process.pid):
                signal_group(process.pid, signal.SIGKILL)
        empty = not group_exists(process.pid)
    return Observation(process.returncode, timed_out, residue, empty,
                       time.monotonic()-started, usage.ru_utime, usage.ru_stime,
                       usage.ru_maxrss if sys.platform == 'darwin' else usage.ru_maxrss*1024,
                       usage.ru_majflt, usage.ru_nswap, usage.ru_nivcsw)
