"""Shared local subprocess deadline; no retry, status or custody authority.

Used only for explicit recover-only quiescence after transport owners stop.
Python verification and durable publication retain their own existing bounds;
this wrapper is not proof of a total shutdown or physical-link time bound.
"""
import math
import subprocess
import time

import interstellar_mesh as mesh

MAX_QUIESCENCE_SECONDS=2.0


class DeadlineNative:
    def __init__(self,native,deadline):
        mesh.require(type(deadline) in (int,float) and math.isfinite(deadline),
                     'finite native quiescence deadline required')
        self.native=native;self.deadline=deadline

    def __getattr__(self,name):return getattr(self.native,name)

    def check_deadline(self):
        if time.monotonic()>=self.deadline:
            raise subprocess.TimeoutExpired('recover-only quiescence',MAX_QUIESCENCE_SECONDS)

    def call(self,*args,**kwargs):
        self.check_deadline()
        result=self.native.call(*args,**kwargs,deadline=self.deadline)
        self.check_deadline()
        return result
