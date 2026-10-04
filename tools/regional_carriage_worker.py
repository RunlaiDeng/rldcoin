"""One bounded outgoing scheduler, independent of native verification CPU.

Only the existing pinned TCP adapter takes custody. This worker has no native,
wallet, signing, receipt-authority or decoded-ledger interface. Its single
bounded last observation is diagnostic, never a recovery cursor or authority.
"""
import json
import threading
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire

FORMAT='RLD-REGIONAL-CARRIAGE-WORKER-V1'
MAX_OBSERVATION_BYTES=64*1024


class Worker:
    def __init__(self, server, interval=0.25):
        mesh.require(type(interval) in (int,float) and 0.1<=interval<=3600,
                     'outgoing worker interval outside ground bound')
        self.server=server;self.interval=interval
        self.guard=threading.Lock();self.stop=threading.Event()
        self.close_guard=threading.Lock()
        self.raw=None;self.duration=None;self.completed=None
        self.passes=0;self.in_progress=False;self.failure=None;self.closed=False
        self.thread=threading.Thread(target=self.run,name='rld-regional-outgoing',daemon=True)
        server.claim_outbound(self.thread)
        try:self.thread.start()
        except BaseException:
            server.release_outbound(self.thread)
            raise

    def run(self):
        try:
            while not self.stop.is_set() and self.server.running:
                started=time.monotonic()
                with self.guard:self.in_progress=True
                result=self.server.tick()
                raw=wire.canonical(result)
                mesh.require(len(raw)<=MAX_OBSERVATION_BYTES,'outgoing worker diagnostic capacity')
                with self.guard:
                    self.raw=raw;self.duration=round(time.monotonic()-started,6)
                    self.completed=time.time();self.passes=min(self.passes+1,2**63-1)
                    self.in_progress=False
                self.stop.wait(self.interval)
        except BaseException as error:
            with self.guard:
                self.failure=type(error).__name__+': '+str(error)[:256]
                self.in_progress=False

    def snapshot(self):
        with self.guard:
            raw=self.raw
            meta=dict(format=FORMAT,observation_available=raw is not None,
                      completed_passes=self.passes,last_pass_seconds=self.duration,
                      last_completed_at_unix=self.completed,pass_in_progress=self.in_progress,
                      diagnostic=self.failure,single_outbound_owner=True,
                      ledger_or_signing_authority=False)
        mesh.require(meta['diagnostic'] is None,'outgoing worker failed; retain queued evidence: '+str(meta['diagnostic']))
        mesh.require(self.thread.is_alive() or not self.server.running or self.closed,
                     'outgoing worker stopped unexpectedly; retain queued evidence')
        result=json.loads(raw) if raw is not None else self.server.observation()
        result['worker']=meta
        return result

    def close(self):
        with self.close_guard:
            if self.closed:return
            mesh.require(threading.current_thread() is not self.thread,'outgoing worker cannot release itself')
            self.stop.set();self.server.running=False
            # A socket deadline does not bound local verification CPU. Never free
            # the service lock/ownership while local durable custody is unfinished.
            self.thread.join()
            self.server.release_outbound(self.thread)
            self.closed=True
