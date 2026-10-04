"""Explicit bounded loopback ciphertext meter; no TLS termination or receipts."""
import ipaddress
import select
import socket
import threading
import time

from regional_ground_resources import LABEL, require


class MeteredRelay:
    def __init__(self, target, label, enabled=False):
        require(LABEL.fullmatch(label) is not None and len(target) == 2
                and isinstance(ipaddress.ip_address(target[0]), ipaddress.IPv4Address)
                and ipaddress.ip_address(target[0]).is_loopback and type(enabled) is bool
                and type(target[1]) is int and 1 <= target[1] <= 65535,
                'explicit labeled literal loopback target required')
        self.target, self.label = target, label
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(2)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.enabled = enabled
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.capacity = threading.BoundedSemaphore(2)
        self.workers = []
        self.counts = dict(attempts=0, refused_connections=0, forwarded_connections=0,
                           failed_connections=0, active_connections=0,
                           client_to_target_received=0, client_to_target_sent=0,
                           target_to_client_received=0, target_to_client_sent=0)
        self.failed = False
        self.thread = threading.Thread(target=self.accept, daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.listener.close()
            raise

    def add(self, **changes):
        with self.lock:
            updated = {key:self.counts[key]+value for key, value in changes.items()}
            if not all(0 <= value < 2**63 for value in updated.values()):
                self.failed = True
                raise ValueError('ciphertext metric counter bound reached')
            self.counts.update(updated)

    def accept(self):
        while not self.closed.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.add(attempts=1)
                with self.lock:
                    enabled = self.enabled and not self.failed
                if not enabled or not self.capacity.acquire(blocking=False):
                    self.add(refused_connections=1)
                    client.close()
                    continue
                worker = threading.Thread(target=self.forward, args=(client,), daemon=True)
                self.workers = [w for w in self.workers if w.is_alive()]
                self.workers.append(worker)
                counted = False
                try:
                    self.add(active_connections=1)
                    counted = True
                    worker.start()
                except BaseException:
                    client.close()
                    self.capacity.release()
                    if counted:
                        self.add(active_connections=-1)
                    with self.lock:
                        self.failed = True
                    self.workers.remove(worker)
            except (OSError, ValueError):
                client.close()
                with self.lock:
                    self.failed = True

    def send(self, destination, raw, direction, deadline):
        view = memoryview(raw)
        while view:
            require(not self.closed.is_set() and time.monotonic() < deadline,
                    'bounded ciphertext connection ended')
            sent = destination.send(view)
            require(sent > 0, 'ciphertext destination closed')
            self.add(**{direction+'_sent':sent})
            view = view[sent:]

    def forward(self, client):
        total, failed = 0, False
        try:
            with client, socket.create_connection(self.target, timeout=1) as remote:
                client.settimeout(0.3)
                remote.settimeout(0.3)
                deadline = time.monotonic() + 4
                while not self.closed.is_set() and time.monotonic() < deadline:
                    readable, _, _ = select.select([client, remote], [], [], 0.1)
                    for source in readable:
                        raw = source.recv(65536)
                        if not raw:
                            return
                        direction = 'client_to_target' if source is client else 'target_to_client'
                        self.add(**{direction+'_received':len(raw)})
                        total += len(raw)
                        require(total <= 64 * 1024 * 1024, 'ciphertext connection byte bound reached')
                        self.send(remote if source is client else client, raw, direction, deadline)
                failed = True
        except (OSError, ValueError):
            failed = True
        finally:
            client.close()
            try:
                self.add(forwarded_connections=1, failed_connections=int(failed), active_connections=-1)
            finally:
                self.capacity.release()

    def enable(self):
        with self.lock:
            self.enabled = True

    def report(self):
        with self.lock:
            result = dict(self.counts)
            result.update(label=self.label, metric_counters_available=not self.failed,
                          ciphertext_bytes_forwarded=result['client_to_target_sent']+result['target_to_client_sent'],
                          observed_bytes_not_yet_forwarded=result['client_to_target_received']+result['target_to_client_received']
                              -result['client_to_target_sent']-result['target_to_client_sent'],
                          max_workers=2, max_connection_seconds=4, max_connection_bytes=64*1024*1024,
                          TLS_terminated=False, packet_headers_measured=False, physical_wire_bytes_measured=False,
                          payload_authenticated=False, custody_acknowledged=False, ledger_accepted=False)
            if self.failed:
                for key in (*self.counts, 'ciphertext_bytes_forwarded', 'observed_bytes_not_yet_forwarded'):
                    result[key] = None
            return result

    def close(self):
        self.closed.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=5)
        require(not self.thread.is_alive() and not any(worker.is_alive() for worker in self.workers),
                'owned ciphertext meter did not stop')
