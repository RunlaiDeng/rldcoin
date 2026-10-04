#!/usr/bin/env python3
"""Signed, bounded IPv4 TCP contact adapter; no ledger or issuance authority.

Configured peer identities/addresses only. Each exchange is committed before
acknowledgment, all socket waits occur outside mesh locks, and failure retains
the original queued evidence. This low-latency duplex ground adapter is not
BPv7, NAT traversal or interstellar-link qualification. TLS 1.3 is the default;
literal endpoints and certificate hashes are independently pinned in config.
"""
import copy
import errno
from bisect import bisect_right
from contextlib import contextmanager
import datetime
import hashlib
import os
import socket
import ssl
import struct
import threading
import time

import interstellar_mesh as mesh
import interstellar_transfer as wire


class MeshRuntimeStopping(ValueError):
    """Local admission refused because this runtime has stopped accepting work."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

ADAPTER = 'RLD-CONTACT-TCP-V4'
MAX_WIRE = mesh.MAX_BATCH + 4096
MAX_WORKERS = 2
MAX_OUTBOUND_PER_TICK = 4
ATTEMPT_SECONDS = 3.0
MAX_LOCAL_LOCK_WAIT_SECONDS = 0.2
MAX_CUSTODY_REPLY_BYTES = 64 * 1024
CERTIFICATE_DAYS = 90


def certificate_check(cert, network, peer, now=None):
    now=now or datetime.datetime.now(datetime.timezone.utc)
    mesh.require(cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
        'ground TLS certificate outside validity; preserve evidence')
    mesh.require(cert.subject==cert.issuer
        and cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)==[x509.NameAttribute(x509.NameOID.COMMON_NAME,peer)]
        and cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)==[x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,network)]
        and isinstance(cert.public_key(),Ed25519PublicKey),
        'TLS certificate identity/network or algorithm mismatch')
    try:
        cert.public_key().verify(cert.signature,cert.tbs_certificate_bytes)
    except InvalidSignature as error:
        raise ValueError('TLS certificate self-signature invalid') from error


def tls_material(root, network, peer):
    mesh.hex32(network)
    mesh.hex32(peer)
    root=mesh.safe_dir(root)
    path=root/'tcp-tls.private.pem'
    if not path.exists():
        key=Ed25519PrivateKey.generate()
        now=datetime.datetime.now(datetime.timezone.utc)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,peer),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,network)])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
            .not_valid_after(now+datetime.timedelta(days=CERTIFICATE_DAYS))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(key,None))
        raw=cert.public_bytes(serialization.Encoding.PEM)+key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        # One owner-only, fsynced file commits certificate and key together.
        wire.write_new(path,raw)
    raw=wire.read_file(path,8192)
    mesh.require(path.stat().st_mode & 0o077 == 0,'TLS private file permissions too broad')
    cert=x509.load_pem_x509_certificate(raw)
    key=serialization.load_pem_private_key(raw,password=None)
    mesh.require(isinstance(key,Ed25519PrivateKey),'TLS private key algorithm mismatch')
    certificate_check(cert,network,peer)
    mesh.require(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        ==cert.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),'TLS private key/certificate mismatch')
    canonical=cert.public_bytes(serialization.Encoding.PEM)+key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    mesh.require(raw==canonical,'TLS private material malformed; preserve file')
    return path,hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),cert.not_valid_after_utc.isoformat()


def public_tls_identity(config):
    with mesh.Node(config) as node:
        _,fingerprint,expires=tls_material(node.root,node.network,node.id)
        return {'node_id':node.id,'network':node.network,'tls_cert_sha256':fingerprint,
            'certificate_valid_until_utc':expires}


def client_context():
    mesh.require(ssl.HAS_TLSv1_3,'TLS 1.3 required; no downgrade')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False
    # Authentication uses the independent exact DER pin plus signed mesh ID,
    # not a public CA or a hostname supplied by an advertisement.
    context.verify_mode=ssl.CERT_NONE
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    return context


def client_connect(address, fingerprint, network, peer, deadline):
    context=client_context()
    connection=socket.create_connection(address,timeout=max(0.001,deadline-time.monotonic()))
    try:
        connection.settimeout(max(0.001,deadline-time.monotonic()))
        connection=context.wrap_socket(connection,server_hostname=None)
        mesh.require(connection.version()=='TLSv1.3','TLS downgrade refused')
        raw=connection.getpeercert(binary_form=True)
        mesh.require(hashlib.sha256(raw).hexdigest()==mesh.hex32(fingerprint),'TLS certificate pin mismatch; no fallback')
        certificate_check(x509.load_der_x509_certificate(raw),network,peer)
        return connection
    except BaseException:
        connection.close()
        raise


def challenge(key,network,peer,fingerprint):
    return mesh.sign(key,'tcp-challenge',{'format':mesh.VERSION,'adapter':ADAPTER,'network':network,
        'node_id':peer,'nonce':os.urandom(32).hex(),'tls_cert_sha256':fingerprint})


def check_challenge(value, network, peer, fingerprint):
    body=mesh.verify(value,'tcp-challenge',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','nonce','tls_cert_sha256'}
        and body['adapter']==ADAPTER and body['node_id']==peer
        and body['tls_cert_sha256']==fingerprint,'TCP connection challenge binding mismatch')
    return mesh.hex32(body['nonce'])


def read_exact(connection, length, deadline):
    chunks = []
    remaining = length
    while remaining:
        available = deadline-time.monotonic()
        mesh.require(available > 0, 'TCP local attempt deadline reached; retain evidence')
        connection.settimeout(available)
        chunk = connection.recv(min(remaining, 65536))
        mesh.require(bool(chunk), 'incomplete TCP frame; retain evidence')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def receive(connection, deadline):
    length = struct.unpack('!I', read_exact(connection, 4, deadline))[0]
    mesh.require(0 < length <= MAX_WIRE, 'TCP wire byte bound; retain evidence')
    raw = read_exact(connection, length, deadline)
    value = wire.decode_json(raw)
    mesh.require(raw == wire.canonical(value), 'noncanonical TCP frame')
    return value


def send(connection, value, deadline):
    data = wire.canonical(value)
    mesh.require(0 < len(data) <= MAX_WIRE, 'TCP wire byte bound; retain evidence')
    remaining = deadline-time.monotonic()
    mesh.require(remaining > 0, 'TCP local attempt deadline reached; retain evidence')
    connection.settimeout(remaining)
    connection.sendall(struct.pack('!I',len(data))+data)


def outgoing(node, peer, accepted_transits=None):
    # Both active carriage and this peer's receipt batch rotate durably before
    # the connection opens. No reply/receipt or ledger right follows from this.
    return node.prepare_exchange(peer,accepted_transits,advance_active=True)


def _custody_reply(node, peer, received, after=None):
    """Same-call reply after receive fsync, with no reverse carriage selection.

    An actual independent outgoing owner carries retained reverse evidence.
    Include authenticated receipts for this request's packets and its retained
    signed inventory. A process-local last-carried ID rotates requested receipts;
    ordinary durable carriage cursors and Native authority remain unchanged.
    """
    receipts = node.receipts()
    selected = []
    for transit in received['body']['transits']:
        ident = mesh.digest(transit['packet'])
        if ident in receipts:
            mesh.receipt_matches(receipts[ident], transit)
            selected.append(receipts[ident])
    mesh.require(peer in node.contacts and received['body']['inventory'] ==
                 node.state['peer_inventory'].get(peer), 'custody inventory not durably retained')
    requested = mesh.inventory_check(received['body']['inventory'], node.network)
    mesh.require(requested['node_id'] == peer, 'custody inventory differs from peer')
    body = dict(format=mesh.VERSION, network=node.network, node_id=node.id, to=peer,
                adverts=[node.state['adverts'][node.id]], transits=[], receipts=selected,
                inventory=mesh.sign(node.key, 'inventory', dict(format=mesh.VERSION,
                    network=node.network, node_id=node.id,
                    packet_ids=sorted(node.state['messages']))))
    result = mesh.sign(node.key, 'exchange', body)
    bound = min(MAX_CUSTODY_REPLY_BYTES, MAX_WIRE)
    mesh.require(len(wire.canonical(result)) + 1024 <= bound,
                 'custody reply byte bound; retain evidence')
    included = {r['body']['packet_id'] for r in selected}
    wanted = sorted(set(requested['packet_ids']) & set(receipts) - included)
    start = bisect_right(wanted, after) % len(wanted) if after is not None and wanted else 0
    carried = after
    for ident in wanted[start:] + wanted[:start]:
        if len(selected) == mesh.MAX_RECEIPT_BATCH:
            break
        candidate = mesh.sign(node.key, 'exchange', {**body, 'receipts': selected+[receipts[ident]]})
        if len(wire.canonical(candidate)) + 1024 > bound:
            continue
        selected.append(receipts[ident])
        result, carried = candidate, ident
    return result, carried


def request(node, peer, connection_nonce, accepted_transits=None):
    bundle = outgoing(node, peer,accepted_transits)
    return bind_request(node.key,node.network,node.id,peer,connection_nonce,bundle)


def bind_request(key, network, requester, peer, connection_nonce, bundle):
    return mesh.sign(key,'tcp-request',{'format':mesh.VERSION,'adapter':ADAPTER,'network':network,
        'node_id':requester,'to':peer,'nonce':os.urandom(32).hex(),
        'challenge':mesh.hex32(connection_nonce),'bundle':bundle})


def check_request(value, network, recipient, peers, connection_nonce):
    body = mesh.verify(value,'tcp-request',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','to','nonce','challenge','bundle'}
        and body['adapter']==ADAPTER and body['to']==recipient and body['node_id'] in peers
        and body['challenge']==connection_nonce,
        'TCP request identity or configured peer mismatch')
    mesh.hex32(body['nonce'])
    mesh.require(len(wire.canonical(body['bundle'])) <= mesh.MAX_BATCH,'TCP exchange byte bound')
    exchange = mesh.verify(body['bundle'],'exchange',network)
    mesh.require(exchange['node_id']==body['node_id'] and exchange['to']==recipient,'TCP request/bundle identity mismatch')
    return body


def check_response(value, network, requester, peer, sent):
    body=mesh.verify(value,'tcp-response',network)
    mesh.require(set(body)=={'format','adapter','network','node_id','to','nonce','challenge','exchange_id','accepted','bundle','error'}
        and body['adapter']==ADAPTER and body['node_id']==peer and body['to']==requester
        and body['nonce']==sent['body']['nonce'] and body['challenge']==sent['body']['challenge']
        and body['exchange_id']==mesh.digest(sent['body']['bundle']),
        'TCP response identity, nonce or exact exchange mismatch')
    mesh.require(type(body['accepted']) is bool, 'invalid TCP acknowledgment')
    if not body['accepted']:
        mesh.require(body['bundle'] is None and body['error']=='CONTACT_REJECTED','invalid TCP refusal')
        raise ValueError('TCP peer refused custody; retain queued evidence')
    mesh.require(body['error'] is None and isinstance(body['bundle'],dict)
        and len(wire.canonical(body['bundle']))<=mesh.MAX_BATCH,'invalid TCP success bundle')
    exchange=mesh.verify(body['bundle'],'exchange',network)
    mesh.require(exchange['node_id']==peer and exchange['to']==requester,'TCP response/bundle identity mismatch')
    return body['bundle']


class Server:
    def __init__(self,config,listen=('127.0.0.1',0),insecure=False,*,contact_trace=None):
        self.contact_trace=contact_trace
        self.config=copy.deepcopy(config)
        with mesh.Node(config) as node:
            self.id,self.network,self.key=node.id,node.network,node.key
            self.peers={peer:dict(c) for peer,c in node.contacts.items() if 'host' in c}
            self.insecure=insecure
            mesh.require(type(insecure) is bool,'invalid insecure transport selection')
            mesh.require(all(('tls_cert_sha256' in c) != insecure for c in self.peers.values()),
                'TLS certificate pin required, or explicit insecure mode with unpinned peers; no fallback')
            self.fingerprint=None
            self.expires=None
            self.context=None
            if not insecure:
                mesh.require(ssl.HAS_TLSv1_3,'TLS 1.3 required; no downgrade')
                path,self.fingerprint,self.expires=tls_material(node.root,node.network,node.id)
                self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.context.minimum_version=self.context.maximum_version=ssl.TLSVersion.TLSv1_3
                self.context.load_cert_chain(path)
                self.context.num_tickets=0
        self.running=True
        if contact_trace is not None:contact_trace.bind(self.network,self.id)
        self.guard=threading.Lock()
        self.outbound_guard=threading.Lock()
        self.outbound_owner=None
        self.connections=set()
        self.workers=set()
        # These immutable inputs occupy the original two inbound slots. They
        # are not durable custody, receipts, a replay cache or Native authority.
        # Restart forgets them; every source retained its unacknowledged packet.
        self.input_pending=[];self.input_active=None
        self.input_wake=threading.Event();self.input_failure=None
        self.input_received=0;self.input_completed=0;self.input_rejected=0
        self.observations={}
        # Optimization only: a verified reply proves this exact exchange was
        # durably held by this configured next hop. Keep all original carriage,
        # forget suppression on restart, and periodically re-probe all packets.
        # This never creates a destination receipt, ledger credit or refund.
        self.accepted_transits={}
        self.peer_attempts={}
        # One nullable ID per configured peer, scheduling only; restart forgets
        # it and all receipts remain fully authenticated and durably retained.
        self.custody_receipt_after={peer:None for peer in self.peers}
        self.refused_connections=0
        self.local_lock_retries=0
        self.local_lock_exhaustions=0
        # One ordinary foreground selection intent, scheduling only. A failed
        # bounded attempt keeps it until that thread next gets a selection;
        # TCP threads cannot repeatedly reacquire ahead of the pending reader.
        self.selection_owner=None
        self.selection_purpose=None
        self.local_mesh_owner=None
        self.last_mesh_class=None
        self.last_tcp_role=None
        self.tcp_mesh_waiters=set()
        self.cursor=0
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:
            self.socket.bind(mesh.tcp_endpoint(*listen,listening=True))
            self.socket.listen(MAX_WORKERS)
            self.socket.settimeout(0.1)
            self.address=self.socket.getsockname()
            self.thread=threading.Thread(target=self.serve,name='rld-tcp-contact-listener',daemon=True)
            self.input_thread=threading.Thread(target=self.consume_inputs,
                name='rld-tcp-deferred-input',daemon=True)
            # Own the input consumer before accepting any connection. Partial
            # startup must stop and join every thread actually started.
            self.input_thread.start()
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def mark(self,peer,direction,success):
        with self.guard:
            entry=self.observations.setdefault(peer,{})
            entry[direction+'_last_attempt_at_unix']=int(time.time())
            entry[direction+'_last_attempt_succeeded']=success
            if success:
                entry[direction+'_last_success_at_unix']=int(time.time())

    def suppressed(self, peer):
        with self.guard:
            return set(self.accepted_transits.get(peer,set()))

    def request_selection(self, purpose='receive'):
        mesh.require(purpose in ('receive','carriage'),'ordinary selection purpose differs')
        current=threading.current_thread()
        with self.guard:
            if not self.running:
                raise MeshRuntimeStopping('TCP runtime is stopping; preserve evidence')
            mesh.require(self.selection_owner is None or self.selection_owner is current,
                         'ordinary mesh selection already has another owner')
            if (self.selection_owner is current and self.selection_purpose!=purpose):
                raise BlockingIOError(errno.EAGAIN,
                    'ordinary other-purpose retry pending; retain evidence')
            self.selection_owner=current;self.selection_purpose=purpose

    def finish_selection(self):
        with self.guard:
            mesh.require(self.selection_owner is threading.current_thread(),
                         'ordinary mesh selection owner differs')
            self.selection_owner=None;self.selection_purpose=None

    def _claim_mesh_turn(self, ordinary):
        current=threading.current_thread()
        with self.guard:
            if not self.running:
                raise MeshRuntimeStopping('TCP runtime is stopping; preserve evidence')
            self.tcp_mesh_waiters={thread for thread in self.tcp_mesh_waiters if thread.is_alive()}
            if ordinary:
                mesh.require(self.selection_owner is current,'ordinary mesh selection owner differs')
            busy=self.local_mesh_owner is not None
            if ordinary:
                deferred=self.last_mesh_class=='ordinary' and bool(self.tcp_mesh_waiters)
            else:
                deferred=(self.selection_owner is not None and self.selection_owner is not current
                          and self.last_mesh_class!='ordinary')
                outgoing=current is self.outbound_owner
                other_out=self.outbound_owner in self.tcp_mesh_waiters and not outgoing
                other_in=any(thread is not current and thread is not self.outbound_owner
                             for thread in self.tcp_mesh_waiters)
                deferred=deferred or (other_out and self.last_tcp_role!='outbound') or (
                    outgoing and other_in and self.last_tcp_role=='outbound')
            if busy or deferred:
                raise BlockingIOError(errno.EAGAIN,'local mesh turn pending; retain evidence')
            self.local_mesh_owner=current

    def _release_mesh_turn(self):
        with self.guard:
            mesh.require(self.local_mesh_owner is threading.current_thread(),'local mesh turn owner differs')
            self.local_mesh_owner=None

    @contextmanager
    def _local_mesh_node(self, deadline, ordinary):
        # Brief ordinary local contention must not repeatedly refuse a complete
        # authenticated request. Every try is nonblocking; wait with no mesh
        # lock, within the original connection deadline and a separate bound.
        until=min(deadline,time.monotonic()+MAX_LOCAL_LOCK_WAIT_SECONDS)
        node=None;lease=False;exhausted=False;current=threading.current_thread()
        if not ordinary:
            with self.guard:
                self.tcp_mesh_waiters={thread for thread in self.tcp_mesh_waiters if thread.is_alive()}
                mesh.require(current in self.tcp_mesh_waiters or len(self.tcp_mesh_waiters)<MAX_WORKERS+1,
                             'local mesh waiter capacity reached; retain evidence')
                self.tcp_mesh_waiters.add(current)
        try:
            while node is None:
                try:
                    self._claim_mesh_turn(ordinary);lease=True
                    try:node=mesh.Node(self.config,nonblocking=True)
                    except BaseException:
                        self._release_mesh_turn();lease=False
                        raise
                except OSError as error:
                    if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):raise
                    with self.guard:self.local_lock_retries+=1
                    if time.monotonic()>=until:
                        exhausted=True
                        with self.guard:self.local_lock_exhaustions+=1
                        raise
                    time.sleep(min(0.005,max(0,until-time.monotonic())))
            with self.guard:
                self.last_mesh_class='ordinary' if ordinary else 'tcp'
                if not ordinary:self.last_tcp_role='outbound' if current is self.outbound_owner else 'inbound'
            # Ordinary's bound covers lock attempts, not full validation CPU.
            if not ordinary:mesh.require(time.monotonic()<deadline,'TCP local attempt deadline reached; retain evidence')
            yield node
        finally:
            try:
                if node is not None:node.close()
            finally:
                if lease:self._release_mesh_turn()
                if not ordinary:
                    with self.guard:
                        # Only actual live runtime owners retain demand after a
                        # bounded refusal. The input owner must still have its
                        # exact unacknowledged job; closed handlers leave none.
                        owned_input=(current is getattr(self,'input_thread',None)
                                     and self.input_active is not None)
                        if not (exhausted and (current is self.outbound_owner or owned_input)
                                and current.is_alive() and self.running):
                            self.tcp_mesh_waiters.discard(current)

    def mesh_node(self, deadline):
        return self._local_mesh_node(deadline,False)

    def selection_mesh_node(self, deadline):
        return self._local_mesh_node(deadline,True)

    @contextmanager
    def ordinary_mesh_node(self):
        """Ordinary transport work uses the existing bounded fair lease.

        A lock refusal retains this live thread's selection intent for its
        next attempt, as the Service receive selector already does. Native
        work/socket I/O stay outside; waiting never grants custody.
        """
        self.request_selection('carriage');node=None
        try:
            with self.selection_mesh_node(time.monotonic()+MAX_LOCAL_LOCK_WAIT_SECONDS) as selected:
                node=selected
                yield node
        except OSError as error:
            if node is None and error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):
                self.finish_selection()
            raise
        except BaseException:
            if node is None:self.finish_selection()
            raise
        finally:
            if node is not None:self.finish_selection()

    def serve(self):
        while self.running:
            try:
                connection,_=self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.guard:
                occupied=len(self.workers)+len(self.input_pending)+(self.input_active is not None)
                if occupied>=MAX_WORKERS:
                    self.refused_connections+=1
                    connection.close()
                    continue
                worker=threading.Thread(target=self.handle,args=(connection,),daemon=True)
                self.connections.add(connection)
                self.workers.add(worker)
                # close() must never observe a registered but unstarted worker.
                worker.start()

    def handle(self,connection):
        tracked=connection;deferred=None
        try:
            deadline=time.monotonic()+ATTEMPT_SECONDS
            if not self.insecure:
                connection.settimeout(ATTEMPT_SECONDS)
                with self.guard:
                    mesh.require(self.running,'TLS runtime is stopping; preserve evidence')
                    connection=self.context.wrap_socket(connection,server_side=True,do_handshake_on_connect=False)
                    self.connections.discard(tracked)
                    self.connections.add(connection)
                tracked=connection
                connection.do_handshake()
                mesh.require(connection.version()=='TLSv1.3','TLS downgrade refused')
            hello=challenge(self.key,self.network,self.id,self.fingerprint)
            send(connection,hello,deadline)
            value=receive(connection,deadline)
            body=check_request(value,self.network,self.id,self.peers,hello['body']['nonce'])
            peer=body['node_id']
            trace=self.contact_trace
            trace_rows=trace.packet_rows(body['bundle']) if trace is not None else ()
            if trace is not None:trace.packets('request_authenticated',peer,trace_rows,nonce=body['nonce'])
            accepted,bundle=False,None;node=None
            destination_receipts=()
            try:
                with self.mesh_node(deadline) as node:
                    mesh.require(node.id==self.id,'TCP runtime identity changed')
                    node.receive(body['bundle'],peer)
                    if trace is not None:
                        retained=node.receipts()
                        destination_receipts=tuple((ident,frame) for ident,frame in trace_rows
                            if ident in retained and retained[ident]['body']['node_id']==self.id)
                        trace.packets('local_transport_custody',peer,trace_rows,nonce=body['nonce'])
                        trace.packets('destination_receipt_retained',peer,destination_receipts,nonce=body['nonce'])
                    accepted=True  # receive fsyncs its complete verified state first.
                    with self.guard:
                        independent=self.outbound_owner is not None and self.outbound_owner.is_alive()
                        after=self.custody_receipt_after[peer]
                    if independent:
                        bundle,carried=_custody_reply(node,peer,body['bundle'],after)
                        with self.guard:
                            self.custody_receipt_after[peer]=carried
                    else:
                        bundle=outgoing(node,peer,self.suppressed(peer))
                self.mark(peer,'inbound',True)
            except (OSError,ValueError) as error:
                # Only an actual pre-open lock refusal transfers this live,
                # authenticated request to a separate input scheduler. Reply
                # refusal remains unchanged; queueing never acknowledges it.
                if (node is None and isinstance(error,BlockingIOError)
                        and error.errno in (errno.EAGAIN,errno.EWOULDBLOCK)):
                    raw=wire.canonical(value)
                    mesh.require(len(raw)<=MAX_WIRE,'deferred input wire bound')
                    deferred=(self.network,self.id,peer,self.peers[peer].get('tls_cert_sha256'),
                              hello['body']['nonce'],raw)
                accepted,bundle=False,None
                self.mark(peer,'inbound',False)
                if trace is not None:trace.packets('inbound_refused',peer,trace_rows,
                    nonce=body['nonce'],error_class=type(error).__name__)
            response=mesh.sign(self.key,'tcp-response',{'format':mesh.VERSION,'adapter':ADAPTER,'network':self.network,
                'node_id':self.id,'to':peer,'nonce':body['nonce'],'challenge':body['challenge'],
                'exchange_id':mesh.digest(body['bundle']),
                'accepted':accepted,'bundle':bundle,'error':None if accepted else 'CONTACT_REJECTED'})
            send(connection,response,deadline)
        except (OSError,ValueError,KeyError,TypeError,RecursionError):
            pass  # No unauthenticated/corrupt request receives a custody assertion.
        finally:
            connection.close()
            with self.guard:
                self.connections.discard(tracked)
                self.workers.discard(threading.current_thread())
                occupied=len(self.workers)+len(self.input_pending)+(self.input_active is not None)
                # Unacknowledged deferred inputs may use only one of the two
                # original inbound slots. Keep a slot available for a fresh
                # authenticated connection; refused sources retain originals.
                deferred_count=len(self.input_pending)+(self.input_active is not None)
                if (deferred is not None and self.running and occupied<MAX_WORKERS
                        and deferred_count<MAX_WORKERS-1):
                    self.input_pending.append(deferred)
                    self.input_received=min(self.input_received+1,2**63-1)
                    self.input_wake.set()

    def consume_inputs(self):
        """Retry bounded unacknowledged input, never a closed handler's ticket.

        Each local attempt keeps the original 0.2-second acquisition bound.
        Only this actual live owner retains demand after a bounded refusal,
        while its exact unacknowledged job remains active. Every retry checks
        the complete request and transits before fsync. No later reply is made.
        """
        try:
            while self.running:
                with self.guard:
                    if self.input_active is None and self.input_pending:
                        self.input_active=self.input_pending.pop(0)
                    job=self.input_active
                    self.input_wake.clear()
                if job is None:
                    self.input_wake.wait(0.25)
                    continue
                retry=False;complete=False
                try:
                    network,recipient,peer,pin,nonce,raw=job
                    mesh.require(network==self.network and recipient==self.id
                        and peer in self.peers and self.peers[peer].get('tls_cert_sha256')==pin
                        and type(raw) is bytes and len(raw)<=MAX_WIRE,
                        'deferred input runtime/configuration binding differs')
                    # Own a new decoded object for this attempt, from the
                    # complete bounded original request; no decoded witness.
                    body=check_request(wire.decode_json(raw),network,recipient,self.peers,nonce)
                    trace=self.contact_trace
                    trace_rows=trace.packet_rows(body['bundle']) if trace is not None else ()
                    if trace is not None:trace.packets('deferred_attempt',peer,trace_rows,nonce=body['nonce'])
                    destination_receipts=()
                    with self.mesh_node(time.monotonic()+ATTEMPT_SECONDS) as node:
                        mesh.require(node.id==recipient and node.network==network,
                                     'deferred input local identity changed')
                        node.receive(body['bundle'],peer)
                        if trace is not None:
                            retained=node.receipts()
                            destination_receipts=tuple((ident,frame) for ident,frame in trace_rows
                                if ident in retained and retained[ident]['body']['node_id']==self.id)
                    complete=True
                    if trace is not None:
                        trace.packets('deferred_local_custody',peer,trace_rows,nonce=body['nonce'])
                        trace.packets('destination_receipt_retained',peer,destination_receipts,nonce=body['nonce'])
                except BlockingIOError as error:
                    retry=error.errno in (errno.EAGAIN,errno.EWOULDBLOCK)
                except (OSError,ValueError,KeyError,TypeError,RecursionError):
                    pass  # No custody acknowledgment; originals stay at source.
                finally:
                    # Decoded request/closed Node belong to this attempt only.
                    # The active immutable original input still binds retries.
                    body=None;raw=None;node=None
                if not retry:
                    with self.guard:
                        mesh.require(self.input_active is job,'deferred input owner differs')
                        self.input_active=None
                        self.tcp_mesh_waiters.discard(threading.current_thread())
                        name='input_completed' if complete else 'input_rejected'
                        setattr(self,name,min(getattr(self,name)+1,2**63-1))
                job=None
                self.input_wake.wait(0.25)
        except BaseException as error:
            with self.guard:self.input_failure=type(error).__name__
        finally:
            with self.guard:self.tcp_mesh_waiters.discard(threading.current_thread())

    def claim_outbound(self, owner):
        with self.guard:
            mesh.require(self.outbound_owner is None and self.outbound_guard.acquire(False),
                         'TCP outgoing scheduler already owned')
            self.outbound_owner=owner
            self.outbound_guard.release()

    def release_outbound(self, owner):
        with self.guard:
            mesh.require(self.outbound_owner is owner and not owner.is_alive(),
                         'TCP outgoing owner still active or differs')
            self.outbound_owner=None
            self.tcp_mesh_waiters.discard(owner)

    def tick(self):
        with self.guard:
            mesh.require(self.outbound_owner is None or self.outbound_owner is threading.current_thread(),
                         'TCP outgoing scheduler belongs to its worker')
            mesh.require(self.outbound_guard.acquire(False), 'TCP outgoing pass already running')
        try:
            return self._outbound_tick()
        finally:
            self.outbound_guard.release()

    def _outbound_tick(self):
        errors=[]
        peers=sorted(self.peers)
        if peers:
            offset=self.cursor%len(peers)
            chosen=(peers[offset:]+peers[:offset])[:MAX_OUTBOUND_PER_TICK]
            self.cursor=(self.cursor+len(chosen))%len(peers)
            for peer in chosen:
                if not self.running:
                    break
                trace=self.contact_trace;trace_rows=();failure_stage='prepare';count=0
                try:
                    c=self.peers[peer]
                    with self.guard:
                        count=self.peer_attempts.get(peer,0)+1
                        self.peer_attempts[peer]=count
                        if count%64==0:
                            self.accepted_transits.pop(peer,None)
                    # Prepare and durably rotate retained carriage before the
                    # connection starts. Cold local verification must not use
                    # up the remote socket deadline. The fresh challenge still
                    # binds the exact prepared exchange after TLS admission.
                    with self.mesh_node(time.monotonic()+ATTEMPT_SECONDS) as node:
                        mesh.require(node.id==self.id,'TCP runtime identity changed')
                        prepared=outgoing(node,peer,self.suppressed(peer))
                    if trace is not None:
                        trace_rows=trace.packet_rows(prepared)
                        trace.packets('outgoing_prepared',peer,trace_rows,attempt=count)
                        trace.event('contact_start',peer,attempt=count)
                    failure_stage='connect'
                    # No mesh lock is held across connect/write/read.
                    deadline=time.monotonic()+ATTEMPT_SECONDS
                    connection=(socket.create_connection((c['host'],c['port']),timeout=ATTEMPT_SECONDS) if self.insecure else
                        client_connect((c['host'],c['port']),c['tls_cert_sha256'],self.network,peer,deadline))
                    with connection:
                        failure_stage='challenge'
                        nonce=check_challenge(receive(connection,deadline),self.network,peer,c.get('tls_cert_sha256'))
                        sent=bind_request(self.key,self.network,self.id,peer,nonce,prepared)
                        failure_stage='send'
                        send(connection,sent,deadline)
                        if trace is not None:trace.packets('request_sent',peer,trace_rows,attempt=count,nonce=sent['body']['nonce'])
                        failure_stage='response'
                        response=receive(connection,deadline)
                    failure_stage='response_authentication'
                    bundle=check_response(response,self.network,self.id,peer,sent)
                    if trace is not None:trace.packets('peer_custody_authenticated',peer,trace_rows,attempt=count,nonce=sent['body']['nonce'])
                    # The socket is closed and its authenticated reply is now
                    # local input. Use a fresh bounded lock attempt, never infer
                    # local custody from the remote reply or expired deadline.
                    failure_stage='reply_local_custody'
                    receipt_rows=()
                    with self.mesh_node(time.monotonic()+ATTEMPT_SECONDS) as node:
                        mesh.require(node.id==self.id,'TCP runtime identity changed')
                        node.receive(bundle,peer)
                        if trace is not None:
                            receipts=node.receipts()
                            receipt_rows=tuple((ident,frame) for ident,frame in trace_rows if ident in receipts)
                    # Only after exact nonce/challenge/exchange verification and
                    # complete local reply custody. A lost/refused reply retries.
                    with self.guard:
                        retained=self.accepted_transits.setdefault(peer,set())
                        retained.update(mesh.digest(t) for t in sent['body']['bundle']['body']['transits'])
                        if len(retained)>mesh.MAX_MESSAGES:
                            # This cache is only an optimization. Forgetting it
                            # safely resends retained evidence, never drops it.
                            self.accepted_transits.pop(peer,None)
                    self.mark(peer,'outbound',True)
                    if trace is not None:trace.packets('reply_local_custody',peer,trace_rows,attempt=count,nonce=sent['body']['nonce'])
                    if trace is not None:trace.packets('destination_receipt_observed',peer,receipt_rows,attempt=count,nonce=sent['body']['nonce'])
                except (OSError,ValueError,KeyError,TypeError,RecursionError) as error:
                    self.mark(peer,'outbound',False)
                    errors.append(str(error)[:256])
                    if trace is not None:
                        trace.packets('outgoing_failed',peer,trace_rows,attempt=count,
                            failure_stage=failure_stage,error_class=type(error).__name__)
                        trace.event('contact_failed',peer,attempt=count,failure_stage=failure_stage,error_class=type(error).__name__)
        return self.observation(errors)

    def observation(self, errors=()):
        return {'adapter':ADAPTER,'listener':{'host':self.address[0],'port':self.address[1]},
            'contacts':self.report(),'errors':errors[:mesh.MAX_CONTACTS],
            'limits':{'inbound_workers':MAX_WORKERS,'outbound_contacts_per_tick':MAX_OUTBOUND_PER_TICK,
                'wire_bytes':MAX_WIRE,'local_attempt_seconds':ATTEMPT_SECONDS,
                'local_lock_wait_seconds':MAX_LOCAL_LOCK_WAIT_SECONDS},
            'encrypted':not self.insecure,'tls_version':None if self.insecure else 'TLSv1.3',
            'tls_cert_sha256':self.fingerprint,'certificate_valid_until_utc':self.expires,
            'fallback_to_plaintext':False,'plaintext_selected_explicitly':self.insecure,
            'ledger_acceptance_from_transport':False,'physical_route_qualified':False}

    def report(self):
        with self.guard:
            mesh.require(self.input_failure is None,'deferred input worker failed; retain source evidence')
            return {'deferred_input':{'pending':len(self.input_pending),'active':self.input_active is not None,
                'received':self.input_received,'completed':self.input_completed,'rejected':self.input_rejected,
                'shares_original_inbound_slots':True,'queue_grants_custody':False},
                'observations':copy.deepcopy(self.observations),'refused_connections':self.refused_connections,
                'local_lock_retries':self.local_lock_retries,'local_lock_exhaustions':self.local_lock_exhaustions}

    def close(self):
        self.running=False
        self.input_wake.set()
        with self.guard:
            self.selection_owner=None;self.selection_purpose=None
            self.tcp_mesh_waiters.clear()
        self.socket.close()
        if hasattr(self,'thread') and self.thread.ident is not None:
            self.thread.join()
        with self.guard:
            connections=list(self.connections)
            workers=list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for worker in workers:
            # Socket waits are bounded independently of local signature/file
            # verification CPU. Keep service custody until every worker exits.
            worker.join()
        if hasattr(self,'input_thread') and self.input_thread.ident is not None:
            self.input_thread.join()
        with self.guard:
            # Unacknowledged in-flight input can be forgotten on shutdown; its
            # original signed carriage remains at source. Stored evidence stays.
            self.input_pending.clear();self.input_active=None
