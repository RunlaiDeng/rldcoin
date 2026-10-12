"""Independent Python TLS oracle and explicit SDK test peer; no native fallback."""
import datetime
import hashlib
import socket
import ssl
import time
import interstellar_mesh as mesh
import interstellar_transfer as wire
import interstellar_file_reference as files
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
CERTIFICATE_DAYS=90

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
        files.write_new(path,raw)
    raw=files.read_file(path,8192)
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
