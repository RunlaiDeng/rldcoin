//! Ground TLS1.3 with explicit certificate/contact pins and bounded sockets.
//! TLS keys are separate from contact and wallet keys. No plaintext fallback.
use crate::{
    contact::{peer_id, Frame, Packet, FRAME_MAX},
    kernel::{Hash, Result},
};
use ed25519_dalek::SigningKey;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use x509_parser::prelude::*;
use zeroize::Zeroizing;
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT TLS {e}")
}
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub key: Hash,
    pub endpoint: SocketAddr,
    pub certificate_sha256: Hash,
}
pub struct Material {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}
impl Material {
    /// Returns separate DER certificate and PKCS8 secret bytes for atomic native
    /// persistence. The generated TLS key must never be used as a wallet key.
    pub fn generate(chain: Hash, identity: Hash) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ED25519};
        let key = Zeroizing::new(KeyPair::generate_for(&PKCS_ED25519).map_err(err)?);
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        let now = ASN1Time::now().to_datetime();
        p.not_before = now - Duration::from_secs(300);
        p.not_after = now + Duration::from_secs(90 * 86400);
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name
            .push(DnType::CommonName, hex::encode(identity));
        p.distinguished_name
            .push(DnType::OrganizationalUnitName, hex::encode(chain));
        p.is_ca = IsCa::ExplicitNoCa;
        let cert = p.self_signed(&*key).map_err(err)?;
        Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
    }
    pub fn from_der(
        cert: Vec<u8>,
        key: Zeroizing<Vec<u8>>,
        chain: Hash,
        identity: Hash,
    ) -> Result<Self> {
        // Retained ground credentials may be expired while an independently
        // admitted file adapter remains usable. Every live TLS peer still checks
        // certificate validity below; loading never renews or replaces a pin.
        check(&cert, chain, identity, None)?;
        let key = PrivateKeyDer::try_from(key.to_vec()).map_err(err)?;
        Ok(Self {
            cert: CertificateDer::from(cert),
            key,
        })
    }
    pub(crate) fn matches_retained_record(&self, raw: &[u8]) -> bool {
        if raw.len() < 4 {
            return false;
        }
        let n = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        n <= 8192
            && 4 + n < raw.len()
            && &raw[4..4 + n] == self.cert.as_ref()
            && &raw[4 + n..] == self.key.secret_der()
    }
    pub fn fingerprint(&self) -> Hash {
        Sha256::digest(&self.cert).into()
    }
    fn copy(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key: self.key.clone_key(),
        }
    }
}
fn check(cert: &[u8], chain: Hash, identity: Hash, now: Option<u64>) -> Result<()> {
    ensure(cert.len() <= 8192, "INVALID_ENCODING TLS certificate size")?;
    let (rest, c) =
        X509Certificate::from_der(cert).map_err(|_| "INVALID_CRYPTO TLS certificate")?;
    ensure(rest.is_empty(), "INVALID_ENCODING TLS certificate trailing")?;
    if let Some(now) = now {
        let now = i64::try_from(now).map_err(|_| "CLOCK_WAIT TLS time")?;
        ensure(
            c.validity().not_before.timestamp() <= now && now <= c.validity().not_after.timestamp(),
            "CLOCK_WAIT TLS validity",
        )?;
    }
    let names = c
        .subject()
        .iter_common_name()
        .map(|x| x.as_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)?;
    let units = c
        .subject()
        .iter_organizational_unit()
        .map(|x| x.as_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)?;
    ensure(
        names == [hex::encode(identity)]
            && units == [hex::encode(chain)]
            && c.subject() == c.issuer()
            && c.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112"
            && c.signature_algorithm.algorithm.to_id_string() == "1.3.101.112",
        "INVALID_CRYPTO TLS identity/suite",
    )?;
    c.verify_signature(None).map_err(err)?;
    Ok(())
}
#[derive(Debug)]
struct Pins {
    chain: Hash,
    peers: Vec<Neighbor>,
}
impl Pins {
    fn verify(
        &self,
        cert: &CertificateDer<'_>,
        now: UnixTime,
    ) -> std::result::Result<(), rustls::Error> {
        let digest: Hash = Sha256::digest(cert).into();
        let peer = self
            .peers
            .iter()
            .find(|n| n.certificate_sha256 == digest)
            .ok_or_else(|| rustls::Error::General("certificate pin mismatch".into()))?;
        check(cert, self.chain, peer.key, Some(now.as_secs())).map_err(rustls::Error::General)
    }
}
fn signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    sig: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    if sig.scheme != SignatureScheme::ED25519 {
        return Err(rustls::Error::General("TLS signature suite".into()));
    }
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        sig,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}
impl ServerCertVerifier for Pins {
    fn verify_server_cert(
        &self,
        c: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "unexpected certificate chain".into(),
            ));
        }
        self.verify(c, now)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS downgrade".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        s: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        signature(m, c, s)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for Pins {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        c: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "unexpected client certificate chain".into(),
            ));
        }
        self.verify(c, now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS downgrade".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        s: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        signature(m, c, s)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
pub fn server(
    material: &Material,
    chain: Hash,
    neighbors: Vec<Neighbor>,
) -> Result<Arc<ServerConfig>> {
    let m = material.copy();
    let mut c = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(err)?
        .with_client_cert_verifier(Arc::new(Pins {
            chain,
            peers: neighbors,
        }))
        .with_single_cert(vec![m.cert], m.key)
        .map_err(err)?;
    c.send_tls13_tickets = 0;
    c.max_early_data_size = 0;
    Ok(Arc::new(c))
}
fn client(material: &Material, chain: Hash, peer: Neighbor) -> Result<Arc<ClientConfig>> {
    let m = material.copy();
    let c = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pins {
            chain,
            peers: vec![peer],
        }))
        .with_client_auth_cert(vec![m.cert], m.key)
        .map_err(err)?;
    Ok(Arc::new(c))
}
pub(crate) struct Timed {
    stream: TcpStream,
    deadline: Instant,
}
/// Typed application adapters share pinned TLS and one whole-socket deadline;
/// application framing/signatures and durable custody remain their responsibility.
pub(crate) fn connect_stream(
    material: &Material,
    chain: Hash,
    peer: &Neighbor,
) -> Result<StreamOwned<ClientConnection, Timed>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let socket = TcpStream::connect_timeout(&peer.endpoint, Duration::from_secs(3)).map_err(err)?;
    let connection = ClientConnection::new(
        client(material, chain, peer.clone())?,
        ServerName::try_from("rld-survivor.invalid")
            .map_err(err)?
            .to_owned(),
    )
    .map_err(err)?;
    let mut stream = StreamOwned::new(
        connection,
        Timed {
            stream: socket,
            deadline,
        },
    );
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(err)?;
    }
    Ok(stream)
}
pub(crate) fn accept_stream(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    neighbors: &[Neighbor],
) -> Result<(Hash, StreamOwned<ServerConnection, Timed>)> {
    socket.set_nonblocking(false).map_err(err)?;
    let mut stream = StreamOwned::new(
        ServerConnection::new(config).map_err(err)?,
        Timed {
            stream: socket,
            deadline: Instant::now() + Duration::from_secs(3),
        },
    );
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(err)?;
    }
    let cert = stream
        .conn
        .peer_certificates()
        .and_then(|p| p.first())
        .ok_or("INVALID_CRYPTO client certificate")?;
    let digest: Hash = Sha256::digest(cert).into();
    let peer = neighbors
        .iter()
        .find(|p| p.certificate_sha256 == digest)
        .ok_or("INVALID_CRYPTO unknown client")?;
    Ok((peer.key, stream))
}
impl Timed {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "contact deadline"))
    }
}
impl Read for Timed {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(b)
    }
}
impl Write for Timed {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn read_frame(stream: &mut impl Read, chain: Hash) -> Result<Frame> {
    let mut prefix = [0; 12];
    stream.read_exact(&mut prefix).map_err(err)?;
    ensure(&prefix[..8] == b"RLDSFRM1", "INVALID_ENCODING frame magic")?;
    let n = u32::from_be_bytes(prefix[8..].try_into().unwrap()) as usize;
    ensure((1..=FRAME_MAX).contains(&n), "INVALID_ENCODING frame limit")?;
    let mut raw = prefix.to_vec();
    raw.resize(12 + n, 0);
    stream.read_exact(&mut raw[12..]).map_err(err)?;
    Frame::decode(&raw, chain)
}
fn nonce() -> Result<Hash> {
    let mut n = [0; 32];
    getrandom::getrandom(&mut n).map_err(err)?;
    ensure(n != [0; 32], "RESOURCE_WAIT contact entropy")?;
    Ok(n)
}
/// Outgoing carriage must already be durable before entering this function.
/// The returned receipt must be durably retained before retransmission suppression.
pub fn deliver(
    material: &Material,
    chain: Hash,
    key: &SigningKey,
    peer: &Neighbor,
    packet: &Packet,
) -> Result<Option<Frame>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let socket = TcpStream::connect_timeout(&peer.endpoint, Duration::from_secs(3)).map_err(err)?;
    let connection = ClientConnection::new(
        client(material, chain, peer.clone())?,
        ServerName::try_from("rld-survivor.invalid")
            .map_err(err)?
            .to_owned(),
    )
    .map_err(err)?;
    let mut stream = StreamOwned::new(
        connection,
        Timed {
            stream: socket,
            deadline,
        },
    );
    let challenge = read_frame(&mut stream, chain)?;
    ensure(
        challenge.kind == 1
            && challenge.sender == peer.key
            && challenge.receiver == peer_id(key.verifying_key().to_bytes())
            && challenge.challenge != [0; 32],
        "INVALID_CRYPTO connection challenge",
    )?;
    let delivery = Frame::delivery(
        chain,
        key,
        peer_id(peer.key),
        challenge.challenge,
        nonce()?,
        packet,
    )?;
    stream
        .write_all(&delivery.raw)
        .and_then(|_| stream.flush())
        .map_err(err)?;
    if packet.kind == 9 {
        return Ok(None);
    }
    let receipt = read_frame(&mut stream, chain)?;
    let code = receipt.authenticate_receipt(&delivery, peer.key)?;
    if code == 1 {
        ensure(
            receipt.discharges(packet),
            "INVALID_CRYPTO wrong destination receipt",
        )?;
    }
    Ok(Some(receipt))
}
/// The callback runs only on authenticated bytes and must complete durable custody
/// before returning the signed response. Do not hold a ledger lock during socket IO.
pub fn accept(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    chain: Hash,
    key: &SigningKey,
    neighbors: &[Neighbor],
    custody: impl FnOnce(&[u8], Hash, Hash) -> Result<Option<Frame>>,
) -> Result<()> {
    // Accepted descriptors may inherit O_NONBLOCK on macOS. This worker uses
    // deadline-bounded blocking IO, independent of the nonblocking listener.
    socket.set_nonblocking(false).map_err(err)?;
    let mut stream = StreamOwned::new(
        ServerConnection::new(config).map_err(err)?,
        Timed {
            stream: socket,
            deadline: Instant::now() + Duration::from_secs(3),
        },
    );
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(err)?;
    }
    let cert = stream
        .conn
        .peer_certificates()
        .and_then(|x| x.first())
        .ok_or("INVALID_CRYPTO client certificate")?;
    let digest: Hash = Sha256::digest(cert).into();
    let peer = neighbors
        .iter()
        .find(|p| p.certificate_sha256 == digest)
        .ok_or("INVALID_CRYPTO unknown client")?;
    let challenge = nonce()?;
    let frame = Frame::challenge(chain, key, peer_id(peer.key), challenge)?;
    stream
        .write_all(&frame.raw)
        .and_then(|_| stream.flush())
        .map_err(err)?;
    let delivery = read_frame(&mut stream, chain)?;
    delivery.authenticate_delivery(
        peer.key,
        peer_id(key.verifying_key().to_bytes()),
        challenge,
        false,
    )?;
    let receipt = custody(&delivery.raw, peer.key, challenge)?;
    if let Some(receipt) = receipt {
        receipt.authenticate_receipt(&delivery, key.verifying_key().to_bytes())?;
        stream
            .write_all(&receipt.raw)
            .and_then(|_| stream.flush())
            .map_err(err)?;
    }
    Ok(())
}
